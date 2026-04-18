# lambdas/process_document/app.py
import json, boto3, os, uuid
from datetime import datetime, timezone

from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_pinecone import PineconeVectorStore
from langchain.text_splitter import RecursiveCharacterTextSplitter
import PyPDF2, io
from pinecone import Pinecone

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
}

s3_client  = boto3.client("s3")
dynamodb   = boto3.resource("dynamodb")
orgs_table = dynamodb.Table(os.environ["ORGANISATIONS_TABLE"])
BUCKET     = os.environ["DOCUMENTS_BUCKET"]

pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])

embeddings = GoogleGenerativeAIEmbeddings(
    model="models/gemini-embedding-001",
    google_api_key=os.environ["GOOGLE_API_KEY"],
)

CHUNK_SIZE    = 800  
CHUNK_OVERLAP = 150  

def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
    pages  = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            pages.append(text.strip())
    return "\n\n".join(pages)

def chunk_text(text: str, source_name: str) -> list[dict]:
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n\n", "\n", ".", " "],
    )
    chunks = splitter.split_text(text)
    return [
        {
            "id":      f"{source_name}_chunk_{i}",
            "text":    chunk,
            "source":  source_name,
            "chunkIndex": i,
        }
        for i, chunk in enumerate(chunks)
    ]

def upsert_to_pinecone(chunks: list[dict], org_id: str, doc_metadata: dict):
    # Each org gets its own Pinecone namespace = org_id.
    index  = pc.Index(os.environ.get("PINECONE_INDEX_NAME", "aws-compliance-rules"))
    texts  = [c["text"] for c in chunks]

    vectors = embeddings.embed_documents(texts)
    to_upsert = []
    
    for chunk, vector in zip(chunks, vectors):
        to_upsert.append({
            "id":     chunk["id"],
            "values": vector,
            "metadata": {
                "text":        chunk["text"],
                "source":      chunk["source"],
                "chunkIndex":  chunk["chunkIndex"],
                "orgId":       org_id,
                "uploadedAt":  doc_metadata.get("uploadedAt", ""),
                "filename":    doc_metadata.get("filename", ""),
                "uploadedBy":  doc_metadata.get("uploadedBy", ""),
                "type":        "org_document",
            }
        })

    for i in range(0, len(to_upsert), 100):
        index.upsert(vectors=to_upsert[i:i+100], namespace=org_id)

    print(f"Upserted {len(to_upsert)} vectors to namespace={org_id}")
    return len(to_upsert)

def lambda_handler(event, context):
    # ── Handle S3 trigger ──
    if "Records" in event:
        for record in event["Records"]:
            s3_key  = record["s3"]["object"]["key"]
            process_s3_key(s3_key)
        return {"statusCode": 200, "body": "Processed"}

    # ── Handle manual HTTP POST ──
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    try:
        body    = json.loads(event.get("body") or "{}")
        s3_key  = body.get("s3Key", "").strip()
        if not s3_key:
            return {"statusCode": 400, "headers": CORS_HEADERS, "body": json.dumps({"message": "s3Key is required"})}
        result = process_s3_key(s3_key)
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": json.dumps(result)}
    except Exception as e:
        import traceback; traceback.print_exc()
        return {"statusCode": 500, "headers": CORS_HEADERS, "body": json.dumps({"error": str(e)})}

def process_s3_key(s3_key: str) -> dict:
    parts    = s3_key.split("/")
    org_id   = parts[0]
    user_id  = parts[1] if len(parts) > 1 else "unknown"
    filename = parts[-1]

    obj      = s3_client.get_object(Bucket=BUCKET, Key=s3_key)
    pdf_bytes = obj["Body"].read()

    text = extract_text_from_pdf(pdf_bytes)
    if not text.strip():
        return {"warning": "No text extracted", "s3Key": s3_key}

    chunks = chunk_text(text, source_name=filename)
    
    doc_meta = {
        "uploadedAt": datetime.now(timezone.utc).isoformat(),
        "filename":   filename,
        "uploadedBy": user_id,
    }
    vector_count = upsert_to_pinecone(chunks, org_id, doc_meta)

    try:
        orgs_table.update_item(
            Key={"orgId": org_id},
            UpdateExpression="ADD documentCount :one",
            ExpressionAttributeValues={":one": 1},
        )
    except Exception as e:
        print(f"Warning: could not update documentCount: {e}")

    return {
        "orgId":        org_id,
        "filename":     filename,
        "chunkCount":   len(chunks),
        "vectorCount":  vector_count,
        "namespace":    org_id,
    }
