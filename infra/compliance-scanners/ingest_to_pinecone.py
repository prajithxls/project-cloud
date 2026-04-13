# ingest_to_pinecone.py
import os
import time
from dotenv import load_dotenv
load_dotenv()

from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_pinecone import PineconeVectorStore
from pinecone import Pinecone, ServerlessSpec

# ================== CONFIG ==================
PDF_FOLDER = "compliance_pdfs"
INDEX_NAME = "aws-compliance-rules"
PINECONE_REGION = "us-east-1"
INDEX_DIMENSION = 3072

PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

if not PINECONE_API_KEY or not GOOGLE_API_KEY:
    raise ValueError("Please set PINECONE_API_KEY and GOOGLE_API_KEY in .env file")

pc = Pinecone(api_key=PINECONE_API_KEY)

# Create index if it does not exist
if INDEX_NAME not in [idx.name for idx in pc.list_indexes()]:
    print(f"Creating new Pinecone index: {INDEX_NAME}")
    pc.create_index(
        name=INDEX_NAME,
        dimension=INDEX_DIMENSION,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region=PINECONE_REGION)
    )

# Connect to Google's highly stable embedding model
embeddings = GoogleGenerativeAIEmbeddings(
    model="gemini-embedding-001",
    google_api_key=GOOGLE_API_KEY
)

# Load all PDFs from the folder
print(f"Scanning folder: ./{PDF_FOLDER}/")

all_docs = []
for filename in os.listdir(PDF_FOLDER):
    if filename.lower().endswith(".pdf"):
        filepath = os.path.join(PDF_FOLDER, filename)
        print(f"Loading {filename}")
        
        loader = PyPDFLoader(filepath)
        docs = loader.load()
        
        for doc in docs:
            doc.metadata["source"] = filename
            doc.metadata["document_type"] = "compliance_rulebook"
        
        all_docs.extend(docs)

print(f"Loaded {len(all_docs)} pages from {len([f for f in os.listdir(PDF_FOLDER) if f.endswith('.pdf')])} PDFs")

# Split documents
splitter = RecursiveCharacterTextSplitter(
    chunk_size=1200,
    chunk_overlap=200
)
splits = splitter.split_documents(all_docs)

print(f"Split into {len(splits)} chunks. Uploading slowly to respect API limits...")

# ================== UPLOAD BATCHING LOGIC ==================
# Upload 80 chunks at a time, then pause for 60 seconds
batch_size = 80

for i in range(0, len(splits), batch_size):
    batch = splits[i : i + batch_size]
    print(f"\nUploading batch {i//batch_size + 1} (chunks {i} to {i + len(batch)} out of {len(splits)})...")
    
    # Send the batch to Pinecone
    PineconeVectorStore.from_documents(
        batch,
        embeddings,
        index_name=INDEX_NAME
    )
    
    # Don't sleep after the very last batch
    if i + batch_size < len(splits):
        print(" Batch uploaded. Sleeping for 60 seconds to clear Google API quota. Do not close terminal...")
        time.sleep(60)

print("\n Ingestion completed successfully! Your AI database is fully loaded.")
print(f"Index: {INDEX_NAME}")
print(f"Total chunks stored: {len(splits)}")