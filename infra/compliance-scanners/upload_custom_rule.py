import os
from langchain_community.document_loaders import PyPDFLoader
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_pinecone import PineconeVectorStore

# 1. Read keys from environment only (never hardcode secrets in source)
if not os.getenv("GOOGLE_API_KEY") or not os.getenv("PINECONE_API_KEY"):
    raise ValueError("Set GOOGLE_API_KEY and PINECONE_API_KEY in your environment before running.")
PINECONE_INDEX_NAME = "aws-compliance-rules" # Ensure this matches AWS exactly

print("Loading the custom policy PDF...")
# 2. Load and split the PDF into readable chunks
loader = PyPDFLoader("a_custom_policy.pdf")
docs = loader.load_and_split()

print("Initializing the EXACT SAME embedding model...")
# 3. CRITICAL: This must exactly match the model in your Lambda app.py
embeddings = GoogleGenerativeAIEmbeddings(
    model="gemini-embedding-001"
)

print(f"Uploading {len(docs)} document chunks to Pinecone index: {PINECONE_INDEX_NAME}...")
# 4. Add the new vectors to your existing index
vectorstore = PineconeVectorStore.from_documents(
    documents=docs,
    embedding=embeddings,
    index_name=PINECONE_INDEX_NAME
)

print("✅ Custom policy successfully injected into the AI's brain!")