import os
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_pinecone import PineconeVectorStore

if not os.getenv("GOOGLE_API_KEY") or not os.getenv("PINECONE_API_KEY"):
    raise ValueError("Set GOOGLE_API_KEY and PINECONE_API_KEY in your environment before running.")

embeddings = GoogleGenerativeAIEmbeddings(model="models/gemini-embedding-001")
vectorstore = PineconeVectorStore.from_existing_index(index_name="aws-compliance-rules", embedding=embeddings)

# Test the old query vs the new query!
docs = vectorstore.similarity_search("AWS IAM User corporate security policies, username rules, and compliance", k=5)

for i, doc in enumerate(docs):
    print(f"\n--- Result {i+1} ---")
    print(doc.page_content)