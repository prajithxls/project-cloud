import json
import os
import time
from langchain_pinecone import PineconeVectorStore
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_groq import ChatGroq
from langchain_core.prompts import PromptTemplate
from pydantic import BaseModel, Field
from typing import List

# ------------------------------------------------------------------
# STRICT PYDANTIC SCHEMA
# ------------------------------------------------------------------
class SecurityReport(BaseModel):
    severity: str = Field(description="Must be exactly CRITICAL, HIGH, MEDIUM, or LOW")
    riskScore: str = Field(description="Risk score from 0.0 to 10.0")
    title: str = Field(description="Short, clear title of the specific security issue")
    remediation: str = Field(description="Detailed fix steps and AWS CLI commands")
    cliCommands: List[str] = Field(description="A JSON array of valid AWS CLI commands to remediate the issue.")
    complianceFramework: List[str] = Field(description="List of compliance frameworks (e.g., CIS-AWS)")

print("Initializing embeddings model...")
embeddings = GoogleGenerativeAIEmbeddings(
    model="models/gemini-embedding-001",
    google_api_key=os.environ["GOOGLE_API_KEY"]
)
print("✓ Embeddings initialized")

def lambda_handler(event, context):
    print("!!! DEBUG: VERSION 14 - NATIVE STRUCTURED OUTPUT !!!")
    try:
        # Parse input payload
        if isinstance(event.get("body"), str):
            payload = json.loads(event["body"])
        elif "resource_type" in event:
            payload = event
        else:
            payload = event

        resource_type = payload.get("resource_type", "S3 Bucket")
        resource_id   = payload.get("resource_id", "Unknown")
        raw_config    = payload.get("raw_config", {})
        
        print("Connecting to Pinecone...")
        vectorstore = PineconeVectorStore.from_existing_index(
            index_name=os.environ["PINECONE_INDEX_NAME"],
            embedding=embeddings
        )
        
        search_query = f"AWS {resource_type} security compliance encryption access"
        docs = vectorstore.similarity_search(search_query, k=3)
        context_text = "\n\n---\n\n".join([d.page_content[:500] for d in docs])

        print("Initializing Grok...")
        # 1. Initialize the Base LLM
        llm = ChatGroq (
            model="llama-3.3-70b-versatile",
            api_key=os.environ["GROQ_API_KEY"],
            temperature=0.0
        )
        
        # 2. FORCE the Native API Structured Output
        # 2. FORCE the Native API Structured Output into JSON Mode
        structured_llm = llm.with_structured_output(SecurityReport, method="json_mode")

        # 3. Cleaned up prompt (no more format instructions needed!)
       # 3. Cleaned up prompt with Explicit JSON Schema
      # 3. Cleaned up prompt with Escaped JSON Schema
        prompt = PromptTemplate(
            template="""AWS Security Auditor - analyze this resource.
            
Resource: {resource_type}
ARN: {resource_id}
Config: {raw_config}

Rules: {context}

CRITICAL INSTRUCTION: 
This resource may contain multiple security vulnerabilities. You must evaluate all of them, but you are strictly required to ONLY output the single highest severity risk (the absolute worst misconfiguration). Do not list multiple issues. 

You MUST output your response in valid JSON format using EXACTLY these keys and nothing else:
{{
  "severity": "CRITICAL, HIGH, MEDIUM, or LOW",
  "riskScore": "0.0 to 10.0",
  "title": "Short title of the issue",
  "remediation": "Detailed fix steps",
  "cliCommands": ["aws ..."],
  "complianceFramework": ["CIS-AWS-..."]
}}""",
            input_variables=["resource_type", "resource_id", "raw_config", "context"]
        )

        print("Generating analysis...")
        start_time = time.time()
        
        try:
            # Chain directly to the structured LLM
            chain = prompt | structured_llm
            
            # This returns a pure Pydantic object, NOT a dictionary/string
            pydantic_result = chain.invoke({
                "resource_type": resource_type,
                "resource_id": resource_id,
                "raw_config": json.dumps(raw_config, default=str)[:1000],
                "context": context_text
            })
            
            # Convert Pydantic object safely to a dictionary
            ai_result = pydantic_result.model_dump()
            
            elapsed = time.time() - start_time
            print(f"✓ Analysis complete in {elapsed:.1f}s")
            
        except Exception as llm_error:
            print(f"⚠️  LLM call failed: {str(llm_error)}")
            ai_result = {
                "severity": "HIGH",
                "riskScore": "8.0",
                "title": f"{resource_type} configuration issues detected",
                "remediation": f"Manual review required. LLM Error: {str(llm_error)}",
                "complianceFramework": ["AWS-Security-Review"]
            }

        return {
            "statusCode": 200,
            "body": json.dumps(ai_result)
        }

    except Exception as e:
        print(f"❌ AI Analyzer Error: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "severity": "HIGH",
                "riskScore": "8.0",
                "title": "AI Analysis Failed",
                "remediation": f"Fatal Error: {str(e)}",
                "complianceFramework": ["Manual-Review"]
            })
        }