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
    print("!!! DEBUG: VERSION 15 - MULTI-TENANT RAG NATIVE STRUCTURED OUTPUT !!!")
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
        org_id        = payload.get("orgId", "").strip() # 🚨 Capture the Organization ID
        
        print(f"Connecting to Pinecone... (OrgID: {org_id or 'None'})")
        search_query = f"AWS {resource_type} security compliance encryption access"
        
        # 1. Fetch Global Compliance Rules (Default Namespace)
        global_store = PineconeVectorStore(
            index_name=os.environ["PINECONE_INDEX_NAME"],
            embedding=embeddings
        )
        global_docs = global_store.similarity_search(search_query, k=2)
        global_context = "\n".join([f"[GLOBAL BEST PRACTICE]: {d.page_content[:400]}" for d in global_docs])

        # 2. Fetch Org-Specific Private Rules (If orgId exists)
        org_context = ""
        if org_id:
            try:
                org_store = PineconeVectorStore(
                    index_name=os.environ["PINECONE_INDEX_NAME"],
                    embedding=embeddings,
                    namespace=org_id # 🚨 Data Isolation Magic
                )
                org_docs = org_store.similarity_search(search_query, k=3)
                org_context = "\n".join([f"[ORG POLICY - {d.metadata.get('filename', 'Internal Doc')}]: {d.page_content[:400]}" for d in org_docs])
            except Exception as e:
                print(f"Warning: Org Pinecone query failed for {org_id}: {e}")

        # Combine both contexts
        combined_context = f"--- GLOBAL AWS RULES ---\n{global_context}\n\n--- ORG PRIVATE POLICIES ---\n{org_context if org_context else 'No custom org policies found.'}"

        print("Initializing Groq...")
        # 3. Initialize the Base LLM
        llm = ChatGroq(
            model="llama-3.3-70b-versatile",
            api_key=os.environ["GROQ_API_KEY"],
            temperature=0.1, # Dropped slightly to ensure strict schema adherence
            max_tokens=1500,
        )
        
        # FORCE the Native API Structured Output into JSON Mode
        structured_llm = llm.with_structured_output(SecurityReport, method="json_mode")

        # 4. Prompt specifically engineered for Multi-Tenant RAG (Strict Per-Violation Focus)
        prompt = PromptTemplate(
            template="""AWS Security Auditor - analyze this specific security violation.
            
Resource Type: {resource_type}
Resource ARN: {resource_id}
Detected Violation: {raw_config}

Rules & Policies: 
{context}

CRITICAL INSTRUCTIONS: 
1. You are analyzing ONLY the violation specified in 'ViolationType' within the 'Detected Violation' block.
2. IGNORE any other potential issues with the resource (e.g., if the ViolationType is about a dormant user, DO NOT evaluate whether the username is compliant).
3. If the [ORG POLICY] mentions rules related to this SPECIFIC 'ViolationType', the ORG POLICY strictly overrides [GLOBAL BEST PRACTICE]. If it does not, use [GLOBAL BEST PRACTICE].
4. The 'title' MUST be a clean, human-readable version of the exact 'ViolationType' provided (e.g., if ViolationType is 'IAM_DormantUser', title must be 'IAM Dormant User'). Do NOT invent a title for a different issue.

You MUST output your response in valid JSON format using EXACTLY these keys and nothing else:
{{
  "severity": "CRITICAL, HIGH, MEDIUM, or LOW",
  "riskScore": "0.0 to 10.0",
  "title": "Human readable version of the ViolationType",
  "remediation": "Detailed fix steps based on the policy",
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
                "context": combined_context
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
                "cliCommands": [],
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
                "cliCommands": [],
                "complianceFramework": ["Manual-Review"]
            })
        }