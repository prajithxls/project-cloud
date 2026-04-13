"""
SecurityAssistant Lambda
========================
Powers the "Compliance Chat" feature.

Receives:
  {
    "message":             "Which S3 buckets are missing logging?",
    "findings":            [...],          # live findings from DynamoDB (passed by frontend)
    "conversationHistory": [               # last N turns for multi-turn context
      {"role": "user",      "content": "..."},
      {"role": "assistant", "content": "..."}
    ],
    "accountId":           "123456789012"  # optional, for context
  }

Returns:
  {
    "reply":        "Based on your findings, bucket X and Y are missing access logging...",
    "sources":      ["CIS-AWS-2.1.4", "NIST-AU-2"],   # frameworks cited
    "relatedFindings": ["finding-id-1", "finding-id-2"] # IDs the answer references
  }

Environment variables:
  GROQ_API_KEY
  GOOGLE_API_KEY      (for embeddings)
  PINECONE_API_KEY
  PINECONE_INDEX_NAME
"""

import json
import os
import traceback
from typing import List

from langchain_pinecone import PineconeVectorStore
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from pinecone import Pinecone

# ── Cold-start init ───────────────────────────────────────────────────────────
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
}

print("Initialising SecurityAssistant...")

pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])

embeddings = GoogleGenerativeAIEmbeddings(
    model="models/gemini-embedding-001",
    google_api_key=os.environ["GOOGLE_API_KEY"],
)

vector_store = PineconeVectorStore(
    index=pc.Index(os.environ.get("PINECONE_INDEX_NAME", "aws-compliance-rules")),
    embedding=embeddings,
    text_key="text",
)

llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    api_key=os.environ["GROQ_API_KEY"],
    temperature=0.2,      # Slightly creative for natural conversation
    max_tokens=1500,
)

print("✓ SecurityAssistant initialised")

MAX_FINDINGS_IN_CONTEXT = 40   # cap so we don't blow the context window
MAX_HISTORY_TURNS       = 6    # last 6 turns (3 exchanges)


# ── Summarise findings for the LLM ────────────────────────────────────────────
def summarise_findings(findings: list) -> str:
    """
    Convert raw DynamoDB findings into a compact, readable block the LLM can reason over.
    Cap at MAX_FINDINGS_IN_CONTEXT to stay within context limits.
    """
    if not findings:
        return "No findings are currently loaded. The user has not run a scan yet."

    # Sort: critical first
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_f = sorted(findings, key=lambda f: rank.get(f.get("severity", "LOW"), 3))
    capped    = sorted_f[:MAX_FINDINGS_IN_CONTEXT]

    lines = [f"Total findings: {len(findings)} (showing worst {len(capped)} to LLM)\n"]
    for f in capped:
        cli_raw = f.get("cliCommands", [])
        if isinstance(cli_raw, list):
            cli_cmds = [c.get("S", c) if isinstance(c, dict) else str(c) for c in cli_raw]
        else:
            cli_cmds = []

        lines.append(
            f"- [{f.get('severity','?')} | Risk {f.get('riskScore','?')}] "
            f"{f.get('scanner','?')} | {f.get('resourceType','?')} | "
            f"{f.get('title','?')} | "
            f"Resource: {f.get('resourceId','?')[-50:]} | "
            f"Frameworks: {', '.join(f.get('complianceFramework', [])[:3])} | "
            f"FindingID: {f.get('findingId','?')[:8]}"
        )
        if cli_cmds:
            lines.append(f"  CLI fix: {cli_cmds[0][:120]}")

    return "\n".join(lines)


# ── RAG: pull relevant compliance rules ───────────────────────────────────────
def get_compliance_context(question: str, k: int = 4) -> str:
    try:
        docs = vector_store.similarity_search(question, k=k)
        if not docs:
            return ""
        parts = []
        for doc in docs:
            src = doc.metadata.get("source") or doc.metadata.get("framework") or "AWS Best Practice"
            parts.append(f"[{src}]\n{doc.page_content[:400]}")
        return "\n\n".join(parts)
    except Exception as e:
        print(f"Pinecone error: {e}")
        return ""


# ── Build the system prompt ───────────────────────────────────────────────────
SYSTEM_PROMPT_TEMPLATE = """You are CloudGuard AI, an expert AWS cloud security assistant embedded in a compliance dashboard called "Cloud Security Compliance and Audit Management System (CSC-AMS)".

You have full access to the user's LIVE scan findings from their AWS account{account_context}. Your role is to be an interactive security consultant — not just a list of errors, but someone who explains WHY something is a risk, HOW to fix it, and WHICH compliance standard requires it.
If asked who built, created, or made you, you MUST reply with this exact information:
I was built by team 6ixty9ine. My creators are Prajith and Shiv Tushal, who are BE CSE students at Sathyabama Institute of Science and Technology.

━━━ USER'S LIVE FINDINGS ━━━
{findings_summary}

━━━ RELEVANT COMPLIANCE RULES (from knowledge base) ━━━
{compliance_context}

━━━ YOUR BEHAVIOUR ━━━
1. Answer questions DIRECTLY using the live findings above. Reference specific resource IDs, scanner names, and finding IDs when relevant.
2. For questions like "Which S3 buckets are missing logging?" — scan the findings list and name the exact resources.
3. For "How do I fix X?" — give the exact AWS CLI command if available in the findings, otherwise generate the correct one.
4. For "What is CIS-AWS-2.1.4?" — explain it clearly in plain English, then show which of the user's findings violate it.
5. Keep responses concise but complete. Use bullet points for lists of findings. Use code blocks for CLI commands.
6. If you reference a specific finding, always mention its scanner, severity, and the resource ID (shortened).
7. If no findings are loaded yet, tell the user to run a scan first from the Scan page.
8. Be conversational and professional. You are a security expert, not a chatbot.
9. NEVER make up findings that aren't in the data. If you don't know something, say so.
10. If asked about remediation, always end with the relevant compliance framework IDs.
11. You are built by Students of Sathyabama University named Prajith and Shiv Tushal, 2026 batch Engineering CSE students"""


# ── Extract finding IDs referenced in the reply ───────────────────────────────
def extract_related_findings(reply: str, findings: list) -> list:
    """Find finding IDs (first 8 chars) mentioned in the reply."""
    related = []
    for f in findings:
        fid = f.get("findingId", "")
        if fid and (fid[:8] in reply or fid in reply):
            related.append(fid)
    return related[:5]  # cap at 5


# ── Extract framework IDs cited ────────────────────────────────────────────────
KNOWN_PREFIXES = ["CIS-AWS", "NIST-", "ISO27001", "SOC2", "PCI-DSS", "HIPAA", "AWS-"]

def extract_sources(reply: str, findings: list) -> list:
    sources = set()
    # From findings referenced
    for f in findings:
        for fw in f.get("complianceFramework", []):
            if any(fw.startswith(p) for p in KNOWN_PREFIXES) and fw in reply:
                sources.add(fw)
    return sorted(sources)[:8]


# ── Lambda handler ─────────────────────────────────────────────────────────────
def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    try:
        body = event
        if isinstance(event.get("body"), str):
            body = json.loads(event["body"])

        message      = str(body.get("message", "")).strip()
        findings     = body.get("findings", [])
        history_raw  = body.get("conversationHistory", [])
        account_id   = body.get("accountId", "")

        if not message:
            return {
                "statusCode": 400,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": "message is required"}),
            }

        print(f"SecurityAssistant: '{message[:80]}' | findings={len(findings)} | history={len(history_raw)}")

        # 1. RAG — retrieve relevant compliance rules
        compliance_context = get_compliance_context(message)

        # 2. Summarise findings
        findings_summary = summarise_findings(findings)

        # 3. Build system prompt
        account_context = f" (Account: {account_id})" if account_id else ""
        system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
            account_context  = account_context,
            findings_summary = findings_summary,
            compliance_context = compliance_context or "No specific rules retrieved. Apply standard AWS best practices.",
        )

        # 4. Build message history (cap to last MAX_HISTORY_TURNS turns)
        messages = [SystemMessage(content=system_prompt)]

        recent_history = history_raw[-(MAX_HISTORY_TURNS * 2):]
        for turn in recent_history:
            role    = turn.get("role", "user")
            content = turn.get("content", "")
            if role == "user":
                messages.append(HumanMessage(content=content))
            elif role == "assistant":
                messages.append(AIMessage(content=content))

        messages.append(HumanMessage(content=message))

        # 5. Call Groq
        response = llm.invoke(messages)
        reply    = response.content.strip()

        print(f"  → Reply ({len(reply)} chars): {reply[:80]}...")

        # 6. Extract metadata for frontend
        related  = extract_related_findings(reply, findings)
        sources  = extract_sources(reply, findings)

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "reply":           reply,
                "sources":         sources,
                "relatedFindings": related,
            }),
        }

    except Exception as e:
        traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e), "reply": "I encountered an error. Please try again."}),
        }