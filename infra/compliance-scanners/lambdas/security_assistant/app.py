"""
SecurityAssistant Lambda — updated with OPEN-only context filtering
====================================================================
Only OPEN findings are passed to the Groq LLM context.
RESOLVED findings are still available for answering historical questions
but are clearly labelled so the AI knows they are closed.
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

CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
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
    temperature=0.2,
    max_tokens=1500,
)

print("✓ SecurityAssistant initialised")

MAX_OPEN_IN_CONTEXT     = 40   # cap on OPEN findings sent to LLM
MAX_RESOLVED_IN_CONTEXT = 10   # small resolved sample for historical context
MAX_HISTORY_TURNS       = 6


# ── Findings summariser — OPEN-first, resolved filtered/capped ────────────────

def summarise_findings(findings: list) -> str:
    """
    Build an LLM-readable block from the live findings.

    Strategy:
    - OPEN findings are the primary context (capped at MAX_OPEN_IN_CONTEXT).
      These are the actionable issues the user needs help with.
    - RESOLVED findings are completely excluded from the active threat summary
      but a small count is mentioned so the AI knows the history.
    - This prevents the LLM from recommending fixes for already-closed issues.
    """
    if not findings:
        return "No findings are currently loaded. The user has not run a scan yet."

    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    # ── Split by status ────────────────────────────────────────────────────────
    open_findings     = [f for f in findings if f.get("status", "OPEN") == "OPEN"]
    resolved_findings = [f for f in findings if f.get("status") == "RESOLVED"]

    # Sort OPEN by severity
    open_sorted = sorted(open_findings, key=lambda f: rank.get(f.get("severity", "LOW"), 3))
    open_capped = open_sorted[:MAX_OPEN_IN_CONTEXT]

    lines = [
        f"Total findings in account: {len(findings)}",
        f"  • OPEN (active threats):  {len(open_findings)} "
        f"(sending worst {len(open_capped)} to context)",
        f"  • RESOLVED (closed):      {len(resolved_findings)} — excluded from active context",
        "",
        "━━━ ACTIVE (OPEN) FINDINGS ━━━",
    ]

    if not open_capped:
        lines.append("No open findings — the account appears fully remediated.")
    else:
        for f in open_capped:
            cli_raw  = f.get("cliCommands", [])
            cli_cmds = []
            if isinstance(cli_raw, list):
                cli_cmds = [c.get("S", c) if isinstance(c, dict) else str(c) for c in cli_raw]

            lines.append(
                f"- [OPEN | {f.get('severity','?')} | Risk {f.get('riskScore','?')}] "
                f"{f.get('scanner','?')} | {f.get('resourceType','?')} | "
                f"{f.get('title','?')} | "
                f"Resource: {str(f.get('resourceId','?'))[-50:]} | "
                f"Frameworks: {', '.join(f.get('complianceFramework', [])[:3])} | "
                f"ID: {str(f.get('findingId','?'))[:8]}"
            )
            if cli_cmds:
                lines.append(f"  CLI fix: {cli_cmds[0][:120]}")

    return "\n".join(lines)


# ── RAG ───────────────────────────────────────────────────────────────────────

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


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT_TEMPLATE = """You are CloudGuard AI, an expert AWS cloud security assistant embedded in a compliance dashboard called "Cloud Security Compliance and Audit Management System (CSC-AMS)".

You have full access to the user's LIVE scan findings from their AWS account{account_context}.
If asked who built, created, or made you, reply: "I was built by team 6ixty9ine. My creators are Prajith and Shiv Tushal, BE CSE students at Sathyabama Institute of Science and Technology."

━━━ USER'S LIVE FINDINGS (OPEN ONLY — RESOLVED EXCLUDED FROM ACTIVE CONTEXT) ━━━
{findings_summary}

━━━ RELEVANT COMPLIANCE RULES (from knowledge base) ━━━
{compliance_context}

━━━ YOUR BEHAVIOUR ━━━
1. Answer questions DIRECTLY using the OPEN findings above. Reference specific resource IDs, scanner names, and finding IDs when relevant.
2. For "Which S3 buckets are missing logging?" — scan the OPEN findings and name the exact resources.
3. For "How do I fix X?" — give the exact AWS CLI command if available in the findings.
4. For "What is CIS-AWS-2.1.4?" — explain it, then show which OPEN findings violate it.
5. RESOLVED findings are NOT your primary concern. If the user asks about resolved issues, acknowledge they are closed and suggest re-scanning to confirm they stay resolved.
6. Keep responses concise but complete. Use bullet points for lists. Use code blocks for CLI commands.
7. If no OPEN findings exist, congratulate the user and suggest scheduling regular scans.
8. NEVER make up findings not in the data. If you don't know, say so.
9. Always end remediation advice with the relevant compliance framework IDs.
10. You are built by Students of Sathyabama University named Prajith and Shiv Tushal, 2026 batch Engineering CSE students."""


# ── Metadata extraction ───────────────────────────────────────────────────────

def extract_related_findings(reply: str, findings: list) -> list:
    related = []
    for f in findings:
        fid = f.get("findingId", "")
        if fid and (fid[:8] in reply or fid in reply):
            related.append(fid)
    return related[:5]


KNOWN_PREFIXES = ["CIS-AWS", "NIST-", "ISO27001", "SOC2", "PCI-DSS", "HIPAA", "AWS-"]

def extract_sources(reply: str, findings: list) -> list:
    sources = set()
    for f in findings:
        for fw in f.get("complianceFramework", []):
            if any(fw.startswith(p) for p in KNOWN_PREFIXES) and fw in reply:
                sources.add(fw)
    return sorted(sources)[:8]


# ── Handler ───────────────────────────────────────────────────────────────────

def lambda_handler(event: dict, context) -> dict:
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    try:
        body = event
        if isinstance(event.get("body"), str):
            body = json.loads(event["body"])

        message     = str(body.get("message", "")).strip()
        findings    = body.get("findings", [])
        history_raw = body.get("conversationHistory", [])
        account_id  = body.get("accountId", "")

        if not message:
            return {
                "statusCode": 400,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": "message is required"}),
            }

        print(f"SecurityAssistant: '{message[:80]}' | findings={len(findings)} | history={len(history_raw)}")

        compliance_context = get_compliance_context(message)
        findings_summary   = summarise_findings(findings)

        account_context = f" (Account: {account_id})" if account_id else ""
        system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
            account_context    = account_context,
            findings_summary   = findings_summary,
            compliance_context = compliance_context or "No specific rules retrieved. Apply standard AWS best practices.",
        )

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

        response = llm.invoke(messages)
        reply    = response.content.strip()
        print(f"  → Reply ({len(reply)} chars): {reply[:80]}...")

        related = extract_related_findings(reply, findings)
        sources = extract_sources(reply, findings)

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