"""
update_status Lambda
====================
PATCH /findings/{findingId}/status

Allows a user to manually override the status of a finding.
Supported transitions:
  OPEN      → RESOLVED  (manual close)
  RESOLVED  → OPEN      (reopen / false-positive reversal)

Request body:
  { "status": "RESOLVED" }   or   { "status": "OPEN" }

Response 200:
  { "findingId": "...", "status": "RESOLVED", "updatedAt": "..." }
"""

import json
import os
import boto3
from datetime import datetime, timezone
from typing import Literal

CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "PATCH,OPTIONS",
}

dynamodb = boto3.resource("dynamodb")
table    = dynamodb.Table(os.environ["FINDINGS_TABLE"])

VALID_STATUSES = {"OPEN", "RESOLVED"}


def _ok(data: dict, code: int = 200) -> dict:
    return {"statusCode": code, "headers": CORS_HEADERS, "body": json.dumps(data)}


def _err(message: str, code: int = 400) -> dict:
    return {"statusCode": code, "headers": CORS_HEADERS, "body": json.dumps({"message": message})}


def lambda_handler(event: dict, context) -> dict:
    # ── CORS preflight ────────────────────────────────────────────────────────
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    # ── Extract findingId from path parameter ─────────────────────────────────
    path_params = event.get("pathParameters") or {}
    finding_id  = (path_params.get("findingId") or "").strip()

    if not finding_id:
        return _err("findingId path parameter is required", 400)

    # ── Parse request body ────────────────────────────────────────────────────
    try:
        body       = json.loads(event.get("body") or "{}")
        new_status = str(body.get("status", "")).strip().upper()
    except json.JSONDecodeError:
        return _err("Invalid JSON body", 400)

    if new_status not in VALID_STATUSES:
        return _err(f"status must be one of: {sorted(VALID_STATUSES)}", 400)

    updated_at = datetime.now(timezone.utc).isoformat()

    # ── Update in DynamoDB ────────────────────────────────────────────────────
    try:
        response = table.update_item(
            Key={"findingId": finding_id},
            UpdateExpression="SET #s = :s, updatedAt = :u",
            ConditionExpression="attribute_exists(findingId)",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": new_status,
                ":u": updated_at,
            },
            ReturnValues="ALL_NEW",
        )
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return _err(f"Finding '{finding_id}' not found", 404)
    except Exception as e:
        print(f"DynamoDB update error: {e}")
        return _err(f"Failed to update finding: {str(e)}", 500)

    updated = response.get("Attributes", {})

    print(f"Finding {finding_id} → {new_status} at {updated_at}")

    return _ok({
        "findingId": finding_id,
        "status":    new_status,
        "updatedAt": updated_at,
        "accountId": updated.get("accountId", ""),
        "scanner":   updated.get("scanner", ""),
        "severity":  updated.get("severity", ""),
    })