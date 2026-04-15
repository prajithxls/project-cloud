"""
get_findings Lambda
===================
GET  /findings?accountId=XXX&status=OPEN
GET  /findings?accountId=XXX&status=RESOLVED
GET  /findings?accountId=XXX              (all statuses)
GET  /refresh?accountId=XXX              (regenerate CSV)

Uses the GSI  accountId-status-index  when a status filter is provided,
which is far more efficient than a full table scan.
"""

import json
import boto3
import os
import csv
import io
from typing import Optional
from datetime import datetime
from decimal import Decimal
from boto3.dynamodb.conditions import Attr, Key

CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

dynamodb   = boto3.resource("dynamodb")
s3_client  = boto3.client("s3")

TABLE_NAME = os.environ["FINDINGS_TABLE"]
CSV_BUCKET = os.environ.get("CSV_BUCKET", "")
GSI_NAME   = "accountId-status-index"

table = dynamodb.Table(TABLE_NAME)


# ── Helpers ───────────────────────────────────────────────────────────────────

def decimal_to_native(obj):
    if isinstance(obj, list):  return [decimal_to_native(i) for i in obj]
    if isinstance(obj, dict):  return {k: decimal_to_native(v) for k, v in obj.items()}
    if isinstance(obj, Decimal): return float(obj)
    return obj


def fetch_findings(account_id: str, status_filter: Optional[str]) -> list:
    """
    Fetch findings for an account.

    - If status_filter is "OPEN" or "RESOLVED" → use the GSI for an
      efficient targeted query (avoids scanning the whole table).
    - If no status filter → fall back to a filtered scan (returns all
      statuses so the caller can split them).
    """
    if status_filter in ("OPEN", "RESOLVED"):
        # Efficient GSI query
        items = []
        kwargs = {
            "IndexName": GSI_NAME,
            "KeyConditionExpression": (
                Key("accountId").eq(account_id) & Key("status").eq(status_filter)
            ),
        }
        while True:
            resp = table.query(**kwargs)
            items.extend(resp.get("Items", []))
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
        return decimal_to_native(items)

    else:
        # No status filter → return all statuses via filtered scan
        items = []
        kwargs = {"FilterExpression": Attr("accountId").eq(account_id)}
        while True:
            resp = table.scan(**kwargs)
            items.extend(resp.get("Items", []))
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
        return decimal_to_native(items)


def generate_csv(findings: list) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "FindingID", "AccountId", "ResourceType", "ResourceID",
        "Scanner", "Severity", "RiskScore", "Title", "Status",
        "Timestamp", "UpdatedAt", "ComplianceFramework", "Remediation", "CLICommands",
    ])
    for f in findings:
        raw_cmds = f.get("cliCommands", [])
        if isinstance(raw_cmds, list):
            clean = [c.get("S", c) if isinstance(c, dict) else str(c) for c in raw_cmds]
            cli_str = "\n".join(clean)
        else:
            cli_str = str(raw_cmds)

        fws = f.get("complianceFramework", [])
        fw_str = ", ".join(str(x) for x in fws) if isinstance(fws, list) else str(fws)

        writer.writerow([
            f.get("findingId", ""),
            f.get("accountId", ""),
            f.get("resourceType", ""),
            f.get("resourceId", ""),
            f.get("scanner", ""),
            f.get("severity", ""),
            f.get("riskScore", ""),
            f.get("title", ""),
            f.get("status", ""),
            f.get("timestamp", ""),
            f.get("updatedAt", ""),
            fw_str,
            f.get("remediation", ""),
            cli_str,
        ])
    return output.getvalue()


def delete_old_csvs():
    try:
        resp    = s3_client.list_objects_v2(Bucket=CSV_BUCKET)
        objects = resp.get("Contents", [])
        if objects:
            s3_client.delete_objects(
                Bucket=CSV_BUCKET,
                Delete={"Objects": [{"Key": o["Key"]} for o in objects], "Quiet": True},
            )
            print(f"Deleted {len(objects)} old CSV(s)")
    except Exception as e:
        print(f"Could not delete old CSVs: {e}")


def _ok(data: dict, code: int = 200) -> dict:
    return {"statusCode": code, "headers": CORS_HEADERS, "body": json.dumps(data)}


def _err(message: str, code: int = 400) -> dict:
    return {"statusCode": code, "headers": CORS_HEADERS, "body": json.dumps({"message": message})}


# ── Handler ───────────────────────────────────────────────────────────────────

def lambda_handler(event: dict, context) -> dict:
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    params     = event.get("queryStringParameters") or {}
    account_id = params.get("accountId", "").strip()

    # Validate accountId
    if not account_id:
        return _err("accountId query parameter is required")
    if len(account_id) != 12 or not account_id.isdigit():
        return _err("accountId must be exactly 12 digits")

    # Optional status filter — only accepted values forwarded to fetch_findings
    raw_status    = params.get("status", "").strip().upper()
    status_filter = raw_status if raw_status in ("OPEN", "RESOLVED") else None

    path       = event.get("path", "")
    is_refresh = path.endswith("/refresh")

    try:
        findings = fetch_findings(account_id, status_filter)
        print(f"Fetched {len(findings)} findings | account={account_id} | status={status_filter or 'ALL'}")

        if is_refresh:
            if not CSV_BUCKET:
                return _err("CSV_BUCKET env var not set", 500)
            delete_old_csvs()
            csv_data  = generate_csv(findings)
            file_name = f"compliance_{account_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
            s3_client.put_object(Bucket=CSV_BUCKET, Key=file_name, Body=csv_data, ContentType="text/csv")
            print(f"Uploaded {file_name}")
            return _ok({
                "message":       "Report generated successfully",
                "csvFile":       file_name,
                "totalFindings": len(findings),
                "accountId":     account_id,
                "bucket":        CSV_BUCKET,
            })

        else:
            # Silent background CSV upload
            if CSV_BUCKET:
                try:
                    csv_data  = generate_csv(findings)
                    file_name = f"compliance_{account_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
                    s3_client.put_object(Bucket=CSV_BUCKET, Key=file_name, Body=csv_data, ContentType="text/csv")
                except Exception as e:
                    print(f"Silent CSV upload failed: {e}")

            # Build summary counts so the frontend doesn't need to compute them
            open_count     = sum(1 for f in findings if f.get("status") == "OPEN")
            resolved_count = sum(1 for f in findings if f.get("status") == "RESOLVED")

            return _ok({
                "findings":      findings,
                "total":         len(findings),
                "openCount":     open_count,
                "resolvedCount": resolved_count,
                "accountId":     account_id,
                "statusFilter":  status_filter or "ALL",
            })

    except Exception as e:
        print(f"get_findings error: {e}")
        import traceback; traceback.print_exc()
        return _err(f"Internal error: {str(e)}", 500)