import json
import boto3
import os
import csv
import io
from datetime import datetime
from decimal import Decimal
from boto3.dynamodb.conditions import Attr

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")

TABLE_NAME = os.environ["FINDINGS_TABLE"]
CSV_BUCKET = os.environ.get("CSV_BUCKET", "")

table = dynamodb.Table(TABLE_NAME)


def decimal_to_native(obj):
    if isinstance(obj, list):
        return [decimal_to_native(i) for i in obj]
    if isinstance(obj, dict):
        return {k: decimal_to_native(v) for k, v in obj.items()}
    if isinstance(obj, Decimal):
        return float(obj)
    return obj


def generate_csv(findings):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "FindingID", "AccountId", "ResourceType", "ResourceID",
        "Scanner", "Severity", "RiskScore", "Title", "Status",
        "Timestamp", "ComplianceFramework", "Remediation","cliCommands"
    ])


    for f in findings:
        # 1. Safely flatten the cliCommands array
        raw_cmds = f.get("cliCommands", [])
        clean_cmds = []
        if isinstance(raw_cmds, list):
            for cmd in raw_cmds:
                # Handle DynamoDB nested "S" dictionary if present
                if isinstance(cmd, dict) and "S" in cmd:
                    clean_cmds.append(cmd["S"])
                else:
                    clean_cmds.append(str(cmd))
            cli_str = " \n".join(clean_cmds)
        else:
            cli_str = str(raw_cmds)
        frameworks = f.get("complianceFramework", [])
        if isinstance(frameworks, list):
            framework_str = ", ".join(str(x) for x in frameworks)
        else:
            framework_str = str(frameworks)

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
            framework_str,
            f.get("remediation", ""),
            cli_str
        ])
    return output.getvalue()


def delete_old_csvs():
    """Delete all existing CSV files from the bucket before uploading new one."""
    try:
        response = s3.list_objects_v2(Bucket=CSV_BUCKET)
        objects = response.get("Contents", [])
        if objects:
            s3.delete_objects(
                Bucket=CSV_BUCKET,
                Delete={
                    "Objects": [{"Key": obj["Key"]} for obj in objects],
                    "Quiet": True
                }
            )
            print(f"Deleted {len(objects)} old CSV(s) from {CSV_BUCKET}")
    except Exception as e:
        print(f"Could not delete old CSVs: {str(e)}")


def fetch_findings_for_account(account_id):
    """Scan DynamoDB filtered by accountId with pagination."""
    filter_expr = Attr("accountId").eq(account_id)
    response = table.scan(FilterExpression=filter_expr)
    findings = response.get("Items", [])
    while "LastEvaluatedKey" in response:
        response = table.scan(
            FilterExpression=filter_expr,
            ExclusiveStartKey=response["LastEvaluatedKey"]
        )
        findings.extend(response.get("Items", []))
    return decimal_to_native(findings)


def lambda_handler(event, context):

    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    # ── Require accountId on every call ──────────────────────────────────────
    account_id = (event.get("queryStringParameters") or {}).get("accountId", "").strip()

    if not account_id:
        return {
            "statusCode": 400,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "accountId query parameter is required",
                "findings": [],
                "total": 0,
            })
        }

    if len(account_id) != 12 or not account_id.isdigit():
        return {
            "statusCode": 400,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "accountId must be exactly 12 digits",
                "findings": [],
                "total": 0,
            })
        }

    # Detect whether this is a /refresh call or a /findings call
    path = event.get("path", "")
    is_refresh = path.endswith("/refresh")

    try:
        findings = fetch_findings_for_account(account_id)
        print(f"Fetched {len(findings)} findings for account {account_id}")

        if is_refresh:
            # /refresh → delete old CSVs, generate fresh one scoped to this account
            if not CSV_BUCKET:
                return {
                    "statusCode": 500,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"message": "CSV_BUCKET env var not set"})
                }

            delete_old_csvs()

            csv_data = generate_csv(findings)
            file_name = f"compliance_{account_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

            s3.put_object(
                Bucket=CSV_BUCKET,
                Key=file_name,
                Body=csv_data,
                ContentType="text/csv"
            )
            print(f"Uploaded new CSV: {file_name} to {CSV_BUCKET}")

            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "message": "Report generated successfully",
                    "csvFile": file_name,
                    "totalFindings": len(findings),
                    "accountId": account_id,
                    "bucket": CSV_BUCKET
                })
            }

        else:
            # /findings → return findings scoped to this account, also upload CSV silently
            if CSV_BUCKET:
                try:
                    csv_data = generate_csv(findings)
                    file_name = f"compliance_{account_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
                    s3.put_object(
                        Bucket=CSV_BUCKET,
                        Key=file_name,
                        Body=csv_data,
                        ContentType="text/csv"
                    )
                except Exception as e:
                    print("Silent CSV upload failed:", str(e))

            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "findings": findings,
                    "total": len(findings),
                    "accountId": account_id,
                })
            }

    except Exception as e:
        print("get_findings error:", str(e))
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "Failed", "error": str(e)})
        }