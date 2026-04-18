import json
import boto3
import os
import uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from boto3.dynamodb.conditions import Key
from botocore.config import Config

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

# ─── BOTO3 RETRY CONFIGURATION ─────────────────────────────────────────
boto_config = Config(
    retries={
        'max_attempts': 10,
        'mode': 'adaptive'
    }
)

lambda_client  = boto3.client("lambda", config=boto_config)
sts_client     = boto3.client("sts")
dynamodb       = boto3.resource("dynamodb")

S3_FN         = os.environ.get("S3_SCANNER_FUNCTION",         "compliance-scanners-dev-s3Scanner")
EC2_FN        = os.environ.get("EC2_SCANNER_FUNCTION",        "compliance-scanners-dev-ec2Scanner")
IAM_FN        = os.environ.get("IAM_SCANNER_FUNCTION",        "compliance-scanners-dev-iamScanner")
LAMBDA_FN     = os.environ.get("LAMBDA_SCANNER_FUNCTION",     "compliance-scanners-dev-lambdaScanner")
RDS_FN        = os.environ.get("RDS_SCANNER_FUNCTION",        "compliance-scanners-dev-rdsScanner")
CLOUDTRAIL_FN = os.environ.get("CLOUDTRAIL_SCANNER_FUNCTION", "compliance-scanners-dev-cloudtrailScanner")
APIGW_FN      = os.environ.get("APIGW_SCANNER_FUNCTION",      "compliance-scanners-dev-apigwScanner")

FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "Findings")
HISTORY_TABLE  = os.environ.get("HISTORY_TABLE", "ScanHistory")

# ─── HELPER: SAVE HISTORY ──────────────────────────────────────────────
def save_scan_history(user_id, account_id, status, findings_count="nil"):
    try:
        if not user_id or user_id == "UNKNOWN":
            print("Skipping history save: No userId provided")
            return
            
        history_table = dynamodb.Table(HISTORY_TABLE)
        history_table.put_item(Item={
            "historyId": str(uuid.uuid4()),
            "userId": user_id,
            "accountId": account_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status": status,
            "findingsCount": findings_count
        })
        print(f"History saved: {status} for account {account_id}")
    except Exception as e:
        print(f"Failed to save history: {e}")

# ─── HELPER: PURGE OLD FINDINGS ────────────────────────────────────────
def purge_old_findings(account_id):
    table = dynamodb.Table(FINDINGS_TABLE)
    try:
        # Use the GSI to quickly find the account's items
        response = table.query(
            IndexName="accountId-status-index", 
            KeyConditionExpression=Key("accountId").eq(account_id)
        )
        items = response.get("Items", [])
        
        if items:
            with table.batch_writer() as batch:
                for item in items:
                    # Delete the item using the base table's exact primary key
                    batch.delete_item(
                        Key={
                            "findingId": item["findingId"]
                        }
                    )
            print(f"Purged {len(items)} old findings for {account_id}")
    except Exception as e:
        print(f"Purge error: {e}")

# ─── HELPER: INVOKE INDIVIDUAL SCANNERS ────────────────────────────────
def invoke_scanner(name, fn, target_account, org_id):
    try:
        payload = {"accountId": target_account, "orgId": org_id}
        response = lambda_client.invoke(
            FunctionName=fn,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload),
        )
        result = json.loads(response["Payload"].read())
        body   = result.get("body", "{}")
        return name, json.loads(body) if isinstance(body, str) else body, None
    except Exception as e:
        print(f"{name} invocation error: {e}")
        return name, None, str(e)

# ─── MAIN ORCHESTRATOR HANDLER ─────────────────────────────────────────
def lambda_handler(event, context):
    
    # 1. KEEP-WARM BOUNCER (Prevents API Gateway Timeouts)
    if event.get("source") == "keep-warm":
        print("Keep-warm ping received. Container is awake!")
        return {"statusCode": 200, "body": "Warm"}

    # 2. CORS PREFLIGHT
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    query_params   = event.get("queryStringParameters") or {}
    user_id        = query_params.get("userId", "UNKNOWN")
    own_account    = context.invoked_function_arn.split(":")[4]
    target_account = query_params.get("accountId", "").strip()
    scanners_param = query_params.get("scanners", "").strip()
    org_id         = query_params.get("orgId", "").strip()

    # Wrap the entire execution in a try/except to catch fatal errors
    try:
        if target_account:
            if len(target_account) != 12 or not target_account.isdigit():
                return {"statusCode": 400, "headers": CORS_HEADERS,
                        "body": json.dumps({"message": "accountId must be exactly 12 digits"})}
            if target_account == own_account:
                target_account = ""

        is_cross_account = bool(target_account)
        scan_account     = target_account if is_cross_account else own_account

        print(f"Scanning account: {scan_account} | Cross-account: {is_cross_account}")

        # ── Fail fast: verify STS role before scanning ──
        if is_cross_account:
            try:
                sts_client.assume_role(
                    RoleArn=f"arn:aws:iam::{target_account}:role/CrossAccountComplianceRole",
                    RoleSessionName="ComplianceScanCheck"
                )
            except Exception as e:
                purge_old_findings(scan_account)
                
                # Save the failure to DynamoDB History
                save_scan_history(user_id, scan_account, "Failed", "nil")
                
                return {
                    "statusCode": 403,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({
                        "message": f"Access Denied: Could not assume CrossAccountComplianceRole in account {target_account}."
                    })
                }

        purge_old_findings(scan_account)

        # ── Filter requested scanners ──
        ALL_SCANNERS = [
            ("s3",         S3_FN),
            ("ec2",        EC2_FN),
            ("iam",        IAM_FN),
            ("lambda",     LAMBDA_FN),
            ("rds",        RDS_FN),
            ("cloudtrail", CLOUDTRAIL_FN),
            ("apigw",      APIGW_FN),
        ]

        scanners_to_run = ALL_SCANNERS
        if scanners_param:
            requested = [s.strip().lower() for s in scanners_param.split(",")]
            filtered_scanners = [s for s in ALL_SCANNERS if s[0] in requested]
            if filtered_scanners:
                scanners_to_run = filtered_scanners

        results = {}
        errors  = {}

        thread_count = max(1, len(scanners_to_run))
        
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = {
                executor.submit(invoke_scanner, name, fn, target_account, org_id): name
                for name, fn in scanners_to_run
            }
            for future in as_completed(futures):
                name, result, error = future.result()
                if error:
                    errors[name] = error
                else:
                    results[name] = result

        print(f"Scan complete. Results: {list(results.keys())}, Errors: {list(errors.keys())}")

        # ── Save Success to DynamoDB History ──
        final_status = "Failed" if len(errors) == len(scanners_to_run) else "Success"
        save_scan_history(user_id, scan_account, final_status, "nil")

        return {
            "statusCode": 200 if not errors else 207,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message":      "Scan complete" if not errors else "Scan completed with errors",
                "accountId":    scan_account,
                "crossAccount": is_cross_account,
                "scannersRun":  [s[0] for s in scanners_to_run],
                "results":      results,
                "errors":       errors,
            }),
        }

    # ── Catch fatal crashes and log them to History ──
    except Exception as e:
        print(f"[FATAL ERROR] {str(e)}")
        
        fallback_account = event.get("queryStringParameters", {}).get("accountId", "UNKNOWN")
        save_scan_history(user_id, fallback_account, "Failed", "nil")
        
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "Internal Server Error during scan."})
        }