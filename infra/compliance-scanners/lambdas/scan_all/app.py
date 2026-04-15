import json
import boto3
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from boto3.dynamodb.conditions import Key

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

lambda_client  = boto3.client("lambda")
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


def purge_old_findings(account_id):
    table = dynamodb.Table(FINDINGS_TABLE)
    try:
        # 1. Use the GSI we created to quickly find the account's items
        response = table.query(
            IndexName="accountId-status-index", 
            KeyConditionExpression=Key("accountId").eq(account_id)
        )
        items = response.get("Items", [])
        
        if items:
            with table.batch_writer() as batch:
                for item in items:
                    # 2. Delete the item using the base table's exact primary key
                    batch.delete_item(
                        Key={
                            "findingId": item["findingId"]
                        }
                    )
            print(f"Purged {len(items)} old findings for {account_id}")
    except Exception as e:
        print(f"Purge error: {e}")

def invoke_scanner(name, fn, target_account):
    try:
        payload = {"accountId": target_account} if target_account else {}
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


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    query_params   = event.get("queryStringParameters") or {}
    user_id        = query_params.get("userId", "UNKNOWN")
    own_account    = context.invoked_function_arn.split(":")[4]
    target_account = query_params.get("accountId", "").strip()
    scanners_param = query_params.get("scanners", "").strip()

    if target_account:
        if len(target_account) != 12 or not target_account.isdigit():
            return {"statusCode": 400, "headers": CORS_HEADERS,
                    "body": json.dumps({"message": "accountId must be exactly 12 digits"})}
        if target_account == own_account:
            target_account = ""

    is_cross_account = bool(target_account)
    scan_account     = target_account if is_cross_account else own_account

    print(f"Scanning account: {scan_account} | Cross-account: {is_cross_account}")

    # ── Fail fast: verify STS role before scanning ─────────────────────────
    if is_cross_account:
        try:
            sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{target_account}:role/CrossAccountComplianceRole",
                RoleSessionName="ComplianceScanCheck"
            )
        except Exception as e:
            purge_old_findings(scan_account)
            return {
                "statusCode": 403,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "message": f"Access Denied: Could not assume CrossAccountComplianceRole in account {target_account}. "
                               f"The role may be missing or the trust policy is incorrect."
                })
            }

    purge_old_findings(scan_account)

    # ── Filter requested scanners ──────────────────────────────────────────
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
        # Only keep scanners that the user specifically requested
        filtered_scanners = [s for s in ALL_SCANNERS if s[0] in requested]
        if filtered_scanners:
            scanners_to_run = filtered_scanners

    results = {}
    errors  = {}

    # Optimize thread count based on how many scanners are actually running
    thread_count = max(1, len(scanners_to_run))
    
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {
            executor.submit(invoke_scanner, name, fn, target_account): name
            for name, fn in scanners_to_run
        }
        for future in as_completed(futures):
            name, result, error = future.result()
            if error:
                errors[name] = error
            else:
                results[name] = result

    print(f"Scan complete. Results: {list(results.keys())}, Errors: {list(errors.keys())}")

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