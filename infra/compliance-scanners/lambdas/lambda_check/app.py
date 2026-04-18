"""
Lambda Scanner — AI-Enhanced (All Findings)
Audits Lambda functions for deprecated runtimes, public URLs, and encryption settings.
"""
import json
import boto3
import os
import botocore
from datetime import datetime, timezone
from boto3.dynamodb.conditions import Attr

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

SCANNER = "Lambda"
dynamodb = boto3.resource("dynamodb")
table    = dynamodb.Table(os.environ["FINDINGS_TABLE"])
lambda_client = boto3.client("lambda")
AI_FUNCTION   = os.environ.get("AI_ANALYZER_FUNCTION", "ai-security-analyzer")

def get_client(service, target_account, own_account, region_name='us-east-1'):
    if not target_account or target_account == own_account:
        return boto3.client(service, region_name=region_name)
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=f"arn:aws:iam::{target_account}:role/CrossAccountComplianceRole",
        RoleSessionName="LambdaScanSession"
    )["Credentials"]
    return boto3.client(
        service,
        region_name=region_name,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

def call_ai_for_violation(resource_id, violation_type, violation_data, scan_account, org_id):
    """
    Call AI analyzer for a specific Lambda violation.
    """
    payload = {
        "resource_type": "AWS Lambda",
        "resource_id":   resource_id,
        "raw_config": {
            "ViolationType": violation_type,
            **violation_data
        },
        "scanner":       SCANNER,
        "account_id":    scan_account,
        "orgId":         org_id
    }
    
    try:
        resp = lambda_client.invoke(
            FunctionName=AI_FUNCTION,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload)
        )
        
        if "FunctionError" in resp:
            error_payload = json.loads(resp["Payload"].read())
            raise Exception(f"AI error: {error_payload.get('errorMessage', 'Unknown')}")
            
        res_payload = json.loads(resp["Payload"].read())
        if res_payload.get("statusCode") != 200:
            raise Exception(res_payload.get("body"))
            
        body = res_payload.get("body")
        return json.loads(body) if isinstance(body, str) else body
        
    except Exception as e:
        print(f"AI analysis failed for {violation_type}: {str(e)}")
        # Return fallback finding
        return {
            "severity": "MEDIUM",
            "riskScore": "6.0",
            "title": f"Lambda {violation_type} (AI unavailable)",
            "remediation": f"Manual review required. {violation_data.get('details', '')}",
            "complianceFramework": ["AWS-Lambda-Security", "Manual-Review"],
            "cliCommands": []
        }

def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    own_account    = context.invoked_function_arn.split(":")[4]
    aws_region     = context.invoked_function_arn.split(":")[3]
    target_account = event.get("accountId", "").strip()
    org_id = event.get("orgId", "").strip()
    scan_account   = target_account if target_account and target_account != own_account else own_account

    print(f"Lambda Scanner — scanning account: {scan_account} in {aws_region}")
    print("="*60)

    try:
        awslambda = get_client("lambda", target_account, own_account, region_name=aws_region)

        # Delete old Lambda findings
        old_items = table.scan(
            FilterExpression=Attr("scanner").eq(SCANNER) & Attr("accountId").eq(scan_account)
        ).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"✓ Deleted {len(old_items)} old Lambda findings\n")

        # Get all functions
        functions = []
        paginator = awslambda.get_paginator('list_functions')
        for page in paginator.paginate():
            functions.extend(page.get('Functions', []))
            
        print(f"Found {len(functions)} functions to scan\n")
        total_findings_added = 0

        # List of deprecated or soon-to-be deprecated runtimes
        RISKY_RUNTIMES = ['python3.7', 'python3.8', 'nodejs14.x', 'nodejs12.x', 'go1.x', 'ruby2.7']

        for func in functions:
            name = func['FunctionName']
            func_arn = func['FunctionArn']
            print(f"--- Analyzing Lambda: {name} ---")
            
            violations = []

            # ══════════════════════════════════════════════════════════════
            # CHECK 1: Runtime Versions
            # ══════════════════════════════════════════════════════════════
            runtime = func.get('Runtime', 'unknown')
            if runtime in RISKY_RUNTIMES:
                violations.append({
                    "type": "Lambda_RiskyRuntime",
                    "severity_hint": "HIGH",
                    "data": {
                        "Runtime": runtime,
                        "details": f"Function is using a deprecated or unsupported runtime ({runtime})."
                    }
                })
                print(f"  ⚠ Runtime: Deprecated ({runtime})")
            else:
                print(f"  ✓ Runtime: Supported ({runtime})")

            # ══════════════════════════════════════════════════════════════
            # CHECK 2: Environment Variables Encryption
            # ══════════════════════════════════════════════════════════════
            env_vars = func.get('Environment', {})
            if env_vars.get('Variables'):
                if not func.get('KMSKeyArn'):
                    violations.append({
                        "type": "Lambda_DefaultEnvEncryption",
                        "severity_hint": "MEDIUM",
                        "data": {
                            "details": "Environment variables are encrypted using the default AWS key. A Customer Managed Key (CMK) is recommended."
                        }
                    })
                    print("  ⚠ Environment Variables: Using Default AWS KMS Key")
                else:
                    print("  ✓ Environment Variables: CMK Encryption Enabled")
            else:
                print("  ✓ Environment Variables: None configured")

            # ══════════════════════════════════════════════════════════════
            # CHECK 3: Public Function URLs
            # ══════════════════════════════════════════════════════════════
            try:
                url_config = awslambda.get_function_url_config(FunctionName=name)
                auth_type = url_config.get('AuthType')
                if auth_type == 'NONE':
                    violations.append({
                        "type": "Lambda_PublicUrl",
                        "severity_hint": "CRITICAL",
                        "data": {
                            "AuthType": auth_type,
                            "details": "Function URL is public (AuthType: NONE). Anyone can invoke this function."
                        }
                    })
                    print("  ⚠ Function URL: PUBLIC (AuthType: NONE)")
                else:
                    print(f"  ✓ Function URL: Secured (AuthType: {auth_type})")
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    print("  ✓ Function URL: Not configured")
                else:
                    violations.append({
                        "type": "Lambda_UrlCheckError",
                        "severity_hint": "LOW",
                        "data": {"error": str(e)}
                    })

            # ══════════════════════════════════════════════════════════════
            # CHECK 4: X-Ray Tracing
            # ══════════════════════════════════════════════════════════════
            tracing_mode = func.get('TracingConfig', {}).get('Mode', 'PassThrough')
            if tracing_mode == 'PassThrough':
                violations.append({
                    "type": "Lambda_TracingDisabled",
                    "severity_hint": "LOW",
                    "data": {
                        "details": "AWS X-Ray tracing is disabled (PassThrough). Active tracing is recommended for observability and debugging."
                    }
                })
                print("  ⚠ Tracing: Disabled (PassThrough)")
            else:
                print("  ✓ Tracing: Active")


            # ══════════════════════════════════════════════════════════════
            # SAVE FINDINGS TO DYNAMODB
            # ══════════════════════════════════════════════════════════════
            
            if not violations:
                # Fully compliant
                finding_id = f"{scan_account}-{SCANNER}-{name}-compliant"
                table.put_item(Item={
                    "findingId":           finding_id,
                    "accountId":           scan_account,
                    "resourceType":        "AWS Lambda",
                    "resourceId":          func_arn,
                    "severity":            "LOW",
                    "riskScore":           "1.0",
                    "title":               f"Lambda {name} is compliant",
                    "status":              "OPEN",
                    "timestamp":           datetime.utcnow().isoformat() + "Z",
                    "scanner":             SCANNER,
                    "remediation":         "Continue monitoring function runtimes and IAM permissions.",
                    "cliCommands":         [],
                    "complianceFramework": ["AWS-Lambda-Security-Best-Practices"],
                })
                print(f"  ✓ COMPLIANT - Saved 1 finding\n")
                total_findings_added += 1
                
            else:
                # Violations found - call AI for EACH violation separately
                print(f"  ⚠ Found {len(violations)} violations - analyzing with AI...")
                
                for idx, violation in enumerate(violations, 1):
                    violation_type = violation["type"]
                    violation_data = violation["data"]
                    
                    print(f"     [{idx}/{len(violations)}] Analyzing {violation_type}...")
                    
                    ai_result = call_ai_for_violation(func_arn, violation_type, violation_data, scan_account, org_id)
                    
                    finding_id = f"{scan_account}-{SCANNER}-{name}-{violation_type}"
                    table.put_item(Item={
                        "findingId":           finding_id,
                        "accountId":           scan_account,
                        "resourceType":        "AWS Lambda",
                        "resourceId":          func_arn,
                        "severity":            ai_result.get("severity", violation["severity_hint"]),
                        "riskScore":           str(ai_result.get("riskScore", "6.0")),
                        "title":               ai_result.get("title", f"Lambda {violation_type}"),
                        "status":              "OPEN",
                        "timestamp":           datetime.utcnow().isoformat() + "Z",
                        "scanner":             SCANNER,
                        "remediation":         ai_result.get("remediation", "Review and fix this configuration."),
                        "cliCommands":         ai_result.get("cliCommands", []),
                        "complianceFramework": ai_result.get("complianceFramework", ["AWS-Lambda-Security"]),
                    })
                    total_findings_added += 1
                    print(f"        → Saved as {ai_result.get('severity', 'HIGH')}")
                    
                print(f"  ✓ Saved {len(violations)} findings for this function\n")

        print("="*60)
        print(f"LAMBDA SCAN COMPLETE")
        print(f"Functions scanned: {len(functions)}")
        print(f"Total findings: {total_findings_added}")
        print("="*60)

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message":          "Lambda scan complete",
                "accountId":        scan_account,
                "functionsScanned": len(functions),
                "findingsAdded":    total_findings_added
            })
        }

    except Exception as e:
        print(f"✗ Lambda scan failed: {str(e)}")
        import traceback; traceback.print_exc()
        return {"statusCode": 500, "headers": CORS_HEADERS, "body": json.dumps({"error": str(e)})}