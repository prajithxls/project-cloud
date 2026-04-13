"""
IAM Scanner — AI-Enhanced (All Findings)
Checks IAM users for missing MFA, stale keys, overly permissive policies, and dormancy.
"""
import json
import boto3
import os
from datetime import datetime, timezone
from boto3.dynamodb.conditions import Attr

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

SCANNER = "IAM"
dynamodb = boto3.resource("dynamodb")
table    = dynamodb.Table(os.environ["FINDINGS_TABLE"])
lambda_client = boto3.client("lambda")

# Note: Using your specific environment variable for the IAM AI Brain
AI_FUNCTION = os.environ.get("AI_BRAIN_FUNCTION_NAME", "compliance-scanners-dev-aiBrain")


def get_client(service, target_account, own_account):
    if not target_account or target_account == own_account:
        return boto3.client(service)
    sts   = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=f"arn:aws:iam::{target_account}:role/CrossAccountComplianceRole",
        RoleSessionName="ComplianceAuditSession"
    )["Credentials"]
    return boto3.client(service,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )


def call_ai_for_violation(resource_id, violation_type, violation_data, scan_account):
    """
    Call AI analyzer for a specific IAM violation.
    """
    payload = {
        "resource_type": "IAM User",
        "resource_id":   resource_id,
        "raw_config": {
            "ViolationType": violation_type,
            **violation_data
        },
        "scanner":       SCANNER,
        "account_id":    scan_account
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
            
        result = json.loads(resp["Payload"].read().decode("utf-8"))
        
        # Handle cases where the response is nested in a 'body' string
        if isinstance(result, dict) and "body" in result:
            body = result["body"]
            result = json.loads(body) if isinstance(body, str) else body
            
        return result
        
    except Exception as e:
        print(f"AI analysis failed for {violation_type}: {str(e)}")
        # Return fallback finding
        return {
            "severity": "HIGH",
            "riskScore": "7.5",
            "title": f"IAM {violation_type} (AI unavailable)",
            "remediation": f"Manual review required. {violation_data.get('details', '')}",
            "complianceFramework": ["CIS-AWS-1.0", "Manual-Review"],
            "cliCommands": []
        }


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    own_account    = context.invoked_function_arn.split(":")[4]
    target_account = event.get("accountId", "").strip()
    scan_account   = target_account if target_account and target_account != own_account else own_account

    print(f"IAM Scanner — scanning account: {scan_account}")
    print("="*60)

    try:
        iam = get_client("iam", target_account, own_account)

        # 1. Delete old IAM findings
        old_items = table.scan(
            FilterExpression=Attr("scanner").eq(SCANNER) & Attr("accountId").eq(scan_account)
        ).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"✓ Deleted {len(old_items)} old IAM findings\n")

        # 2. List all users
        users = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page["Users"])
        print(f"Found {len(users)} IAM users to scan\n")

        total_findings_added = 0
        now = datetime.now(timezone.utc)

        # 3. Gather and Filter config for each user
        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]
            print(f"--- Analyzing user: {username} ---")
            
            violations = []

            # -- Collect Data --
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            has_mfa = len(mfa_devices) > 0

            attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
            attached_policies = [p["PolicyName"] for p in attached]
            inline_policies = iam.list_user_policies(UserName=username).get("PolicyNames", [])
            
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            
            pwd_last_used = user.get("PasswordLastUsed")
            days_since_login = (now - pwd_last_used).days if pwd_last_used else "Never"
            has_console_access = pwd_last_used is not None

            # ====================================================================
            # CHECK 1: Missing MFA for Console Users
            # ====================================================================
            if has_console_access and not has_mfa:
                violations.append({
                    "type": "IAM_NoMFA",
                    "severity_hint": "CRITICAL",
                    "data": {
                        "UserName": username,
                        "details": "User has console access but Multi-Factor Authentication (MFA) is disabled."
                    }
                })
                print("  ⚠ MFA: Disabled for console user (CRITICAL)")
            elif has_mfa:
                print("  ✓ MFA: Enabled")

            # ====================================================================
            # CHECK 2: Stale Access Keys (> 90 Days)
            # ====================================================================
            stale_keys = []
            has_active_keys = False
            for key in keys:
                if key["Status"] == "Active":
                    has_active_keys = True
                    age_days = (now - key["CreateDate"]).days if "CreateDate" in key else 0
                    if age_days > 90:
                        stale_keys.append({"AccessKeyId": key["AccessKeyId"], "AgeInDays": age_days})
            
            if stale_keys:
                violations.append({
                    "type": "IAM_StaleAccessKeys",
                    "severity_hint": "HIGH",
                    "data": {
                        "UserName": username,
                        "StaleKeys": stale_keys,
                        "details": f"User has {len(stale_keys)} active access key(s) older than 90 days."
                    }
                })
                print(f"  ⚠ Access Keys: {len(stale_keys)} stale key(s) found (>90 days)")
            else:
                print("  ✓ Access Keys: Healthy or none active")

            # ====================================================================
            # CHECK 3: Overly Permissive Policies (Admin/FullAccess)
            # ====================================================================
            risky_policies = [p for p in attached_policies if "Administrator" in p or "FullAccess" in p]
            if risky_policies:
                violations.append({
                    "type": "IAM_OverlyPermissivePolicy",
                    "severity_hint": "HIGH",
                    "data": {
                        "UserName": username,
                        "RiskyPolicies": risky_policies,
                        "details": "User has highly permissive or administrative policies attached directly instead of via a group."
                    }
                })
                print(f"  ⚠ Policies: Directly attached risky policies {risky_policies}")

            # ====================================================================
            # CHECK 4: Dormant User Accounts
            # ====================================================================
            is_inactive_console = days_since_login == "Never" or (isinstance(days_since_login, int) and days_since_login > 90)
            if not has_active_keys and is_inactive_console:
                violations.append({
                    "type": "IAM_DormantUser",
                    "severity_hint": "MEDIUM",
                    "data": {
                        "UserName": username,
                        "DaysSinceLastLogin": days_since_login,
                        "details": "User account is dormant (no active access keys and no recent console login)."
                    }
                })
                print("  ⚠ Account Status: Dormant (>90 days inactive)")


            # ====================================================================
            # SAVE FINDINGS TO DYNAMODB
            # ====================================================================
            if not violations:
                # User is fully compliant
                finding_id = f"{scan_account}-{SCANNER}-{username}-compliant"
                table.put_item(Item={
                    "findingId":           finding_id,
                    "accountId":           scan_account,
                    "resourceType":        "IAM User",
                    "resourceId":          user_arn,
                    "severity":            "LOW",
                    "riskScore":           "1.0",
                    "title":               f"IAM User {username} is compliant",
                    "status":              "OPEN",
                    "timestamp":           datetime.utcnow().isoformat() + "Z",
                    "scanner":             SCANNER,
                    "remediation":         "Continue regular access reviews.",
                    "cliCommands":         [],
                    "complianceFramework": ["CIS-AWS-1.0"],
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
                    
                    ai_result = call_ai_for_violation(user_arn, violation_type, violation_data, scan_account)
                    
                    finding_id = f"{scan_account}-{SCANNER}-{username}-{violation_type}"
                    table.put_item(Item={
                        "findingId":           finding_id,
                        "accountId":           scan_account,
                        "resourceType":        "IAM User",
                        "resourceId":          user_arn,
                        "severity":            ai_result.get("severity", violation["severity_hint"]),
                        "riskScore":           str(ai_result.get("riskScore", "7.0")),
                        "title":               ai_result.get("title", f"IAM {violation_type}"),
                        "status":              "OPEN",
                        "timestamp":           datetime.utcnow().isoformat() + "Z",
                        "scanner":             SCANNER,
                        "remediation":         ai_result.get("remediation", "Review and fix this IAM configuration."),
                        "cliCommands":         ai_result.get("cliCommands", []),
                        "complianceFramework": ai_result.get("complianceFramework", ["CIS-AWS-1.0"]),
                    })
                    total_findings_added += 1
                    print(f"        → Saved as {ai_result.get('severity', 'HIGH')}")
                    
                print(f"  ✓ Saved {len(violations)} findings for this user\n")

        print("="*60)
        print(f"IAM SCAN COMPLETE")
        print(f"Users scanned: {len(users)}")
        print(f"Total findings: {total_findings_added}")
        print("="*60)

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message":       "IAM scan complete",
                "accountId":     scan_account,
                "usersScanned":  len(users),
                "findingsAdded": total_findings_added,
            }),
        }

    except Exception as e:
        print(f"❌ IAM scan error: {str(e)}")
        import traceback; traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "IAM scan failed", "error": str(e)}),
        }