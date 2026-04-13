"""
CloudTrail Scanner — AI-Enhanced (All Findings)
Checks trail configuration for gaps in audit logging coverage.
"""
import json
import boto3
import os
from datetime import datetime
from boto3.dynamodb.conditions import Attr

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

SCANNER       = "CLOUDTRAIL"
dynamodb      = boto3.resource("dynamodb")
table         = dynamodb.Table(os.environ["FINDINGS_TABLE"])
lambda_client = boto3.client("lambda")
AI_FUNCTION   = os.environ.get("AI_ANALYZER_FUNCTION", "compliance-scanners-dev-aiBrain")


def get_client(service, target_account, own_account, region):
    if not target_account or target_account == own_account:
        return boto3.client(service, region_name=region)
    sts   = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=f"arn:aws:iam::{target_account}:role/CrossAccountComplianceRole",
        RoleSessionName="CloudTrailScanSession"
    )["Credentials"]
    return boto3.client(service, region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def call_ai_for_violation(resource_id, violation_type, violation_data, scan_account):
    """
    Call AI analyzer for a specific violation.
    """
    payload = {
        "resource_type": "AWS CloudTrail",
        "resource_id":   resource_id,
        "raw_config": {
            "ViolationType": violation_type,
            **violation_data
        },
        "scanner":       SCANNER,
        "account_id":    scan_account,
    }
    
    try:
        resp = lambda_client.invoke(
            FunctionName=AI_FUNCTION,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload),
        )
        
        if "FunctionError" in resp:
            error_payload = json.loads(resp["Payload"].read())
            raise Exception(f"AI error: {error_payload.get('errorMessage', 'Unknown')}")
            
        result = json.loads(resp["Payload"].read())
        
        if result.get("statusCode") != 200:
            raise Exception(f"AI returned {result.get('statusCode')}")
            
        body = result.get("body")
        return json.loads(body) if isinstance(body, str) else body
        
    except Exception as e:
        print(f"AI analysis failed for {violation_type}: {str(e)}")
        # Return fallback finding
        return {
            "severity": "HIGH",
            "riskScore": "8.0",
            "title": f"CloudTrail {violation_type} (AI unavailable)",
            "remediation": f"Manual review required. {violation_data.get('details', '')}",
            "complianceFramework": ["CIS-AWS-3.1", "Manual-Review"],
            "cliCommands": []
        }


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    own_account    = context.invoked_function_arn.split(":")[4]
    aws_region     = context.invoked_function_arn.split(":")[3]
    target_account = event.get("accountId", "").strip()
    scan_account   = target_account if target_account and target_account != own_account else own_account

    print(f"CloudTrail Scanner — scanning account: {scan_account} region: {aws_region}")
    print("="*60)

    try:
        ct = get_client("cloudtrail", target_account, own_account, aws_region)

        # Delete old CloudTrail findings
        old = table.scan(
            FilterExpression=Attr("scanner").eq(SCANNER) & Attr("accountId").eq(scan_account)
        ).get("Items", [])
        for item in old:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"✓ Deleted {len(old)} old CloudTrail findings\n")

        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        print(f"Found {len(trails)} trails in region\n")

        total_findings_added = 0

        # ── Account-level check: no trails at all ─────────────────────────
        if not trails:
            print("  ⚠ No CloudTrail trails found — escalating to AI")
            
            violation_type = "NO_TRAILS"
            violation_data = {
                "TrailsFound": 0,
                "Region": aws_region,
                "details": "No CloudTrail trails configured in this region. AWS API activity is not being audited."
            }
            resource_id = f"arn:aws:cloudtrail:{aws_region}:{scan_account}:trail/no-trail"
            
            ai_result = call_ai_for_violation(resource_id, violation_type, violation_data, scan_account)

            table.put_item(Item={
                "findingId":           f"{scan_account}-{SCANNER}-no-trail",
                "accountId":           scan_account,
                "resourceType":        "AWS CloudTrail",
                "resourceId":          resource_id,
                "severity":            ai_result.get("severity", "CRITICAL"),
                "riskScore":           str(ai_result.get("riskScore", "9.5")),
                "title":               ai_result.get("title", "No CloudTrail trails configured"),
                "status":              "OPEN",
                "timestamp":           datetime.utcnow().isoformat() + "Z",
                "scanner":             SCANNER,
                "remediation":         ai_result.get("remediation", "Create a multi-region CloudTrail trail immediately."),
                "cliCommands":         ai_result.get("cliCommands", []),
                "complianceFramework": ai_result.get("complianceFramework", ["CIS-AWS-3.1"]),
            })
            total_findings_added += 1

        # ── Scan individual trails ────────────────────────────────────────
        for trail in trails:
            trail_name = trail["Name"]
            trail_arn  = trail["TrailARN"]
            print(f"--- Scanning trail: {trail_name} ---")
            
            violations = []
            
            # Check 1: Multi-region
            if not trail.get("IsMultiRegionTrail"):
                violations.append({
                    "type": "CloudTrail_SingleRegion",
                    "severity_hint": "HIGH",
                    "data": {
                        "TrailName": trail_name,
                        "details": "Trail only logs this region — multi-region events missed"
                    }
                })
                print("  ⚠ Multi-region: Disabled")
            else:
                print("  ✓ Multi-region: Enabled")

            # Check 2: Log file validation
            if not trail.get("LogFileValidationEnabled"):
                violations.append({
                    "type": "CloudTrail_ValidationDisabled",
                    "severity_hint": "MEDIUM",
                    "data": {
                        "TrailName": trail_name,
                        "details": "Log file integrity validation disabled — logs can be tampered"
                    }
                })
                print("  ⚠ Log Validation: Disabled")
            else:
                print("  ✓ Log Validation: Enabled")

            # Check 3: Trail status (logging enabled?)
            try:
                status = ct.get_trail_status(Name=trail_arn)
                is_logging = status.get("IsLogging", False)
                if not is_logging:
                    violations.append({
                        "type": "CloudTrail_LoggingDisabled",
                        "severity_hint": "CRITICAL",
                        "data": {
                            "TrailName": trail_name,
                            "details": "Trail exists but logging is currently DISABLED"
                        }
                    })
                    print("  ⚠ Logging: DISABLED")
                else:
                    print("  ✓ Logging: Active")
            except Exception as e:
                violations.append({
                    "type": "CloudTrail_StatusError",
                    "severity_hint": "LOW",
                    "data": {"TrailName": trail_name, "error": str(e)}
                })

            # Check 4: CloudWatch Logs integration
            if not trail.get("CloudWatchLogsLogGroupArn"):
                violations.append({
                    "type": "CloudTrail_NoCloudWatch",
                    "severity_hint": "MEDIUM",
                    "data": {
                        "TrailName": trail_name,
                        "details": "Trail not integrated with CloudWatch Logs — no real-time monitoring"
                    }
                })
                print("  ⚠ CloudWatch Logs: Not Configured")
            else:
                print("  ✓ CloudWatch Logs: Integrated")

            # Check 5: S3 bucket encryption
            bucket = trail.get("S3BucketName", "")
            if bucket:
                try:
                    s3 = get_client("s3", target_account, own_account, "us-east-1")
                    s3.get_bucket_encryption(Bucket=bucket)
                    print("  ✓ S3 Bucket Encryption: Enabled")
                except Exception as e:
                    violations.append({
                        "type": "CloudTrail_S3Unencrypted",
                        "severity_hint": "MEDIUM",
                        "data": {
                            "TrailName": trail_name,
                            "BucketName": bucket,
                            "details": "S3 bucket storing trail logs is not encrypted or inaccessible"
                        }
                    })
                    print(f"  ⚠ S3 Bucket Encryption: Missing or Unverified")

            # Check 6: KMS encryption for trail logs
            kms_key = trail.get("KMSKeyId", "")
            if not kms_key:
                violations.append({
                    "type": "CloudTrail_NoKMS",
                    "severity_hint": "LOW",
                    "data": {
                        "TrailName": trail_name,
                        "details": "Trail logs are not encrypted with a KMS CMK"
                    }
                })
                print("  ⚠ KMS Encryption: Not Configured")
            else:
                print("  ✓ KMS Encryption: Configured")

            # Check 7: Event selectors (Write events)
            try:
                selectors = ct.get_event_selectors(TrailName=trail_arn)
                es = selectors.get("EventSelectors", [])
                if es and all(s.get("ReadWriteType") == "ReadOnly" for s in es):
                    violations.append({
                        "type": "CloudTrail_NoWriteEvents",
                        "severity_hint": "HIGH",
                        "data": {
                            "TrailName": trail_name,
                            "details": "Trail only logs read events — write/mutating API calls not captured"
                        }
                    })
                    print("  ⚠ Event Selectors: Write events not logged")
            except Exception as e:
                pass 

            # ── SAVE FINDINGS TO DYNAMODB ─────────────────────────────────
            if not violations:
                # Fully compliant
                finding_id = f"{scan_account}-{SCANNER}-{trail_name}-compliant"
                table.put_item(Item={
                    "findingId":           finding_id,
                    "accountId":           scan_account,
                    "resourceType":        "AWS CloudTrail",
                    "resourceId":          trail_arn,
                    "severity":            "LOW",
                    "riskScore":           "1.0",
                    "title":               f"CloudTrail {trail_name} is compliant",
                    "status":              "OPEN",
                    "timestamp":           datetime.utcnow().isoformat() + "Z",
                    "scanner":             SCANNER,
                    "remediation":         "Continue monitoring trail configuration.",
                    "cliCommands":         [],
                    "complianceFramework": ["CIS-AWS-3.1"],
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
                    
                    ai_result = call_ai_for_violation(trail_arn, violation_type, violation_data, scan_account)
                    
                    finding_id = f"{scan_account}-{SCANNER}-{trail_name}-{violation_type}"
                    table.put_item(Item={
                        "findingId":           finding_id,
                        "accountId":           scan_account,
                        "resourceType":        "AWS CloudTrail",
                        "resourceId":          trail_arn,
                        "severity":            ai_result.get("severity", violation["severity_hint"]),
                        "riskScore":           str(ai_result.get("riskScore", "7.0")),
                        "title":               ai_result.get("title", f"CloudTrail {violation_type}"),
                        "status":              "OPEN",
                        "timestamp":           datetime.utcnow().isoformat() + "Z",
                        "scanner":             SCANNER,
                        "remediation":         ai_result.get("remediation", "Review and fix this configuration."),
                        "cliCommands":         ai_result.get("cliCommands", []),
                        "complianceFramework": ai_result.get("complianceFramework", ["CIS-AWS-3.1"]),
                    })
                    total_findings_added += 1
                    print(f"        → Saved as {ai_result.get('severity', 'HIGH')}")
                    
                print(f"  ✓ Saved {len(violations)} findings for this trail\n")

        print("="*60)
        print(f"CLOUDTRAIL SCAN COMPLETE")
        print(f"Trails scanned: {len(trails)}")
        print(f"Total findings: {total_findings_added}")
        print("="*60)

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message":       "CloudTrail scan complete",
                "accountId":     scan_account,
                "trailsScanned": len(trails),
                "findingsAdded": total_findings_added,
            }),
        }

    except Exception as e:
        print(f"CloudTrail scan error: {e}")
        import traceback; traceback.print_exc()
        return {"statusCode": 500, "headers": CORS_HEADERS,
                "body": json.dumps({"message": "CloudTrail scan failed", "error": str(e)})}