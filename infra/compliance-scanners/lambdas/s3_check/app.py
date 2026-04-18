import json
import boto3
import uuid
import os
import botocore
from datetime import datetime
from boto3.dynamodb.conditions import Attr

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}
scanner = "S3"
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["FINDINGS_TABLE"])
lambda_client = boto3.client("lambda")

def get_client(service, target_account, own_account):
    if not target_account or target_account == own_account:
        return boto3.client(service)
    sts = boto3.client("sts")
    try:
        creds = sts.assume_role(
            RoleArn=f"arn:aws:iam::{target_account}:role/CrossAccountComplianceRole",
            RoleSessionName="ComplianceAuditSession"
        )["Credentials"]
        return boto3.client(
            service,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    except Exception as e:
        raise Exception(f"Failed to assume role in {target_account}: {str(e)}")


def call_ai_for_violation(resource_id, violation_type, violation_data, scan_account, org_id):
    """
    Call AI analyzer for a specific violation.
    
    Args:
        resource_id: ARN of the S3 bucket
        violation_type: Type of violation (PublicAccess, NoEncryption, etc.)
        violation_data: Dict containing violation details
        scan_account: Account ID being scanned
    
    Returns:
        dict: AI analysis result
    """
    payload = {
        "resource_type": "S3 Bucket",
        "resource_id": resource_id,
        "raw_config": {
            "ViolationType": violation_type,
            **violation_data
        },
        "scanner": scanner,
        "account_id": scan_account,
        "orgId": org_id
    }
    
    try:
        ai_response = lambda_client.invoke(
            FunctionName=os.environ.get("AI_ANALYZER_FUNCTION", "ai-security-analyzer"),
            InvocationType="RequestResponse",
            Payload=json.dumps(payload)
        )
        
        if "FunctionError" in ai_response:
            error_payload = json.loads(ai_response["Payload"].read())
            raise Exception(f"AI error: {error_payload.get('errorMessage', 'Unknown')}")
        
        response_payload = json.loads(ai_response["Payload"].read())
        
        if response_payload.get("statusCode") != 200:
            raise Exception(f"AI returned {response_payload.get('statusCode')}")
        
        ai_body = response_payload.get("body")
        return json.loads(ai_body) if isinstance(ai_body, str) else ai_body
        
    except Exception as e:
        print(f"AI analysis failed for {violation_type}: {str(e)}")
        # Return fallback finding
        return {
            "severity": "HIGH",
            "riskScore": "7.5",
            "title": f"S3 {violation_type} (AI unavailable)",
            "remediation": f"Manual review required. {violation_data.get('details', '')}",
            "complianceFramework": ["CIS-AWS-2.1", "Manual-Review"],
            "cliCommands": []
        }


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    own_account = context.invoked_function_arn.split(":")[4]
    target_account = event.get("accountId", "").strip()
    org_id = event.get("orgId", "").strip()
    scan_account = target_account if target_account and target_account != own_account else own_account

    print(f"S3 Scanner — scanning account: {scan_account}")
    print("="*60)

    try:
        s3 = get_client("s3", target_account, own_account)

        # Delete old S3 findings for this account
        old_items = table.scan(
            FilterExpression=Attr("scanner").eq("S3") & Attr("accountId").eq(scan_account)
        ).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"✓ Deleted {len(old_items)} old S3 findings\n")

        buckets = s3.list_buckets().get("Buckets", [])
        print(f"Found {len(buckets)} buckets to scan\n")

        total_findings_added = 0

        for bucket in buckets:
            name = bucket["Name"]
            resource_arn = f"arn:aws:s3:::{name}"
            print(f"--- Scanning bucket: {name} ---")
            
            violations = []  # List of all violations found for this bucket
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 1: PUBLIC ACCESS BLOCK
            # ═══════════════════════════════════════════════════════════════
            try:
                pab = s3.get_public_access_block(Bucket=name)
                config = pab["PublicAccessBlockConfiguration"]
                
                # Check each setting individually
                pab_settings = {
                    "BlockPublicAcls": config.get("BlockPublicAcls", False),
                    "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
                    "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
                    "RestrictPublicBuckets": config.get("RestrictPublicBuckets", False)
                }
                
                disabled_settings = [k for k, v in pab_settings.items() if not v]
                
                if disabled_settings:
                    violations.append({
                        "type": "PublicAccessBlock_Disabled",
                        "severity_hint": "CRITICAL",
                        "data": {
                            "BucketName": name,
                            "DisabledSettings": disabled_settings,
                            "CurrentConfig": pab_settings,
                            "details": f"{len(disabled_settings)} public access block settings are disabled"
                        }
                    })
                    print(f"  ⚠ Public Access Block: {len(disabled_settings)} settings disabled")
                else:
                    print(f"  ✓ Public Access Block: Fully enabled")
                    
            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchPublicAccessBlockConfiguration':
                    violations.append({
                        "type": "PublicAccessBlock_Missing",
                        "severity_hint": "CRITICAL",
                        "data": {
                            "BucketName": name,
                            "details": "No public access block configuration exists - bucket may be publicly accessible"
                        }
                    })
                    print(f"  ⚠ Public Access Block: NOT CONFIGURED (CRITICAL)")
                elif error_code != 'AccessDenied':
                    violations.append({
                        "type": "PublicAccessBlock_Error",
                        "severity_hint": "MEDIUM",
                        "data": {"BucketName": name, "error": str(e)}
                    })
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 2: ENCRYPTION
            # ═══════════════════════════════════════════════════════════════
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                if rules:
                    algo = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', 'None')
                    print(f"  ✓ Encryption: Enabled ({algo})")
                else:
                    violations.append({
                        "type": "Encryption_NotConfigured",
                        "severity_hint": "HIGH",
                        "data": {
                            "BucketName": name,
                            "details": "Encryption rules exist but are not properly configured"
                        }
                    })
                    print(f"  ⚠ Encryption: No rules configured")
                    
            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
                    violations.append({
                        "type": "Encryption_Disabled",
                        "severity_hint": "HIGH",
                        "data": {
                            "BucketName": name,
                            "details": "Default encryption is not enabled - data at rest is unencrypted"
                        }
                    })
                    print(f"  ⚠ Encryption: NOT ENABLED (HIGH)")
                elif error_code != 'AccessDenied':
                    violations.append({
                        "type": "Encryption_Error",
                        "severity_hint": "MEDIUM",
                        "data": {"BucketName": name, "error": str(e)}
                    })
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 3: VERSIONING
            # ═══════════════════════════════════════════════════════════════
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                status = ver.get("Status", "Suspended")
                if status != "Enabled":
                    violations.append({
                        "type": "Versioning_Disabled",
                        "severity_hint": "MEDIUM",
                        "data": {
                            "BucketName": name,
                            "CurrentStatus": status,
                            "details": "Versioning is not enabled - accidental deletions cannot be recovered"
                        }
                    })
                    print(f"  ⚠ Versioning: {status}")
                else:
                    print(f"  ✓ Versioning: Enabled")
            except Exception as e:
                violations.append({
                    "type": "Versioning_Error",
                    "severity_hint": "LOW",
                    "data": {"BucketName": name, "error": str(e)}
                })
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 4: ACCESS LOGGING
            # ═══════════════════════════════════════════════════════════════
            try:
                log = s3.get_bucket_logging(Bucket=name)
                if "LoggingEnabled" not in log:
                    violations.append({
                        "type": "Logging_Disabled",
                        "severity_hint": "MEDIUM",
                        "data": {
                            "BucketName": name,
                            "details": "Access logging is not enabled - no audit trail of bucket access"
                        }
                    })
                    print(f"  ⚠ Logging: NOT ENABLED")
                else:
                    target = log["LoggingEnabled"].get("TargetBucket", "Unknown")
                    print(f"  ✓ Logging: Enabled (target: {target})")
            except Exception as e:
                violations.append({
                    "type": "Logging_Error",
                    "severity_hint": "LOW",
                    "data": {"BucketName": name, "error": str(e)}
                })
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 5: BUCKET ACL
            # ═══════════════════════════════════════════════════════════════
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                grants = acl.get('Grants', [])
                public_grants = [g for g in grants if 'URI' in g.get('Grantee', {}) 
                                and 'AllUsers' in g['Grantee']['URI']]
                if public_grants:
                    violations.append({
                        "type": "ACL_Public",
                        "severity_hint": "CRITICAL",
                        "data": {
                            "BucketName": name,
                            "PublicGrantsCount": len(public_grants),
                            "details": f"Bucket has {len(public_grants)} public ACL grants - data may be publicly readable"
                        }
                    })
                    print(f"  ⚠ ACL: PUBLIC ({len(public_grants)} grants)")
                else:
                    print(f"  ✓ ACL: Private")
            except Exception as e:
                pass  # ACL errors are not critical
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 6: BUCKET POLICY
            # ═══════════════════════════════════════════════════════════════
            try:
                policy = s3.get_bucket_policy(Bucket=name)
                policy_doc = json.loads(policy['Policy'])
                
                # Check for wildcard principals
                wildcard_found = False
                for statement in policy_doc.get('Statement', []):
                    principal = statement.get('Principal', {})
                    if principal == '*' or principal.get('AWS') == '*':
                        wildcard_found = True
                        break
                
                if wildcard_found:
                    violations.append({
                        "type": "BucketPolicy_Wildcard",
                        "severity_hint": "CRITICAL",
                        "data": {
                            "BucketName": name,
                            "details": "Bucket policy contains wildcard principal (*) - may grant public access"
                        }
                    })
                    print(f"  ⚠ Bucket Policy: Contains wildcard principal")
                else:
                    print(f"  ✓ Bucket Policy: No wildcard principals")
                    
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    pass  # Not critical
            
            # ═══════════════════════════════════════════════════════════════
            # SAVE FINDINGS TO DYNAMODB
            # ═══════════════════════════════════════════════════════════════
            
            if not violations:
                # Bucket is fully compliant - save a single LOW severity finding
                finding_id = f"{scan_account}-{scanner}-{name}-compliant"
                table.put_item(Item={
                    "findingId": finding_id,
                    "accountId": scan_account,
                    "resourceType": "S3 Bucket",
                    "resourceId": resource_arn,
                    "severity": "LOW",
                    "riskScore": "1.0",
                    "title": f"S3 bucket {name} is compliant",
                    "status": "OPEN",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "scanner": scanner,
                    "remediation": "Continue regular review of bucket configurations.",
                    "cliCommands": [],
                    "complianceFramework": ["CIS-AWS-2.1", "NIST-SI-2"],
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
                    
                    # Call AI for this specific violation
                    ai_result = call_ai_for_violation(resource_arn, violation_type, violation_data, scan_account, org_id)
                    
                    # Save this specific finding
                    finding_id = f"{scan_account}-{scanner}-{name}-{violation_type}"
                    table.put_item(Item={
                        "findingId": finding_id,
                        "accountId": scan_account,
                        "resourceType": "S3 Bucket",
                        "resourceId": resource_arn,
                        "severity": ai_result.get("severity", violation["severity_hint"]),
                        "riskScore": str(ai_result.get("riskScore", "7.0")),
                        "title": ai_result.get("title", f"S3 {violation_type}"),
                        "status": "OPEN",
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "scanner": scanner,
                        "remediation": ai_result.get("remediation", "Review and fix this violation."),
                        "cliCommands": ai_result.get("cliCommands", []),
                        "complianceFramework": ai_result.get("complianceFramework", ["CIS-AWS-2.1"]),
                    })
                    total_findings_added += 1
                    print(f"        → Saved as {ai_result.get('severity', 'HIGH')}")
                
                print(f"  ✓ Saved {len(violations)} findings for this bucket\n")

        print("="*60)
        print(f"S3 SCAN COMPLETE")
        print(f"Buckets scanned: {len(buckets)}")
        print(f"Total findings: {total_findings_added}")
        print("="*60)

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "S3 scan complete",
                "accountId": scan_account,
                "bucketsScanned": len(buckets),
                "findingsAdded": total_findings_added
            })
        }

    except Exception as e:
        print(f"S3 scan error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)})
        }