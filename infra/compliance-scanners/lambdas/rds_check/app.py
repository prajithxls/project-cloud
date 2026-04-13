"""
RDS Scanner — AI-Enhanced (All Findings)
Collects full RDS instance/cluster configuration, logs individual violations.
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

SCANNER       = "RDS"
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
        RoleSessionName="RDSScanSession"
    )["Credentials"]
    return boto3.client(service, region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def call_ai_for_violation(resource_type, resource_id, violation_type, violation_data, scan_account):
    """
    Call AI analyzer for a specific RDS/Aurora violation.
    """
    payload = {
        "resource_type": resource_type,
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
            "riskScore": "7.5",
            "title": f"{resource_type} {violation_type} (AI unavailable)",
            "remediation": f"Manual review required. {violation_data.get('details', '')}",
            "complianceFramework": ["AWS-RDS-Security", "Manual-Review"],
            "cliCommands": []
        }


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    own_account    = context.invoked_function_arn.split(":")[4]
    aws_region     = context.invoked_function_arn.split(":")[3]
    target_account = event.get("accountId", "").strip()
    scan_account   = target_account if target_account and target_account != own_account else own_account

    print(f"RDS Scanner — account: {scan_account} region: {aws_region}")
    print("="*60)

    try:
        rds = get_client("rds", target_account, own_account, aws_region)

        # Delete old RDS findings
        old = table.scan(
            FilterExpression=Attr("scanner").eq(SCANNER) & Attr("accountId").eq(scan_account)
        ).get("Items", [])
        for item in old:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"✓ Deleted {len(old)} old RDS findings\n")

        # ── Fetch all DB instances ────────────────────────────────────────
        instances = []
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
        print(f"Found {len(instances)} RDS instances\n")

        total_findings_added = 0

        for db in instances:
            db_id         = db["DBInstanceIdentifier"]
            db_arn        = db["DBInstanceArn"]
            engine        = db.get("Engine", "unknown")
            print(f"--- Scanning RDS Instance: {db_id} ({engine}) ---")
            
            violations    = []

            # Check 1: Publicly accessible
            if db.get("PubliclyAccessible"):
                violations.append({
                    "type": "RDS_PubliclyAccessible",
                    "severity_hint": "CRITICAL",
                    "data": {"details": "Instance is publicly accessible from the internet."}
                })
                print("  ⚠ Public Access: ENABLED (CRITICAL)")

            # Check 2: Encryption at rest
            if not db.get("StorageEncrypted"):
                violations.append({
                    "type": "RDS_StorageUnencrypted",
                    "severity_hint": "HIGH",
                    "data": {"details": "Storage is not encrypted at rest."}
                })
                print("  ⚠ Encryption: DISABLED (HIGH)")

            # Check 3: Deletion protection
            if not db.get("DeletionProtection"):
                violations.append({
                    "type": "RDS_DeletionProtectionDisabled",
                    "severity_hint": "MEDIUM",
                    "data": {"details": "Deletion protection is disabled. Accidental deletion is possible."}
                })
                print("  ⚠ Deletion Protection: DISABLED (MEDIUM)")

            # Check 4: Backup retention
            retention = db.get("BackupRetentionPeriod", 0)
            if retention < 7:
                violations.append({
                    "type": "RDS_LowBackupRetention",
                    "severity_hint": "MEDIUM",
                    "data": {"BackupRetentionPeriod": retention, "details": f"Backup retention is {retention} days (minimum 7 recommended)."}
                })
                print(f"  ⚠ Backup Retention: {retention} Days (MEDIUM)")

            # Check 5: Multi-AZ
            if not db.get("MultiAZ") and engine not in ("aurora", "aurora-mysql", "aurora-postgresql"):
                violations.append({
                    "type": "RDS_MultiAZDisabled",
                    "severity_hint": "LOW",
                    "data": {"details": "Multi-AZ is not enabled. No automatic failover in case of AZ outage."}
                })
                print("  ⚠ Multi-AZ: DISABLED (LOW)")

            # Check 6: Auto minor version upgrade
            if not db.get("AutoMinorVersionUpgrade"):
                violations.append({
                    "type": "RDS_AutoUpgradeDisabled",
                    "severity_hint": "LOW",
                    "data": {"details": "Auto minor version upgrade is disabled. Security patches are not applied automatically."}
                })
                print("  ⚠ Auto Upgrade: DISABLED (LOW)")

            # Check 7: Enhanced monitoring
            monitoring_interval = db.get("MonitoringInterval", 0)
            if monitoring_interval == 0:
                violations.append({
                    "type": "RDS_EnhancedMonitoringDisabled",
                    "severity_hint": "LOW",
                    "data": {"details": "Enhanced monitoring is disabled. OS-level metrics are not being collected."}
                })
                print("  ⚠ Enhanced Monitoring: DISABLED (LOW)")

            # Check 8: VPC
            if not db.get("DBSubnetGroup", {}).get("VpcId"):
                violations.append({
                    "type": "RDS_NotInVPC",
                    "severity_hint": "MEDIUM",
                    "data": {"details": "Instance is not launched inside a Virtual Private Cloud (VPC)."}
                })
                print("  ⚠ VPC: Instance not in VPC (MEDIUM)")

            # ── Save Instance Findings ──────────────────────────────────────
            if not violations:
                finding_id = f"{scan_account}-{SCANNER}-{db_id}-compliant"
                table.put_item(Item={
                    "findingId":           finding_id,
                    "accountId":           scan_account,
                    "resourceType":        "RDS Instance",
                    "resourceId":          db_arn,
                    "severity":            "LOW",
                    "riskScore":           "1.0",
                    "title":               f"RDS instance {db_id} is compliant",
                    "status":              "OPEN",
                    "timestamp":           datetime.utcnow().isoformat() + "Z",
                    "scanner":             SCANNER,
                    "remediation":         "Continue regular review of RDS configurations.",
                    "cliCommands":         [],
                    "complianceFramework": ["CIS-AWS-RDS", "NIST-SI-2"],
                })
                print(f"  ✓ COMPLIANT - Saved 1 finding\n")
                total_findings_added += 1
            else:
                print(f"  ⚠ Found {len(violations)} violations - analyzing with AI...")
                for idx, violation in enumerate(violations, 1):
                    v_type = violation["type"]
                    v_data = violation["data"]
                    print(f"     [{idx}/{len(violations)}] Analyzing {v_type}...")
                    
                    ai_result = call_ai_for_violation("RDS Instance", db_arn, v_type, v_data, scan_account)
                    
                    finding_id = f"{scan_account}-{SCANNER}-{db_id}-{v_type}"
                    table.put_item(Item={
                        "findingId":           finding_id,
                        "accountId":           scan_account,
                        "resourceType":        "RDS Instance",
                        "resourceId":          db_arn,
                        "severity":            ai_result.get("severity", violation["severity_hint"]),
                        "riskScore":           str(ai_result.get("riskScore", "7.0")),
                        "title":               ai_result.get("title", f"RDS {v_type}"),
                        "status":              "OPEN",
                        "timestamp":           datetime.utcnow().isoformat() + "Z",
                        "scanner":             SCANNER,
                        "remediation":         ai_result.get("remediation", "Review and fix this configuration."),
                        "cliCommands":         ai_result.get("cliCommands", []),
                        "complianceFramework": ai_result.get("complianceFramework", ["CIS-AWS-RDS"]),
                    })
                    total_findings_added += 1
                    print(f"        → Saved as {ai_result.get('severity', 'HIGH')}")
                print(f"  ✓ Saved {len(violations)} findings for this instance\n")

        # ── Also scan Aurora clusters ─────────────────────────────────────
        clusters = []
        try:
            cpag = rds.get_paginator("describe_db_clusters")
            for page in cpag.paginate():
                clusters.extend(page.get("DBClusters", []))
        except Exception as e:
            print(f"Cluster scan error: {e}")

        print(f"Found {len(clusters)} Aurora clusters\n")

        for cluster in clusters:
            cid       = cluster["DBClusterIdentifier"]
            carn      = cluster["DBClusterArn"]
            print(f"--- Scanning Aurora Cluster: {cid} ---")
            
            violations = []

            if not cluster.get("StorageEncrypted"):
                violations.append({
                    "type": "Aurora_StorageUnencrypted",
                    "severity_hint": "HIGH",
                    "data": {"details": "Cluster storage is not encrypted at rest."}
                })
                print("  ⚠ Encryption: DISABLED (HIGH)")

            if not cluster.get("DeletionProtection"):
                violations.append({
                    "type": "Aurora_DeletionProtectionDisabled",
                    "severity_hint": "MEDIUM",
                    "data": {"details": "Deletion protection is disabled for the cluster."}
                })
                print("  ⚠ Deletion Protection: DISABLED (MEDIUM)")

            retention = cluster.get("BackupRetentionPeriod", 0)
            if retention < 7:
                violations.append({
                    "type": "Aurora_LowBackupRetention",
                    "severity_hint": "MEDIUM",
                    "data": {"BackupRetentionPeriod": retention, "details": f"Backup retention is only {retention} days."}
                })
                print(f"  ⚠ Backup Retention: {retention} Days (MEDIUM)")

            if cluster.get("HttpEndpointEnabled"):
                violations.append({
                    "type": "Aurora_HttpEndpointEnabled",
                    "severity_hint": "MEDIUM",
                    "data": {"details": "HTTP endpoint (Data API) is enabled, exposing the cluster over HTTP."}
                })
                print("  ⚠ HTTP Endpoint: ENABLED (MEDIUM)")

            if not violations:
                finding_id = f"{scan_account}-{SCANNER}-cluster-{cid}-compliant"
                table.put_item(Item={
                    "findingId":           finding_id,
                    "accountId":           scan_account,
                    "resourceType":        "Aurora DB Cluster",
                    "resourceId":          carn,
                    "severity":            "LOW",
                    "riskScore":           "1.0",
                    "title":               f"Aurora cluster {cid} is compliant",
                    "status":              "OPEN",
                    "timestamp":           datetime.utcnow().isoformat() + "Z",
                    "scanner":             SCANNER,
                    "remediation":         "Continue monitoring cluster configuration.",
                    "cliCommands":         [],
                    "complianceFramework": ["CIS-AWS-RDS"],
                })
                print(f"  ✓ COMPLIANT - Saved 1 finding\n")
                total_findings_added += 1
            else:
                print(f"  ⚠ Found {len(violations)} violations - analyzing with AI...")
                for idx, violation in enumerate(violations, 1):
                    v_type = violation["type"]
                    v_data = violation["data"]
                    print(f"     [{idx}/{len(violations)}] Analyzing {v_type}...")
                    
                    ai_result = call_ai_for_violation("Aurora DB Cluster", carn, v_type, v_data, scan_account)
                    
                    finding_id = f"{scan_account}-{SCANNER}-cluster-{cid}-{v_type}"
                    table.put_item(Item={
                        "findingId":           finding_id,
                        "accountId":           scan_account,
                        "resourceType":        "Aurora DB Cluster",
                        "resourceId":          carn,
                        "severity":            ai_result.get("severity", violation["severity_hint"]),
                        "riskScore":           str(ai_result.get("riskScore", "7.0")),
                        "title":               ai_result.get("title", f"Aurora {v_type}"),
                        "status":              "OPEN",
                        "timestamp":           datetime.utcnow().isoformat() + "Z",
                        "scanner":             SCANNER,
                        "remediation":         ai_result.get("remediation", "Review and fix this configuration."),
                        "cliCommands":         ai_result.get("cliCommands", []),
                        "complianceFramework": ai_result.get("complianceFramework", ["CIS-AWS-RDS"]),
                    })
                    total_findings_added += 1
                    print(f"        → Saved as {ai_result.get('severity', 'HIGH')}")
                print(f"  ✓ Saved {len(violations)} findings for this cluster\n")

        print("="*60)
        print(f"RDS SCAN COMPLETE")
        print(f"Instances scanned: {len(instances)}")
        print(f"Clusters scanned: {len(clusters)}")
        print(f"Total findings: {total_findings_added}")
        print("="*60)

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message":          "RDS scan complete",
                "accountId":        scan_account,
                "instancesScanned": len(instances),
                "clustersScanned":  len(clusters),
                "findingsAdded":    total_findings_added,
            }),
        }

    except Exception as e:
        print(f"RDS scan error: {e}")
        import traceback; traceback.print_exc()
        return {"statusCode": 500, "headers": CORS_HEADERS,
                "body": json.dumps({"message": "RDS scan failed", "error": str(e)})}