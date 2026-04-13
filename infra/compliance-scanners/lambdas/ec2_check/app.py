"""
EC2 Scanner - Returns ALL findings per instance (not just worst)

Key Changes from Old Version:
- Collects violations as separate objects
- Calls AI once per violation type
- Saves multiple findings per EC2 instance
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
scanner = "EC2"
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["FINDINGS_TABLE"])
lambda_client = boto3.client("lambda")

def get_client(service, target_account, own_account, region_name='us-east-1'):
    if not target_account or target_account == own_account:
        return boto3.client(service, region_name=region_name)
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=f"arn:aws:iam::{target_account}:role/CrossAccountComplianceRole",
        RoleSessionName="EC2ScanSession"
    )["Credentials"]
    return boto3.client(service, region_name=region_name,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"])

def call_ai_for_violation(resource_id, violation_type, violation_data, scan_account):
    """Call AI analyzer for a specific EC2 violation."""
    payload = {
        "resource_type": "EC2 Instance",
        "resource_id": resource_id,
        "raw_config": {
            "ViolationType": violation_type,
            **violation_data
        },
        "scanner": scanner,
        "account_id": scan_account
    }
    
    try:
        ai_response = lambda_client.invoke(
            FunctionName=os.environ.get("AI_ANALYZER_FUNCTION", "ai-security-analyzer"),
            InvocationType="RequestResponse",
            Payload=json.dumps(payload)
        )
        
        if "FunctionError" in ai_response:
            raise Exception("AI function error")
        
        response_payload = json.loads(ai_response["Payload"].read())
        if response_payload.get("statusCode") != 200:
            raise Exception(f"AI returned {response_payload.get('statusCode')}")
        
        ai_body = response_payload.get("body")
        return json.loads(ai_body) if isinstance(ai_body, str) else ai_body
        
    except Exception as e:
        print(f"AI analysis failed for {violation_type}: {str(e)}")
        return {
            "severity": "HIGH",
            "riskScore": "7.5",
            "title": f"EC2 {violation_type} (AI unavailable)",
            "remediation": f"Manual review required. {violation_data.get('details', '')}",
            "complianceFramework": ["CIS-AWS-4.1"],
            "cliCommands": []
        }

def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    own_account = context.invoked_function_arn.split(":")[4]
    aws_region = context.invoked_function_arn.split(":")[3]
    target_account = event.get("accountId", "").strip()
    scan_account = target_account if target_account and target_account != own_account else own_account

    print(f"EC2 Scanner — scanning account: {scan_account} in {aws_region}")
    print("="*60)

    try:
        ec2 = get_client("ec2", target_account, own_account, region_name=aws_region)

        # Delete old EC2 findings
        old_items = table.scan(
            FilterExpression=Attr("scanner").eq(scanner) & Attr("accountId").eq(scan_account)
        ).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"✓ Deleted {len(old_items)} old EC2 findings\n")

        # Get all instances
        instances = []
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                instances.extend(reservation.get('Instances', []))
        
        # Filter out terminated instances
        instances = [i for i in instances 
                    if i.get('State', {}).get('Name') not in ['terminated', 'shutting-down']]
        
        print(f"Found {len(instances)} active instances to scan\n")
        total_findings_added = 0

        for instance in instances:
            instance_id = instance['InstanceId']
            resource_arn = f"arn:aws:ec2:{aws_region}:{scan_account}:instance/{instance_id}"
            print(f"--- Scanning instance: {instance_id} ---")
            
            violations = []
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 1: IMDSv2 ENFORCEMENT
            # ═══════════════════════════════════════════════════════════════
            metadata_options = instance.get('MetadataOptions', {})
            imdsv2 = metadata_options.get('HttpTokens', 'optional')
            
            if imdsv2 != 'required':
                violations.append({
                    "type": "IMDSv2_NotEnforced",
                    "severity_hint": "HIGH",
                    "data": {
                        "InstanceId": instance_id,
                        "CurrentSetting": imdsv2,
                        "InstanceType": instance['InstanceType'],
                        "details": "IMDSv2 is not strictly enforced - instance vulnerable to SSRF attacks"
                    }
                })
                print(f"  ⚠ IMDSv2: {imdsv2} (should be 'required')")
            else:
                print(f"  ✓ IMDSv2: Enforced")
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 2: SECURITY GROUP RULES (SSH/RDP OPEN TO 0.0.0.0/0)
            # ═══════════════════════════════════════════════════════════════
            sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
            
            if sg_ids:
                try:
                    sgs = ec2.describe_security_groups(GroupIds=sg_ids).get('SecurityGroups', [])
                    open_ports = []
                    
                    for sg in sgs:
                        for permission in sg.get('IpPermissions', []):
                            from_port = permission.get('FromPort')
                            to_port = permission.get('ToPort')
                            
                            # Check for SSH (22) or RDP (3389) open to 0.0.0.0/0
                            if from_port in [22, 3389] or (from_port and to_port and from_port <= 22 <= to_port) or (from_port and to_port and from_port <= 3389 <= to_port):
                                for ip_range in permission.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        open_ports.append({
                                            "Port": from_port or to_port,
                                            "SecurityGroup": sg['GroupId'],
                                            "Protocol": permission.get('IpProtocol', 'unknown')
                                        })
                    
                    if open_ports:
                        violations.append({
                            "type": "SecurityGroup_OpenPorts",
                            "severity_hint": "CRITICAL",
                            "data": {
                                "InstanceId": instance_id,
                                "OpenPorts": open_ports,
                                "SecurityGroups": sg_ids,
                                "details": f"{len(open_ports)} critical ports (SSH/RDP) are open to the internet (0.0.0.0/0)"
                            }
                        })
                        print(f"  ⚠ Security Groups: {len(open_ports)} ports open to 0.0.0.0/0 (CRITICAL)")
                    else:
                        print(f"  ✓ Security Groups: No dangerous open ports")
                        
                except Exception as e:
                    print(f"  ⚠ Security Groups: Error checking - {str(e)}")
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 3: PUBLIC IP ADDRESS
            # ═══════════════════════════════════════════════════════════════
            public_ip = instance.get('PublicIpAddress')
            
            if public_ip:
                violations.append({
                    "type": "PublicIP_Assigned",
                    "severity_hint": "MEDIUM",
                    "data": {
                        "InstanceId": instance_id,
                        "PublicIP": public_ip,
                        "details": "Instance has a public IP address - increases attack surface"
                    }
                })
                print(f"  ⚠ Public IP: {public_ip} (consider using private subnet)")
            else:
                print(f"  ✓ Public IP: None (private instance)")
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 4: IAM INSTANCE PROFILE
            # ═══════════════════════════════════════════════════════════════
            iam_profile = instance.get('IamInstanceProfile', {}).get('Arn')
            
            if not iam_profile:
                violations.append({
                    "type": "IAM_InstanceProfile_Missing",
                    "severity_hint": "MEDIUM",
                    "data": {
                        "InstanceId": instance_id,
                        "details": "No IAM instance profile attached - applications may use hardcoded credentials"
                    }
                })
                print(f"  ⚠ IAM Profile: None (consider attaching instance profile)")
            else:
                print(f"  ✓ IAM Profile: {iam_profile.split('/')[-1]}")
            
            # ═══════════════════════════════════════════════════════════════
            # CHECK 5: EBS ENCRYPTION
            # ═══════════════════════════════════════════════════════════════
            block_devices = instance.get('BlockDeviceMappings', [])
            unencrypted_volumes = []
            
            for bd in block_devices:
                ebs = bd.get('Ebs', {})
                volume_id = ebs.get('VolumeId')
                if volume_id:
                    try:
                        vol = ec2.describe_volumes(VolumeIds=[volume_id]).get('Volumes', [])[0]
                        if not vol.get('Encrypted', False):
                            unencrypted_volumes.append(volume_id)
                    except Exception:
                        pass
            
            if unencrypted_volumes:
                violations.append({
                    "type": "EBS_Unencrypted",
                    "severity_hint": "HIGH",
                    "data": {
                        "InstanceId": instance_id,
                        "UnencryptedVolumes": unencrypted_volumes,
                        "details": f"{len(unencrypted_volumes)} EBS volumes are not encrypted at rest"
                    }
                })
                print(f"  ⚠ EBS Encryption: {len(unencrypted_volumes)} unencrypted volumes")
            else:
                print(f"  ✓ EBS Encryption: All volumes encrypted")
            
            # ═══════════════════════════════════════════════════════════════
            # SAVE FINDINGS TO DYNAMODB
            # ═══════════════════════════════════════════════════════════════
            
            if not violations:
                # Instance is compliant
                finding_id = f"{scan_account}-{scanner}-{instance_id}-compliant"
                table.put_item(Item={
                    "findingId": finding_id,
                    "accountId": scan_account,
                    "resourceType": "EC2 Instance",
                    "resourceId": resource_arn,
                    "severity": "LOW",
                    "riskScore": "1.0",
                    "title": f"EC2 instance {instance_id} is compliant",
                    "status": "OPEN",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "scanner": scanner,
                    "remediation": "Continue regular security reviews.",
                    "cliCommands": [],
                    "complianceFramework": ["CIS-AWS-4.1", "AWS-Security-Best-Practices"],
                })
                print(f"  ✓ COMPLIANT - Saved 1 finding\n")
                total_findings_added += 1
            else:
                # Violations found - call AI for each
                print(f"  ⚠ Found {len(violations)} violations - analyzing with AI...")
                
                for idx, violation in enumerate(violations, 1):
                    violation_type = violation["type"]
                    violation_data = violation["data"]
                    
                    print(f"     [{idx}/{len(violations)}] Analyzing {violation_type}...")
                    
                    ai_result = call_ai_for_violation(resource_arn, violation_type, violation_data, scan_account)
                    
                    finding_id = f"{scan_account}-{scanner}-{instance_id}-{violation_type}"
                    table.put_item(Item={
                        "findingId": finding_id,
                        "accountId": scan_account,
                        "resourceType": "EC2 Instance",
                        "resourceId": resource_arn,
                        "severity": ai_result.get("severity", violation["severity_hint"]),
                        "riskScore": str(ai_result.get("riskScore", "7.0")),
                        "title": ai_result.get("title", f"EC2 {violation_type}"),
                        "status": "OPEN",
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "scanner": scanner,
                        "remediation": ai_result.get("remediation", "Review and fix this violation."),
                        "cliCommands": ai_result.get("cliCommands", []),
                        "complianceFramework": ai_result.get("complianceFramework", ["CIS-AWS-4.1"]),
                    })
                    total_findings_added += 1
                    print(f"        → Saved as {ai_result.get('severity', 'HIGH')}")
                
                print(f"  ✓ Saved {len(violations)} findings for this instance\n")

        print("="*60)
        print(f"EC2 SCAN COMPLETE")
        print(f"Instances scanned: {len(instances)}")
        print(f"Total findings: {total_findings_added}")
        print("="*60)

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "EC2 scan complete",
                "accountId": scan_account,
                "instancesScanned": len(instances),
                "findingsAdded": total_findings_added
            })
        }

    except Exception as e:
        print(f"EC2 scan error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)})
        }