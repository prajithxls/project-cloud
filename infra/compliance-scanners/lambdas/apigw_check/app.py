"""
API Gateway Scanner — AI-Enhanced (All Findings)
Audits REST APIs (v1) and HTTP/WebSocket APIs (v2) for security misconfigurations.
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

SCANNER       = "APIGW"
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
        RoleSessionName="APIGWScanSession"
    )["Credentials"]
    return boto3.client(service, region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def call_ai_for_violation(resource_type, resource_id, violation_type, violation_data, scan_account, org_id):
    """
    Call AI analyzer for a specific API Gateway violation.
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
        "orgId":         org_id,
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
        return {
            "severity": "HIGH",
            "riskScore": "7.5",
            "title": f"API Gateway {violation_type} (AI unavailable)",
            "remediation": f"Manual review required. {violation_data.get('details', '')}",
            "complianceFramework": ["AWS-APIGW-Security", "Manual-Review"],
            "cliCommands": []
        }


def scan_rest_api(apigw, api, aws_region):
    """Scan a REST API (v1) and return structured violations."""
    api_id   = api["id"]
    api_name = api.get("name", api_id)
    api_arn  = f"arn:aws:apigateway:{aws_region}::/restapis/{api_id}"
    violations = []

    # Check 1: Stage-level configurations (WAF, Logging, Tracing)
    try:
        stages = apigw.get_stages(restApiId=api_id).get("item", [])
        for stage in stages:
            stage_name = stage["stageName"]
            
            # Check: Logging disabled
            log_level = stage.get("defaultRouteSettings", {}).get("loggingLevel") or \
                        stage.get("methodSettings", {}).get("*/*", {}).get("loggingLevel", "OFF")
            if log_level in ("OFF", None, ""):
                violations.append({
                    "type": f"LoggingDisabled_{stage_name}",
                    "severity_hint": "HIGH",
                    "data": {"StageName": stage_name, "details": f"Stage '{stage_name}' has logging OFF — API calls are not audited."}
                })
                print(f"  ⚠ Stage {stage_name}: Logging OFF (HIGH)")

            # Check: WAF not associated
            if not stage.get("webAclArn"):
                violations.append({
                    "type": f"NoWAF_{stage_name}",
                    "severity_hint": "HIGH",
                    "data": {"StageName": stage_name, "details": f"Stage '{stage_name}' has no WAF Web ACL attached — vulnerable to DDoS/injection."}
                })
                print(f"  ⚠ Stage {stage_name}: No WAF Web ACL (HIGH)")

            # Check: X-Ray tracing
            if not stage.get("tracingEnabled"):
                violations.append({
                    "type": f"TracingDisabled_{stage_name}",
                    "severity_hint": "LOW",
                    "data": {"StageName": stage_name, "details": f"Stage '{stage_name}' has X-Ray tracing disabled."}
                })
                print(f"  ⚠ Stage {stage_name}: Tracing Disabled (LOW)")

            # Check: Metrics
            metrics = stage.get("methodSettings", {}).get("*/*", {}).get("metricsEnabled", False)
            if not metrics:
                violations.append({
                    "type": f"MetricsDisabled_{stage_name}",
                    "severity_hint": "LOW",
                    "data": {"StageName": stage_name, "details": f"Stage '{stage_name}' detailed CloudWatch metrics are disabled."}
                })
                print(f"  ⚠ Stage {stage_name}: Metrics Disabled (LOW)")

    except Exception as e:
        print(f"  ✗ Failed to scan stages: {str(e)}")

    # Check 2: Authorizers
    try:
        authorizers = apigw.get_authorizers(restApiId=api_id).get("items", [])
        if len(authorizers) == 0:
            violations.append({
                "type": "NoAuthorizers",
                "severity_hint": "MEDIUM",
                "data": {"details": "No authorizers configured. API endpoints may be publicly accessible without authentication."}
            })
            print("  ⚠ Authorizers: None configured (MEDIUM)")
    except Exception as e:
        pass

    # Check 3: Resource Policy
    try:
        policy = api.get("policy", "")
        if not policy:
            violations.append({
                "type": "NoResourcePolicy",
                "severity_hint": "LOW",
                "data": {"details": "No resource policy attached. Access control relies solely on authorizers or IAM."}
            })
            print("  ⚠ Resource Policy: Not attached (LOW)")
    except Exception as e:
        pass

    return violations, api_arn, api_name


def scan_http_api(apigwv2, api, aws_region):
    """Scan an HTTP or WebSocket API (v2) and return structured violations."""
    api_id      = api["ApiId"]
    api_name    = api.get("Name", api_id)
    api_type    = api.get("ProtocolType", "HTTP")
    api_arn     = f"arn:aws:apigateway:{aws_region}::/apis/{api_id}"
    violations  = []

    # Check 1: CORS Wildcard
    cors = api.get("CorsConfiguration", {})
    if cors:
        origins = cors.get("AllowOrigins", [])
        if "*" in origins:
            violations.append({
                "type": "CORS_Wildcard",
                "severity_hint": "HIGH",
                "data": {"details": "CORS configuration allows all origins (*) — vulnerable to cross-origin abuse."}
            })
            print("  ⚠ CORS: Wildcard origin enabled (HIGH)")

    # Check 2: Execute-API endpoint
    if not api.get("DisableExecuteApiEndpoint"):
        violations.append({
            "type": "DefaultEndpointEnabled",
            "severity_hint": "LOW",
            "data": {"details": "Default execute-api endpoint is enabled. This can be used to bypass WAF or custom domain controls."}
        })
        print("  ⚠ Endpoint: Default execute-api endpoint active (LOW)")

    # Check 3: Stages (Logging & Throttling)
    try:
        stages = apigwv2.get_stages(ApiId=api_id).get("Items", [])
        for stage in stages:
            stage_name = stage["StageName"]
            log_arn    = stage.get("AccessLogSettings", {}).get("DestinationArn", "")
            throttle   = stage.get("DefaultRouteSettings", {}).get("ThrottlingBurstLimit", None)

            if not log_arn:
                violations.append({
                    "type": f"AccessLoggingDisabled_{stage_name}",
                    "severity_hint": "HIGH",
                    "data": {"StageName": stage_name, "details": f"Stage '{stage_name}' has access logging disabled."}
                })
                print(f"  ⚠ Stage {stage_name}: Access logging disabled (HIGH)")

            if not throttle:
                violations.append({
                    "type": f"NoThrottling_{stage_name}",
                    "severity_hint": "MEDIUM",
                    "data": {"StageName": stage_name, "details": f"Stage '{stage_name}' has no throttling configured — vulnerable to abuse/DDoS."}
                })
                print(f"  ⚠ Stage {stage_name}: No throttling (MEDIUM)")
    except Exception as e:
        print(f"  ✗ Failed to scan HTTP stages: {str(e)}")

    return violations, api_arn, api_name, api_type


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    own_account    = context.invoked_function_arn.split(":")[4]
    aws_region     = context.invoked_function_arn.split(":")[3]
    target_account = event.get("accountId", "").strip()
    org_id = event.get("orgId", "").strip()
    scan_account   = target_account if target_account and target_account != own_account else own_account

    print(f"API Gateway Scanner — account: {scan_account} region: {aws_region}")
    print("="*60)

    try:
        apigw   = get_client("apigateway",   target_account, own_account, aws_region)
        apigwv2 = get_client("apigatewayv2", target_account, own_account, aws_region)

        # Delete old APIGW findings
        old = table.scan(
            FilterExpression=Attr("scanner").eq(SCANNER) & Attr("accountId").eq(scan_account)
        ).get("Items", [])
        for item in old:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"✓ Deleted {len(old)} old APIGW findings\n")

        total_findings_added = 0

        # ── REST APIs (v1) ────────────────────────────────────────────────
        rest_apis = apigw.get_rest_apis().get("items", [])
        print(f"Found {len(rest_apis)} REST APIs\n")

        for api in rest_apis:
            print(f"--- Scanning REST API: {api.get('name', api['id'])} ---")
            violations, api_arn, api_name = scan_rest_api(apigw, api, aws_region)
            resource_type = "API Gateway REST API"

            if not violations:
                finding_id = f"{scan_account}-{SCANNER}-{api['id']}-compliant"
                table.put_item(Item={
                    "findingId":           finding_id,
                    "accountId":           scan_account,
                    "resourceType":        resource_type,
                    "resourceId":          api_arn,
                    "severity":            "LOW",
                    "riskScore":           "1.0",
                    "title":               f"REST API {api_name} is compliant",
                    "status":              "OPEN",
                    "timestamp":           datetime.utcnow().isoformat() + "Z",
                    "scanner":             SCANNER,
                    "remediation":         "Continue monitoring API configuration.",
                    "cliCommands":         [],
                    "complianceFramework": ["AWS-APIGW-Security", "NIST-SI-2"],
                })
                print(f"  ✓ COMPLIANT - Saved 1 finding\n")
                total_findings_added += 1
            else:
                print(f"  ⚠ Found {len(violations)} violations - analyzing with AI...")
                for idx, violation in enumerate(violations, 1):
                    v_type = violation["type"]
                    v_data = violation["data"]
                    print(f"     [{idx}/{len(violations)}] Analyzing {v_type}...")
                    
                    ai_result = call_ai_for_violation(resource_type, api_arn, v_type, v_data, scan_account, org_id)
                    
                    finding_id = f"{scan_account}-{SCANNER}-{api['id']}-{v_type}"
                    table.put_item(Item={
                        "findingId":           finding_id,
                        "accountId":           scan_account,
                        "resourceType":        resource_type,
                        "resourceId":          api_arn,
                        "severity":            ai_result.get("severity", violation["severity_hint"]),
                        "riskScore":           str(ai_result.get("riskScore", "7.0")),
                        "title":               ai_result.get("title", f"APIGW {v_type}"),
                        "status":              "OPEN",
                        "timestamp":           datetime.utcnow().isoformat() + "Z",
                        "scanner":             SCANNER,
                        "remediation":         ai_result.get("remediation", "Review and fix this configuration."),
                        "cliCommands":         ai_result.get("cliCommands", []),
                        "complianceFramework": ai_result.get("complianceFramework", ["AWS-APIGW-Security"]),
                    })
                    total_findings_added += 1
                    print(f"        → Saved as {ai_result.get('severity', 'HIGH')}")
                print(f"  ✓ Saved {len(violations)} findings for this REST API\n")


        # ── HTTP / WebSocket APIs (v2) ─────────────────────────────────────
        http_apis = apigwv2.get_apis().get("Items", [])
        print(f"Found {len(http_apis)} HTTP/WebSocket APIs\n")

        for api in http_apis:
            print(f"--- Scanning {api.get('ProtocolType', 'HTTP')} API: {api.get('Name', api['ApiId'])} ---")
            violations, api_arn, api_name, api_type = scan_http_api(apigwv2, api, aws_region)
            resource_type = f"API Gateway {api_type} API"

            if not violations:
                finding_id = f"{scan_account}-{SCANNER}-{api['ApiId']}-compliant"
                table.put_item(Item={
                    "findingId":           finding_id,
                    "accountId":           scan_account,
                    "resourceType":        resource_type,
                    "resourceId":          api_arn,
                    "severity":            "LOW",
                    "riskScore":           "1.0",
                    "title":               f"{api_type} API {api_name} is compliant",
                    "status":              "OPEN",
                    "timestamp":           datetime.utcnow().isoformat() + "Z",
                    "scanner":             SCANNER,
                    "remediation":         "Continue monitoring API configuration.",
                    "cliCommands":         [],
                    "complianceFramework": ["AWS-APIGW-Security", "NIST-SI-2"],
                })
                print(f"  ✓ COMPLIANT - Saved 1 finding\n")
                total_findings_added += 1
            else:
                print(f"  ⚠ Found {len(violations)} violations - analyzing with AI...")
                for idx, violation in enumerate(violations, 1):
                    v_type = violation["type"]
                    v_data = violation["data"]
                    print(f"     [{idx}/{len(violations)}] Analyzing {v_type}...")
                    
                    ai_result = call_ai_for_violation(resource_type, api_arn, v_type, v_data, scan_account, org_id)
                    
                    finding_id = f"{scan_account}-{SCANNER}-{api['ApiId']}-{v_type}"
                    table.put_item(Item={
                        "findingId":           finding_id,
                        "accountId":           scan_account,
                        "resourceType":        resource_type,
                        "resourceId":          api_arn,
                        "severity":            ai_result.get("severity", violation["severity_hint"]),
                        "riskScore":           str(ai_result.get("riskScore", "7.0")),
                        "title":               ai_result.get("title", f"APIGW {v_type}"),
                        "status":              "OPEN",
                        "timestamp":           datetime.utcnow().isoformat() + "Z",
                        "scanner":             SCANNER,
                        "remediation":         ai_result.get("remediation", "Review and fix this configuration."),
                        "cliCommands":         ai_result.get("cliCommands", []),
                        "complianceFramework": ai_result.get("complianceFramework", ["AWS-APIGW-Security"]),
                    })
                    total_findings_added += 1
                    print(f"        → Saved as {ai_result.get('severity', 'HIGH')}")
                print(f"  ✓ Saved {len(violations)} findings for this HTTP/WS API\n")

        print("="*60)
        print(f"API GATEWAY SCAN COMPLETE")
        print(f"REST APIs scanned: {len(rest_apis)}")
        print(f"HTTP/WS APIs scanned: {len(http_apis)}")
        print(f"Total findings: {total_findings_added}")
        print("="*60)

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message":         "API Gateway scan complete",
                "accountId":       scan_account,
                "restApisScanned": len(rest_apis),
                "httpApisScanned": len(http_apis),
                "findingsAdded":   total_findings_added,
            }),
        }

    except Exception as e:
        print(f"API Gateway scan error: {e}")
        import traceback; traceback.print_exc()
        return {"statusCode": 500, "headers": CORS_HEADERS,
                "body": json.dumps({"message": "API Gateway scan failed", "error": str(e)})}