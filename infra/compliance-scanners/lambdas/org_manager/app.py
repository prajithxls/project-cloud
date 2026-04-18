# lambdas/org_manager/app.py
import json, boto3, os, uuid
from datetime import datetime, timezone
from decimal import Decimal

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
}

dynamodb   = boto3.resource("dynamodb")
orgs_table = dynamodb.Table(os.environ["ORGANISATIONS_TABLE"])
user_table = dynamodb.Table(os.environ["USER_ORGS_TABLE"])
s3_client  = boto3.client("s3")

def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    method = event.get("httpMethod")
    path   = event.get("path", "")

    try:
        # POST /orgs — create new organisation
        if method == "POST" and path.endswith("/orgs"):
            body     = json.loads(event.get("body") or "{}")
            org_name = body.get("orgName", "").strip()
            user_id  = body.get("userId", "").strip()

            if not org_name or not user_id:
                return err("orgName and userId are required")

            org_id = f"org_{uuid.uuid4().hex[:12]}"
            now    = datetime.now(timezone.utc).isoformat()

            orgs_table.put_item(Item={
                "orgId":              org_id,
                "orgName":            org_name,
                "createdAt":          now,
                "memberEmails":       [],
                "documentCount":      0,
                "pineconeNamespace":  org_id,
                "createdBy":          user_id,
            })
            # Map creator as admin in UserOrgs
            user_table.put_item(Item={
                "userId": user_id,
                "orgId":  org_id,
                "role":   "admin",
                "joinedAt": now,
            })
            return ok({"orgId": org_id, "orgName": org_name})

        # GET /orgs/me?userId=xxx — get user's org
        elif method == "GET" and "me" in path:
            user_id = (event.get("queryStringParameters") or {}).get("userId", "")
            if not user_id:
                return err("userId required")
            resp = user_table.get_item(Key={"userId": user_id})
            item = resp.get("Item")
            if not item:
                return ok({"orgId": None, "message": "User not in any org"})
            
            org_resp = orgs_table.get_item(Key={"orgId": item["orgId"]})
            org_data = org_resp.get("Item", {})
            
            # ── FETCH EXACT DOCUMENTS FROM S3 ──
            bucket_name = os.environ.get("DOCUMENTS_BUCKET", "csc-ams-org-documents")
            docs = []
            try:
                s3_res = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=f"{item['orgId']}/")
                for obj in s3_res.get("Contents", []):
                    if obj["Key"].endswith("/"): continue
                    docs.append({
                        "name": obj["Key"].split("/")[-1],
                        "uploadedAt": obj["LastModified"].isoformat()
                    })
            except Exception as e:
                print(f"S3 fetch error: {e}")
                
            org_data["documents"] = docs
            org_data["documentCount"] = len(docs)
            
            return ok(org_data)

        # POST /orgs/{orgId}/members — invite user to org
        elif method == "POST" and "/members" in path:
            path_parts = path.split("/")
            # Depending on path structure, orgId is usually at index 2 for /orgs/org_123/members
            join_org_id = path_parts[2] if len(path_parts) > 2 else None
            
            body = json.loads(event.get("body") or "{}")
            join_user_id = body.get("userId")
            
            if not join_org_id or not join_user_id:
                return err("orgId and userId required")
                
            # 1. Verify the Org actually exists
            existing_org = orgs_table.get_item(Key={"orgId": join_org_id}).get("Item")
            if not existing_org:
                return err("Organisation not found", 404)
                
            # 2. Add the user to the UserOrgs mapping table
            user_table.put_item(Item={
                "userId": join_user_id,
                "orgId": join_org_id,
                "role": "MEMBER",
                "joinedAt": datetime.now(timezone.utc).isoformat()
            })
            
            # Return the org data so the frontend can immediately display it
            return ok(existing_org)

        # DELETE /orgs/leave?userId=xxx — leave org
        elif method == "DELETE" and "leave" in path:
            user_id = (event.get("queryStringParameters") or {}).get("userId", "")
            if not user_id:
                return err("userId required")
                
            user_table.delete_item(Key={"userId": user_id})
            return ok({"message": "Successfully left the organisation"})

        return err("Route not found", 404)

    except Exception as e:
        import traceback; traceback.print_exc()
        return err(str(e), 500)
def ok(data): 
    return {
        "statusCode": 200, 
        "headers": CORS_HEADERS, 
        "body": json.dumps(data, default=lambda x: float(x) if isinstance(x, Decimal) else str(x))
    }
def err(msg, code=400): return {"statusCode": code, "headers": CORS_HEADERS, "body": json.dumps({"message": msg})}