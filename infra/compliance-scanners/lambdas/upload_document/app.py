import json
import os
import boto3
import uuid
from botocore.config import Config

# Force Regional S3v4 Endpoint
s3_client = boto3.client(
    's3', 
    region_name='ap-south-1', 
    endpoint_url='https://s3.ap-south-1.amazonaws.com',
    config=Config(signature_version='s3v4')
)

# Mandatory CORS Headers for API Gateway
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "OPTIONS,POST"
}

def lambda_handler(event, context):
    try:
        # 1. Parse the incoming request from React
        body = json.loads(event.get('body', '{}'))
        org_id = body.get('orgId')
        user_id = body.get('userId')
        filename = body.get('filename', 'document.pdf')

        if not org_id or not user_id:
            return {
                "statusCode": 400,
                "headers": CORS_HEADERS,
                "body": json.dumps({"error": "Missing orgId or userId in request"})
            }

        # 2. Create a secure, unique path for the PDF
        s3_key = f"{org_id}/{user_id}/{uuid.uuid4().hex[:8]}_{filename}"

        # 3. Generate the strictly signed URL
        upload_url = s3_client.generate_presigned_url(
            ClientMethod='put_object',
            Params={
                'Bucket': os.environ['DOCUMENTS_BUCKET'],
                'Key': s3_key,
                'ContentType': 'application/pdf'
            },
            ExpiresIn=300
        )

        # 4. Return the URL successfully with CORS headers attached
        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "uploadUrl": upload_url,
                "s3Key": s3_key
            })
        }
        
    except Exception as e:
        print(f"CRITICAL ERROR: {str(e)}")
        # If it crashes, return a 500 BUT KEEP THE CORS HEADERS so the frontend can read the error
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)})
        }