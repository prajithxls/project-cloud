import boto3
import os
import json
import uuid
from datetime import datetime

# Connect to DynamoDB
dynamodb = boto3.resource('dynamodb')
table_name = os.environ.get('FINDINGS_TABLE', 'Findings')
table = dynamodb.Table(table_name)

def hello(event, context):
    # Create a test item
    item = {
        'findingId': str(uuid.uuid4()),
        'resourceType': 'TEST',
        'title': 'Test Finding',
        'severity': 'LOW',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'status': 'OPEN'
    }
    
    # Insert into DynamoDB
    table.put_item(Item=item)
    
    # Return response
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Test finding added', 'item': item})
    }
