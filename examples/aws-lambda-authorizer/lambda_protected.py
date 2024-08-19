"""
Lambda function that acts as a sensitive endpoint behind authentication.
It always returns HTTP 200 with a JSON response.
"""
import json

def lambda_handler(event, context):
    print("event:", event)
    print("context:", context)

    headers = { k.lower():v for k,v in event['headers'].items() }
    origin = headers.get("origin", "*")

    response = {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "*"
        },
    }

    http_method = event['requestContext']['http']['method']
    if http_method.lower() != 'options':
        response['body'] = json.dumps({"message": "This endpoint is protected"})

    print("response", response)

    return response
