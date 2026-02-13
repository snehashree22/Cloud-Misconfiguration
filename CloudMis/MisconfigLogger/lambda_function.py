import json
import boto3
import os

s3 = boto3.client('s3')
bucket_name = os.environ.get('APP_BUCKET')

def lambda_handler(event, context):
    try:
        file_key = "reports/test.json"
        s3.put_object(
            Bucket=bucket_name,
            Key=file_key,
            Body=json.dumps({"status": "ok", "msg": "Lambda executed successfully"})
        )

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "MisconfigLogger Lambda executed",
                "s3_location": f"s3://{bucket_name}/{file_key}"
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
