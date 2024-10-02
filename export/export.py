import boto3
import json
import os

def handler(event, context):
    
    ssm = boto3.client('ssm')

    api = ssm.get_parameter(
        Name = os.environ['FIREWALLA_API'], 
        WithDecryption = True
    )
    
    print(api['Parameter']['Value'])

    return {
        'statusCode': 200,
        'body': json.dumps('Export!')
    }