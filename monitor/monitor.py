import boto3
import json
import os
import requests

def handler(event, context):
    
    secret = boto3.client('secretsmanager')

    getsecret = secret.get_secret_value(
        SecretId = os.environ['SECRET_MGR_ARN']
    )

    login = json.loads(getsecret['SecretString'])

    headers = {
        'Authorization': 'Token '+login['token'],
        'Content-Type': 'application/json'
    }

    publicips = []

    url = login['url']+'/v2/boxes'

    response = requests.get(url, headers=headers)

    sns = boto3.client('sns')

    for i in response.json():
        r = requests.get('https://api.lukach.io/osint/ip?'+i['publicIP'])
        if r.status_code == 200:
            result = r.json()
            if result['status'] == 'suspect':
                sns.publish(
                    TopicArn = os.environ['SNS_TOPIC_ARN'],
                    Message = json.dumps(result, indent=4),
                    Subject = 'Suspect IP Alert'
                )

    return {
        'statusCode': 200,
        'body': json.dumps('Exported!')
    }