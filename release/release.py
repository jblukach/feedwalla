import boto3
import datetime
import hashlib
import json
import os
import requests
from boto3.dynamodb.conditions import Key

def hasher(filename):
    
    BLOCKSIZE = 65536
    sha256_hasher = hashlib.sha256()

    with open(filename,'rb') as h:
        buf = h.read(BLOCKSIZE)
        while len(buf) > 0:
            sha256_hasher.update(buf)
            buf = h.read(BLOCKSIZE)
    h.close()

    sha256 = sha256_hasher.hexdigest().upper()

    return sha256

def handler(event, context):

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])

### INTERNET SCANNERS ###

    response = table.query(
        KeyConditionExpression=Key('pk').eq('IP#')
    )
    responsedata = response['Items']
    while 'LastEvaluatedKey' in response:
        response = table.query(
            KeyConditionExpression=Key('pk').eq('IP#'),
            ExclusiveStartKey=response['LastEvaluatedKey']
        )
        responsedata.extend(response['Items'])

### OSINT THREAT FEED ###

    year = datetime.datetime.now().strftime('%Y')
    month = datetime.datetime.now().strftime('%m')
    day = datetime.datetime.now().strftime('%d')
    now = datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')

    f = open('/tmp/feedwalla.txt','w')

    f.write('# \n')
    f.write('# feedwalla: https://github.com/jblukach/feedwalla/releases\n')
    f.write('# \n')
    f.write('# released: '+str(now)+'\n')
    f.write('# total: '+str(len(responsedata))+'\n')
    f.write('# \n')

    for item in responsedata:
        f.write(item['ip']+'\n')
    
    f.close()

    sha256 = hasher('/tmp/feedwalla.txt')

    secret = boto3.client('secretsmanager')

    getsecret = secret.get_secret_value(
        SecretId = os.environ['SECRET_MGR_ARN']
    )

    login = json.loads(getsecret['SecretString'])

    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer '+login['github'],
        'X-GitHub-Api-Version': '2022-11-28'
    }

    data = '''{
        "tag_name":"v'''+str(year)+'''.'''+str(month)+'''.'''+str(day)+'''",
        "target_commitish":"main",
        "name":"feedwalla",
        "body":"The sha256 verification hash for the feedwalla.txt file is: '''+sha256+'''",
        "draft":false,
        "prerelease":false,
        "generate_release_notes":false
    }'''

    response = requests.post(
        'https://api.github.com/repos/jblukach/feedwalla/releases',
        headers=headers,
        data=data
    )

    print(response.json())

    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer '+login['github'],
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'text/plain'
    }

    params = {
        "name":"feedwalla.txt"
    }

    url = 'https://uploads.github.com/repos/jblukach/feedwalla/releases/'+str(response.json()['id'])+'/assets'

    with open('/tmp/feedwalla.txt', 'rb') as f:
        data = f.read()
    f.close()

    response = requests.post(url, params=params, headers=headers, data=data)

    print(response.json())

    return {
        'statusCode': 200,
        'body': json.dumps('Released!')
    }