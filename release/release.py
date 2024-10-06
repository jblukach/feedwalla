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

    output = {}
    output['name'] = 'Feedwalla'
    output['description'] = 'Internet Scanners Targeting North Dakota'
    output['created'] = str(datetime.datetime.now())
    output['epoch'] = int(datetime.datetime.now().timestamp() * 1000)
    output['source'] = 'https://github.com/jblukach/feedwalla/releases'

### IP ###

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

    output['count'] = len(responsedata)
    output['addresses'] = []

    for item in responsedata:
        temp = {}
        temp['ip'] = item['ip']
        output['addresses'].append(temp)

### OUTPUT ###

    f = open('/tmp/feedwalla.json','w')
    f.write(json.dumps(output, indent = 4))
    f.close()

    sha256 = hasher('/tmp/feedwalla.json')

    ssm = boto3.client('ssm')

    token = ssm.get_parameter(
        Name = os.environ['GITHUB_API'], 
        WithDecryption = True
    )

    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer '+token['Parameter']['Value'],
        'X-GitHub-Api-Version': '2022-11-28'
    }

    year = datetime.datetime.now().strftime('%Y')
    month = datetime.datetime.now().strftime('%m')
    day = datetime.datetime.now().strftime('%d')
    epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    data = '''{
        "tag_name":"v'''+str(year)+'''.'''+str(month)+str(day)+'''.'''+str(epoch)+'''",
        "target_commitish":"main",
        "name":"feedwalla",
        "body":"The sha256 verification hash for the feedwalla.json file is: '''+sha256+'''",
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
        'Authorization': 'Bearer '+token['Parameter']['Value'],
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json'
    }

    params = {
        "name":"feedwalla.json"
    }

    url = 'https://uploads.github.com/repos/jblukach/feedwalla/releases/'+str(response.json()['id'])+'/assets'

    with open('/tmp/feedwalla.json', 'rb') as f:
        data = f.read()
    f.close()

    response = requests.post(url, params=params, headers=headers, data=data)

    print(response.json())

    return {
        'statusCode': 200,
        'body': json.dumps('Release!')
    }