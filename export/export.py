import boto3
import datetime
import json
import os
import requests

def handler(event, context):
    
    secret = boto3.client('secretsmanager')

    getsecret = secret.get_secret_value(
        SecretId = os.environ['SECRET_MGR_ARN']
    )

    login = json.loads(getsecret['SecretString'])

    addrs = []
    epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 600

    headers = {
        'Authorization': 'Token '+login['token'],
        'Content-Type': 'application/json'
    }

    publicips = []

    url = login['url']+'/v2/boxes'

    r = requests.get(url, headers=headers)

    for i in r.json():
        publicips.append(i['publicIP'])

    url = login['url']+'/v2/flows'

    params = {
        'cursor': None,
        'limit': 500,
        'query': 'ts:>'+str(epoch)+' Status:Blocked Direction:Inbound -Box:"Road Warrior"'
    }

    r = requests.get(url, headers=headers, params=params)
    j = r.json()

    for i in j['results']:
        addrs.append(i['source']['ip'])

    try:

        params['cursor'] = j['next_cursor']

        while j['next_cursor'] != None:

            r = requests.get(url, headers=headers, params=params)
            j = r.json()

            for i in j['results']:
                addrs.append(i['source']['ip'])

            try:
                params['cursor'] = j['next_cursor']
            except:
                break

    except:
        pass

    addrs = list(set(addrs))
    print('Blocked IPs:', str(len(addrs)))

    ttl = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 86400

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])

    for addr in addrs:

        if addr not in publicips:

            table.put_item(
                Item = {
                    'pk': 'IP#',
                    'sk': 'IP#'+str(addr),
                    'ip': str(addr),
                    'ttl': ttl
                }
            )

    return {
        'statusCode': 200,
        'body': json.dumps('Exported!')
    }