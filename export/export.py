import boto3
import datetime
import json
import os
import requests

def handler(event, context):
    
    ssm = boto3.client('ssm')

    api = ssm.get_parameter(
        Name = os.environ['FIREWALLA_API'], 
        WithDecryption = True
    )

    web = ssm.get_parameter(
        Name = os.environ['FIREWALLA_WEB']
    )

    addrs = []
    epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 600

    headers = {
        'Authorization': 'Token '+api['Parameter']['Value'],
        'Content-Type': 'application/json'
    }

    url = web['Parameter']['Value']+'/v2/flows'

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






    return {
        'statusCode': 200,
        'body': json.dumps('Export!')
    }