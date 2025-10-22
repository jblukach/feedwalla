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

    logs = []
    epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 360 # last six minutes

    headers = {
        'Authorization': 'Token '+api['Parameter']['Value'],
        'Content-Type': 'application/json'
    }

    publicips = []

    url = web['Parameter']['Value']+'/v2/boxes'

    r = requests.get(url, headers=headers)

    for i in r.json():
        print(i)
        print('------')
        publicips.append(i['publicIP'])

    url = web['Parameter']['Value']+'/v2/flows'

    params = {
        'cursor': None,
        'limit': 1, #500,
        'query': 'ts:>'+str(epoch)+' Status:Blocked Direction:Inbound -Box:"Road Warrior"'
    }

    r = requests.get(url, headers=headers, params=params)
    j = r.json()

    for i in j['results']:
        print(i)
        print(i['ts'])
        # convert ts epoch to 2002-01-24 23:10:05 -00:00 format
        print(datetime.datetime.fromtimestamp(i['ts'], datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S %z'))

        print(i['count'])
        print(i['protocol'])
        
        print(i['source']['ip'])
        print(i['source']['portInfo']['port'])
        print(i['destination']['ip'])
        print(i['destination']['portInfo']['port'])



#time
#flags
#dip
#sip
#version
#proto
#sport
#dport
#count


    #try:

    #    params['cursor'] = j['next_cursor']

    #    while j['next_cursor'] != None:

    #        r = requests.get(url, headers=headers, params=params)
    #        j = r.json()

    #        for i in j['results']:
    #            addrs.append(i['source']['ip'])

    #        try:
    #            params['cursor'] = j['next_cursor']
    #        except:
    #            break

    #except:
    #    pass




    return {
        'statusCode': 200,
        'body': json.dumps('Export!')
    }