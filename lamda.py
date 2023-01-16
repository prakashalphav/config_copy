import os, sys, json, requests
import boto3
from botocore.exceptions import ClientError

def get_slack_secret(secret_name, region_name):
    session = boto3.session.Session()
    secretsmanager_client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = secretsmanager_client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        raise e

    slack_secret = json.loads(get_secret_value_response['SecretString'])
    return slack_secret

def post_unformatted_message(url, status, message, common_labels=None, common_annotations=None):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = {
        "text": f"Status: {status}\nThe Alert JSON object failed to decode properly."
    }
    response = requests.post(url, headers=headers, data=json.dumps(payload).encode('utf-8'))
    return response

def post_formatted_message(url, message, common_labels=None, common_annotations=None):
    if message['status'] == "firing":
        emoji = ":rotating_light:"
        color = "#ff0000"
    else:
         emoji = ":white_check_mark:"
         color = "#00ff00"
    alert_status = f"[{message['status'].upper()}]"
    print(alert_status)
    alert_name = message['labels']['alertname']
    print(alert_name)
    alert_time = message['startsAt']
    print(alert_time)
    alert_summary = message.get('annotations', {}).get('summary', 'no_summary_annotation_found')
    print(alert_summary)
    alert_description = message.get('annotations', {}).get('description', 'no_description_annotation_found')
    print(alert_description)
    alert_labels = message.get('labels', {})
    print(alert_labels)
    alert_environment = alert_labels.get('env', alert_labels.get('environment', 'no_environment_label_found'))
    print(alert_environment)

    labels = "\n".join([f"{key}: `{value}`" for key, value in alert_labels.items()])
    print(labels)

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = {
        "message" : f"{alert_status} {alert_summary}",
  "tags":{
      "alertname":f"{alert_name}",
      "environment":f"{alert_environment}",
  "alert_description":f"{alert_description}"
    }, "summary":f"{alert_summary}"
    }
    json_payload = json.dumps(payload)
    print(json_payload)

    response = requests.post(url, headers=headers, data=json_payload)
    return response

def lambda_handler(event, context):
    secret_name = os.getenv('SQUADCAST_WEBHOOK_SECRET')
    region_name = os.getenv('REGION')
    slack_secret = get_slack_secret(secret_name, region_name)
    print(event)

    url = slack_secret['webhook_url']

    try:
        json_data = json.loads(event['Records'][0]['Sns']['Message'])
    except json.decoder.JSONDecodeError as e:
        print("Decoding with strict disabled...")
        try:
            json_data = json.loads(event['Records'][0]['Sns']['Message'], strict=False)
            print(json_data)
        except:
            print("Decode Failed with strict=false. Unable to parse SNS Message")
            json_data = event['Records'][0]['Sns']['Message']
            response = post_unformatted_message(url, event['Records'][0]['Sns']['Subject'], json_data)
            print(response.text)
            sys.exit(-1)

    common_labels = json_data.get('commonLabels', None)
    common_annotations = json_data.get('commonAnnotations', None)

    for alert in json_data['alerts']:
        response = post_formatted_message(url, alert, common_labels, common_annotations)
        print(response.text)
