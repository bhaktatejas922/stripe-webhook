"""Webhook implementation for Stripe THIS IS FOR TESTING. USE PYTHON3.8"""

import os
import json
from datetime import datetime, timedelta
import base64
import hmac
import hashlib
from cgi import parse_header
import boto3
import botocore
import botocore.session
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig
import psycopg2
import subprocess
import secrets


engine = psycopg2.connect(
        database="postgres",
        user="tbhakta",
        password="Budget007!",
        host="database-ca.cnc4fmgjuhvz.us-east-2.rds.amazonaws.com",
        port='5432'
    )
# set $HOME to this directory
os.environ['HOME'] = os.getcwd()

client = botocore.session.get_session().create_client('secretsmanager')
cache_config = SecretCacheConfig()
cache = SecretCache(config=cache_config, client=client)

stripe_webhook_secret_arn = os.environ.get('STRIPE_WEBHOOK_SECRET_ARN')
event_bus_name = os.environ.get('EVENT_BUS_NAME', 'default')

event_bridge_client = boto3.client('events')

def _add_header(request, **kwargs):
    userAgentHeader = request.headers['User-Agent'] + ' fURLWebhook/1.0 (Stripe)'
    del request.headers['User-Agent']
    request.headers['User-Agent'] = userAgentHeader

event_system = event_bridge_client.meta.events
event_system.register_first('before-sign.events.PutEvents', _add_header)

class PutEventError(Exception):
    """Raised when Put Events Failed"""
    pass

def lambda_handler(event, _context):
    """Webhook function"""

    headers = event.get('headers')

    # Input validation
    try:
        json_payload = get_json_payload(event=event)
    except ValueError as err:
        print_error(f'400 Bad Request - {err}', headers)
        return {'statusCode': 400, 'body': str(err)}
    except BaseException as err:  # Unexpected Error
        print_error('500 Internal Server Error\n' +
                    f'Unexpected error: {err}, {type(err)}', headers)
        return {'statusCode': 500, 'body': 'Internal Server Error'}

    try:

        timestamp, signatures = parse_signature(
            signature_header=headers.get('stripe-signature'))

        if not timestamp or not timestamp_is_valid(timestamp):
            print_error('400 Bad Request - Invalid timestamp', headers)
            return {
                'statusCode': 400,
                'body': 'Invalid timestamp'
            }

        if not contains_valid_signature(
                payload=json_payload,
                timestamp=timestamp,
                signatures=signatures):
            print_error('401 Unauthorized - Invalid Signature', headers)
            return {'statusCode': 401, 'body': 'Invalid Signature'}

        json_format = json.loads(json_payload)
        detail_type = json_format.get('type', 'stripe-webhook-lambda')
        print(f'Webhook received: {json_format}')
        if json_format['data']['object']['object'] == 'checkout.session': # we dont need to check for success because we only have webhook on successs
            add_user_to_db(json_format)

        elif json_format['data']['object']['object'] == 'payment_intent': # we dont need to check for success because we only have webhook on successs
            add_paid_user_to_db(json_format)
        response = forward_event(json_payload, detail_type)

        if response['FailedEntryCount'] > 0:
            print_error('500 FailedEntry Error - The event was not successfully forwarded to Amazon EventBridge\n' +
                        str(response['Entries'][0]), headers)
            return {'statusCode': 500, 'body': 'FailedEntry Error - The entry could not be succesfully forwarded to Amazon EventBridge'}

        return {'statusCode': 202, 'body': 'Message forwarded to Amazon EventBridge'}

    except PutEventError as err:
        print_error(f'500 Put Events Error - {err}', headers)
        return {'statusCode': 500, 'body': 'Internal Server Error - The request was rejected by Amazon EventBridge API'}

    except BaseException as err:  # Unexpected Error
        print_error('500 Client Error\n' +
                    f'Unexpected error: {err}, {type(err)}', headers)
        return {'statusCode': 500, 'body': 'Internal Server Error'}

def add_user_to_db(json_format):
    """Add unpaid user to checkout_users db"""
    cursor = engine.cursor()
    email = json_format['data']['object']['customer_details']['email']
    api_key = get_api_key(email)
    query = f"INSERT INTO checkout_users (email, customer_id, plan, api_key) VALUES ('{email}', '{json_format['data']['object']['customer']}', '{json_format['data']['object']['payment_link']}', '{api_key}')"
    cursor.execute(query)
    engine.commit()
    cursor.close()

def add_paid_user_to_db(json_format):
    """Add paid user to db every time when payment is successful. need to parse event and get email, customer_id, plan, risk_score, charge_id"""
    charge_id = json_format['data']['object']['charges']['data'][0]['id']
    amount = json_format['data']['object']['charges']['data'][0]['amount']
    email = json_format['data']['object']['charges']['data'][0]['billing_details']['email']
    customer_id = json_format['data']['object']['charges']['data'][0]['customer']
    risk_score = json_format['data']['object']['charges']['data'][0]['outcome']['risk_score'] if 'risk_score' in json_format['data']['object']['charges']['data'][0]['outcome'] else -1
    plans = read_plans('single_address_api') # will look like {'hobby': 3000, 'business': 5000, 'enterprise': 10000}
    for plan, price in plans.items():
        if amount <= price*1.3: # account for taxes
            user_plan = plan
            break
    api_key = get_api_key(email)
    cursor = engine.cursor()
    query = f"INSERT INTO paid_users (email, customer_id, plan, risk_score, charge_id, api_key, paid) VALUES ('{email}', '{customer_id}', '{user_plan}', '{risk_score}', '{charge_id}', '{api_key}', 'true')"
    cursor.execute(query)
    engine.commit()
    cursor.close()

        
def get_api_key(email):
    """Get most recent api key from db for a user. Check the created_at column for the most recent key. Note that its possible that this email does not exist yet in paid_users.
    If it does not exist, then we need to create a new user in the db and get their original key from checkout flow 
    """
    cursor = engine.cursor()
    query = f"SELECT api_key FROM paid_users WHERE email='{email}' ORDER BY created_at DESC LIMIT 1"
    cursor.execute(query)
    paid_api_key = cursor.fetchone()
    if paid_api_key is None: # if user does not have a most recent paid api_key, then we need to get the key from their trial in checkout_users
        # attempt to fetch user from checkout_users table to see if they got a key from a trial
        query = f"SELECT api_key FROM checkout_users WHERE email='{email}' ORDER BY created_at DESC LIMIT 1"
        cursor.execute(query)
        trial_api_key = cursor.fetchone()
        if trial_api_key is None: 
            # if user does not have a most recent api_key, then we need to create a new user and generate new api key and 
            # email the user their api key via SES
            api_key = generate_api_key(email)
            email_api_key(email, api_key)
        else:
            # return the found trial key. might want to throw error here if we want to force users to pay after trial TODO
            api_key = trial_api_key[0]
    else:
        # return the last found paid key
        api_key = paid_api_key[0]
    return api_key

def generate_api_key(email):
    """
    Generate a new api key for a user. This will be used to authenticate the user when they make a request to the api. We will store it in the db and email it to the user
    """
    api_key = secrets.token_urlsafe(16)
    cursor = engine.cursor()
    # first check that this api key does not already exist in the db for any user
    query = f"SELECT api_key FROM paid_users WHERE api_key='{api_key}'"
    cursor.execute(query)
    if cursor.fetchone() is not None:
        generate_api_key(email)  # try again
    else:
        return api_key

def email_api_key(email, api_key):
    """Email the user their api key via SES by sending them the one time link"""
    ses_client = boto3.client('ses')
    api_key_link = gen_one_time_link(api_key)
    response = ses_client.send_email(
        Source='support@abut.ai',
        Destination={
            'ToAddresses': [
                email,
            ],
        },
        Message={
            'Body': {
                'Html': {
                    'Charset': 'UTF-8',
                    'Data': f"""Thanks for subscribing! <br /> <br /> You can now use your API key to access the single address api. Please use the following link to access your api key: {api_key_link} <br /> 
                    Note that this link will only work once, so save this key somewhere safe! <br /> <br /> 
                    You can view the documentation and test single address api with your new api key here: <br />
                    https://api.abut.ai/docs <br /> <br />
                    To view your billing information. please visit https://billing.stripe.com/p/login/4gw29n6l45sK8sU7ss . If you need to access your api key again or have any questions, please email us at support@abut.ai  <br /> <br />
                    Thanks, <br />
                    The Abut.ai Team
                    """
                },
                'Text': {
                    'Charset': 'UTF-8',
                    'Data': f"""Thanks for subscribing! <br /> <br /> You can now use your API key to access the single address api. Please use the following link to access your api key: {api_key_link} <br /> 
                    Note that this link will only work once, so save this key somewhere safe! <br /> <br /> 
                    You can view the documentation and test single address api with your new api key here: <br />
                    https://api.abut.ai/docs <br /> <br />
                    To view your billing information. please visit https://billing.stripe.com/p/login/4gw29n6l45sK8sU7ss . If you need to access your api key again or have any questions, please email us at support@abut.ai  <br /> <br />
                    Thanks, <br />
                    The Abut.ai Team
                    """
                },
            },
            'Subject': {
                'Charset': 'UTF-8',
                'Data': 'Your API Key from Abut for Single Address API',
            },
        },
        ReplyToAddresses=[
            'support@abut.ai',
        ]
    )
    print("Email sent! Message ID:", response)



def gen_one_time_link(api_key):
    # call the ots file and pass the api key. read the stdout line by line. 
    # this is the command that is being called
    # echo api_key | ./ots new
    ps = subprocess.Popen(('echo', api_key), stdout=subprocess.PIPE)
    output = subprocess.check_output(('./ots', 'new'), stdin=ps.stdout)
    ps.wait()
    # separate the output into lines
    output = output.splitlines()
    # read the bytes from the output and decode them into a string
    return output[3].decode("utf-8")

def read_plans(product):
    """Read plans from db"""
    cursor = engine.cursor()
    cursor.execute("SELECT * FROM plans")
    plans = cursor.fetchall()
    plans_dict ={}
    for plan in plans:
        if plan[0] == product:
            plans_dict[plan[2]] = plan[1]
    # sort plans by price (lowest to highest). price is in plan[1]
    plans_dict = {k: v for k, v in sorted(plans_dict.items(), key=lambda item: item[1])}
    return plans_dict

def get_json_payload(event):
    """Get JSON string from payload"""
    content_type = get_content_type(event.get('headers', {}))
    if content_type != 'application/json':
        raise ValueError('Unsupported content-type')

    payload = normalize_payload(
        raw_payload=event.get('body'),
        is_base64_encoded=event['isBase64Encoded'])

    try:
        json.loads(payload)

    except ValueError as err:
        raise ValueError('Invalid JSON payload') from err

    return payload


def normalize_payload(raw_payload, is_base64_encoded):
    """Decode payload if needed"""
    if raw_payload is None:
        raise ValueError('Missing event body')
    if is_base64_encoded:
        return base64.b64decode(raw_payload).decode('utf-8')
    return raw_payload


def contains_valid_signature(payload, timestamp, signatures):
    """Check for the payload signature
       Stripe documentation: https://stripe.com/docs/webhooks/signatures
    """
    secret = cache.get_secret_string(stripe_webhook_secret_arn)
    payload_bytes = get_payload_bytes(
        timestamp=timestamp,
        payload=payload
    )
    computed_signature = compute_signature(
        payload_bytes=payload_bytes, secret=secret)
    return any(
        hmac.compare_digest(event_signature, computed_signature)
        for event_signature in signatures
    )


def get_payload_bytes(timestamp, payload):
    """Get payload bytes to feed hash function"""
    return (timestamp + "." + payload).encode()


def compute_signature(payload_bytes, secret):
    """Compute HMAC-SHA256"""
    return hmac.new(key=secret.encode(), msg=payload_bytes, digestmod=hashlib.sha256).hexdigest()


def parse_signature(signature_header):
    """
        Parse signature from hearders based on:
        https://stripe.com/docs/webhooks/signatures#prepare-payload
    """
    if not signature_header:
        return None, None

    header_elements = signature_header.split(',')
    timestamp, signatures = None, []

    for element in header_elements:
        [k, v] = element.split('=')
        if k == 't':
            timestamp = v
        # Stripe will send all valid signatures as a v1=<signature>
        if k == 'v1':
            signatures.append(v)

    return timestamp, signatures


def timestamp_is_valid(timestamp):
    """Check whether incoming timestamp is not too old (<5min old)"""
    current_time = datetime.today()
    stripe_timestamp = datetime.fromtimestamp(int(timestamp))

    diff = current_time - stripe_timestamp

    # Time diff is less than 5 minutes
    return diff < timedelta(minutes=5)


def forward_event(payload, detail_type):
    """Forward event to EventBridge"""
    try:
        return event_bridge_client.put_events(
            Entries=[
                {
                    'Source': 'stripe.com',
                    'DetailType': detail_type,
                    'Detail': payload,
                    'EventBusName': event_bus_name
                },
            ]
        )
    except BaseException as err:
        raise PutEventError('Put Events Failed')

def get_content_type(headers):
    """Helper function to parse content-type from the header"""
    raw_content_type = headers.get('content-type')

    if raw_content_type is None:
        return None
    content_type, _ = parse_header(raw_content_type)
    return content_type


def print_error(message, headers):
    """Helper function to print errors"""
    print(f'ERROR: {message}\nHeaders: {str(headers)}')
