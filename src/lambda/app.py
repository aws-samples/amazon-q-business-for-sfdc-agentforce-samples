import os
import json
import time
import boto3
import botocore
import logging
import ast
import uuid
import serverless_wsgi
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel
from boto3.dynamodb.conditions import Key
from flask import Flask, request, jsonify, abort


app = Flask(__name__)

@app.errorhandler(500)
def invalid_payload(e):    
    response = jsonify(message=e.description, code=e.code, name=e.name)
    return response, 500

@app.errorhandler(405)
def method_not_allowed(e):
    response = jsonify(code=e.code, name=e.name)
    return response, 405

@app.errorhandler(404)
def resource_not_found(e):
    response = jsonify(code=e.code, name=e.name)
    return response, 404

@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Methods'] = '*'
    return response

# Setup logging
log_level = os.environ.get('LOG_LEVEL', 'DEBUG')
logger = logging.getLogger(__name__)
logger.setLevel(log_level)

qbiz_app_id = os.environ.get('QBIZ_APP_ID')
identity_pool_id = os.environ.get('COGNITO_IDENTITY_POOL_ID')
assume_role_arn = os.environ.get('ASSUME_ROLE_ARN')
creds_table = os.environ.get('CREDS_TABLE')
qbiz_data_source_id = os.environ.get('QBIZ_DATA_SOURCE_ID')
cognito_identity_provider_name = os.environ.get('COGNITO_IDENTITY_PROVIDER_NAME')
if qbiz_data_source_id:
    qbiz_data_source_id = ast.literal_eval(qbiz_data_source_id)

# Generate a random UUID (version 4)
qbiz_uuid = str(uuid.uuid4())

# Initialize AWS clients
cognito_client = boto3.client('cognito-identity')
sts_client = boto3.client('sts')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(creds_table)

class ChatPayload(BaseModel):
    user_id: str
    conversation_id: Optional[str] = None
    previous_message_id: Optional[str] = None
    data_source_id: Optional[List[str]] = qbiz_data_source_id
    # data_source_id: Optional[List[str]] = ['8f68f5f6-0e95-4b88-b684-ef34f71c10d7']   #['84c7bbfb-cdb9-4e6e-84fc-47bcd0870705']
    user_message: str

class FeedbackPayload(BaseModel):
    user_id: str
    conversation_id: str
    message_id: str
    liked: bool


def load_alignment():
    alignment_path = os.path.join(os.path.dirname(__file__), 'alignment.txt')
    with open(alignment_path, 'r') as file:
        text = file.read()
        logger.debug(f"Alignment text = \n {text}")
        return text

@app.route("/chat", methods=['POST'])
def chat():
    logger.debug("Received chat request")
    try:
        payload = ChatPayload(**request.json)
    except ValueError as e:
        logger.error(f"Invalid payload: {str(e)}")
        abort(400, description="Invalid payload")

    user_id = payload.user_id
    conversation_id = payload.conversation_id
    previous_message_id = payload.previous_message_id
    user_message = payload.user_message
    data_source_id = payload.data_source_id
    client_ip = request.remote_addr

    logger.debug(f"Processing chat request for user_id: {user_id}, conversation_id: {conversation_id}")

    qbiz = get_qbiz_client(user_id=user_id,client_ip=client_ip)

    # identity_id = get_identity_id(user_id)
    # if not identity_id:
    #     logger.info(f"No identity ID found for user_id: {user_id}. Getting new credentials.")
    #     credentials, identity_id = get_new_credentials(user_id, client_ip)
    # else:
    #     credentials = get_cached_credentials(identity_id)
    #     if not credentials:
    #         logger.info(f"No valid cached credentials found for identity_id: {identity_id}. Getting new credentials.")
    #         credentials, _ = get_new_credentials(user_id, client_ip, identity_id)

    # qbiz = boto3.client(
    #     'qbusiness',  
    #     aws_access_key_id=credentials['AccessKeyId'],
    #     aws_secret_access_key=credentials['SecretAccessKey'],
    #     aws_session_token=credentials['SessionToken'],  
    # )

    datasource_filter = [ 
        {
            "equalsTo": {
                "name": "_data_source_id",
                "value": {
                    "stringValue": e
                }
            }
        } 
        for e in data_source_id
    ]
    
    alignment = load_alignment()

    chat_params = {
        "applicationId": qbiz_app_id,
        "userMessage": user_message,
        # "userMessage": alignment+"\n"+user_message,
        "attributeFilter": {
            "andAllFilters": datasource_filter
        }
    }

    if conversation_id:
        chat_params["conversationId"] = conversation_id
        chat_params["parentMessageId"] = previous_message_id

    logger.debug(f"Sending chat_sync request with params: {chat_params}")

    try:
        chat_response = qbiz.chat_sync(**chat_params)
        logger.info("Successfully received chat_sync response")
        logger.debug(f"Chat response: {chat_response}")
    except botocore.exceptions.ClientError as e:
        logger.debug(f"Error code is: {e.response['Error']['Code']}")
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.warning("Conversation not found. Starting a new conversation.")
            # Remove conversation-related parameters and retry
            chat_params.pop("conversationId", None)
            chat_params.pop("parentMessageId", None)
            try:
                chat_response = qbiz.chat_sync(**chat_params)
                logger.info("Successfully started a new conversation")
                logger.debug(f"New chat response: {chat_response}")
                return chat_response
            except Exception as new_e:
                logger.error(f"Error starting new conversation: {str(new_e)}")
                abort(500, description="An error occurred processing your request")
        elif e.response['Error']['Code'] == 'AccessDeniedException': 
            # this is becaue chat_sync silently creates a subscription so retrying
            # the message after subscription creation works
            time.sleep(4)
            try:
                chat_response = qbiz.chat_sync(**chat_params)
                logger.info("Successfully started a new conversation")
                logger.debug(f"New chat response: {chat_response}")
                return chat_response
            except Exception as new_e:
                logger.error(f"Error starting new conversation: {str(new_e)}")
                abort(500, description="An error occurred processing your request")
        else:
            logger.error(f"Unexpected ClientError in chat_sync call: {str(e)}")
            abort(500, description="An error occurred processing your request")
    except Exception as e:
        logger.error(f"Error in chat_sync call: {str(e)}")
        abort(500, description="An error occurred processing your request")

    return chat_response

@app.route("/feedback", methods=['POST'])
def feedback():
    logger.debug("Received feedback")
    try:
        payload = FeedbackPayload(**request.json)
    except ValueError as e:
        logger.error(f"Invalid payload: {str(e)}")
        abort(400, description="Invalid payload")
    
    client_ip = request.remote_addr
    user_id = payload.user_id
    conversation_id = payload.conversation_id
    message_id = payload.message_id
    liked = "USEFUL" if payload.liked else "NOT_USEFUL"

    logger.debug(f"Received {liked} feedback for conversation {conversation_id}, message {message_id}")
    qbiz = get_qbiz_client(user_id=user_id, client_ip=client_ip)
    try:
        qbiz.put_feedback(
            applicationId=qbiz_app_id,
            conversationId=conversation_id,
            messageId=message_id,
            messageUsefulness={
                'usefulness': liked,
                'submittedAt': datetime.now()
            }
        )
        logger.debug("Feedback response recorded")
        return {"message": "Thank you for providing your feedback!"}
    except Exception as e:
        logger.error(f"Error in put_feedback call: {str(e)}")
        return {"message": "Encountered error!"}

"""
Credentials and session related functions
"""
def get_qbiz_client(user_id, client_ip):
    identity_id = get_identity_id(user_id)
    
    if not identity_id:
        logger.info(f"No identity ID found for user_id: {user_id}. Getting new credentials.")
        credentials, identity_id = get_new_credentials(user_id, client_ip)
    else:
        credentials = get_cached_credentials(identity_id)
        if not credentials:
            logger.info(f"No valid cached credentials found for identity_id: {identity_id}. Getting new credentials.")
            credentials, _ = get_new_credentials(user_id, client_ip, identity_id)

    qbiz = boto3.client(
        'qbusiness',  
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],  
    )
    return qbiz

def get_identity_id(user_id):
    try:
        response = cognito_client.list_identities(
            IdentityPoolId=identity_pool_id,
            MaxResults=1,
            HideDisabled=True
        )
        logger.debug(response)
        if response['Identities']:
            return response['Identities'][0]['IdentityId']
        else:
            return None
    except Exception as e:
        logger.error(f"Error listing identities: {str(e)}")
        return None
    
def get_cached_credentials(identity_id):
    logger.debug(f"Attempting to retrieve cached credentials for identity_id: {identity_id}")
    response = table.get_item(Key={'user_id': identity_id})
    if 'Item' in response:
        item = response['Item']
        if item['expiration'] > int(time.time()):
            logger.info(f"Valid cached credentials found for identity_id: {identity_id}")
            return item['credentials']
    logger.info(f"No valid cached credentials found for identity_id: {identity_id}")
    return None

def get_new_credentials(user_id, client_ip, identity_id=None):
    logger.debug(f"Getting new credentials for user_id: {user_id}")
    try:
        cognito_params = {
            "IdentityPoolId": identity_pool_id,
            "Logins": {
                # cognito_identity_provider_name: "6b7ad1d5-2b07-4147-b2ea-fe075567b452"
                # 'qbiz.customProvider': qbiz_uuid
                cognito_identity_provider_name: "ee3bfa3d-9354-4c80-ad32-d57172cc63cf"
            },
            "PrincipalTags":{
                'Email': user_id
            },
            "TokenDuration": 3600
        }
        if identity_id:
            cognito_params["IdentityId"] = identity_id            
        
        cognito_response = cognito_client.get_open_id_token_for_developer_identity(**cognito_params)
        logger.debug("Successfully obtained Cognito token")

        sts_response = sts_client.assume_role_with_web_identity(
            RoleArn=assume_role_arn,
            RoleSessionName="CognitoSession",
            WebIdentityToken=cognito_response['Token'],
            DurationSeconds=3600 
        )
        logger.debug("Successfully assumed role with web identity")

        credentials = sts_response['Credentials']
        
        # Prepare the DynamoDB item
        item = {
            'user_id': cognito_response['IdentityId'], #user_id,
            'ip_address': client_ip,
            'credentials': {
                'AccessKeyId': credentials['AccessKeyId'],
                'SecretAccessKey': credentials['SecretAccessKey'],
                'SessionToken': credentials['SessionToken']
            },
            'expiration': int(credentials['Expiration'].timestamp()),
            'ttl': int(credentials['Expiration'].timestamp())
        }

        # Store in DynamoDB
        table.put_item(Item=item)
        logger.info(f"Successfully stored new credentials for user_id: {user_id}")

        return credentials, cognito_response['IdentityId']
    except Exception as e:
        logger.error(f"Error getting new credentials: {str(e)}")
        raise

def lambda_handler(event, context):
    logger.debug("Lambda function invoked")
    logger.debug(json.dumps(event))
    
    return serverless_wsgi.handle_request(app,event,context)
