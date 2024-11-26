# Amazon Q Business Integration CDK Project

## Overview
This project implements a serverless infrastructure using AWS CDK to enable Amazon Q chat integration. It provides a secure and scalable architecture for handling chat functionality through Amazon Q Business services.

## Architecture
The solution includes the following AWS services:
- AWS Lambda
- Amazon API Gateway
- AWS IAM
- Amazon Q Business
- Amazon DynamoDB
- Amazon Cognito

## Prerequisites
- AWS Account
- Node.js (v14.x or later)
- AWS CDK CLI
- Docker (for Lambda deployment)
- AWS CLI configured with appropriate credentials

## Project Structure
biz-unauth-cdk-app/
├── lib/
│ └── qbiz-unauth-cdk-app-stack.js
├── src/
│ └── lambda/
│ └── lambda source files
├── cdk-params.json
├── package.json
└── README.md

## Configuration
Create a `cdk-params.json` file in the root directory with the following structure:
```json
{
  "AccountId": "AWS Account ID",
  "Region": "AWS region",
  "UserCredentialsTableName": "your-table-name",
  "PartitionKeyName": "your-partition-key",
  "TTLAttributeName": "ttl",
  "CognitoUserPoolName": "your-user-pool-name",
  "CognitoIdentityPoolRole": "your-identity-pool-role",
  "LambdaroleName": "your-lambda-role",
  "LambdafunctionName": "your-lambda-function",
  "QbizAppId": "your-qbiz-app-id",
  "QbizDataSourceId": "your-datasource-id",
  "RestApiName": "your-api-name",
  "LogLevel": "INFO"
}
```

## Installation
1. Clone the repository
git clone [repository-url]
cd qbiz-unauth-cdk-app

2. Update the AWS Account ID and Region in the parameter file cdk-params.json 
  "AccountId": "111122223333",
  "Region": "us-east-1",

3. Set up the required resources for the AWS CDK
```sh
cdk bootstrap
```

4. Install dependencies
```sh
npm install
```
5. Synthesize the CloudFormation template
```sh
cdk synth
```
6. Deploy the stack:
```sh
cdk deploy 
```
7. Create Amazon Q Buinsess application without web Experience and get the Application ID and Data source ID
Note: The CDK code cretae Cognito identity pool and AWS IAM Identity Provider. You will need the Cognito identity pool Id and AWS IAM Identity Provider arn during the creation of the Amazon Q Buinsess application 

    Identity Provider: arn:aws:iam::ACOUNT_ID:oidc-provider/cognito-identity.amazonaws.com
    Client ID: Cogntio Identity pool ID (us-east-1:a1111111-2222-3333-a1a1-a111111111)

8. Update the Application ID and Data source ID in the parameter file cdk-params.json 
	"QbizAppId":  "a11b2cc3-222a-333b-4444-5555c66d7777",
	"QbizDataSourceId":  "['1a1111a1-2aaa-33aa-4444-aa555a55a55a']",

9. Run the CDK Deploy aian to update the stack with Amazon Q Business Application ID and Data source ID
cdk deploy 

## Clean Up
To remove all deployed resources:
```sh
cdk destroy
```

## License

This project is licensed under the [MIT License](LICENSE).
```
