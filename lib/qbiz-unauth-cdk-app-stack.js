const { Stack, CfnOutput, Duration, RemovalPolicy } = require('aws-cdk-lib');
const iam = require('aws-cdk-lib/aws-iam');
const lambda = require('aws-cdk-lib/aws-lambda');
const dynamodb = require('aws-cdk-lib/aws-dynamodb');
const amplify = require('@aws-cdk/aws-amplify-alpha');
const assets = require('aws-cdk-lib/aws-s3-assets');
const apigateway = require('aws-cdk-lib/aws-apigateway');
const cognito = require('aws-cdk-lib/aws-cognito');
const fs = require('fs');
const path = require('path');
const logs = require('aws-cdk-lib/aws-logs');
const kms = require('aws-cdk-lib/aws-kms');

class QbizUnauthCdkAppStack extends Stack {
  /**
   *
   * @param {Construct} scope
   * @param {string} id
   * @param {StackProps=} props
   */
  constructor(scope, id, props) {
    super(scope, id, props);
    
    // Read parameters from file
    const paramsPath = path.join(__dirname, '../cdk-params.json');
    const params = JSON.parse(fs.readFileSync(paramsPath, 'utf8'));


    // Create a new KMS key for DynamoDB encryption
    const dynamoDbEncryptionKey = new kms.Key(this, 'DynamoDbEncryptionKey', {
      description: 'Customer managed key for DynamoDB table encryption',
      enableKeyRotation: true,
      alias: `alias/${params.UserCredentialsTableName}-key`,
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7), // Waiting period for key deletion
    });

    // Create the DynamoDB table with encryption using the CMK
    const userCredentialsTable = new dynamodb.Table(this, 'QbizUserCredentialsTable', {
      tableName: params.UserCredentialsTableName,
      partitionKey: { 
        name: params.PartitionKeyName,
        type: dynamodb.AttributeType.STRING 
      },
      removalPolicy: RemovalPolicy.DESTROY,
      timeToLiveAttribute: params.TTLAttributeName,
      pointInTimeRecovery: true,
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      // Enable encryption using the CMK
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey
    });

    // Grant the DynamoDB service principal access to use the CMK
    dynamoDbEncryptionKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'Enable DynamoDB Service Principal Usage',
        effect: iam.Effect.ALLOW,
        principals: [
          new iam.ServicePrincipal('dynamodb.amazonaws.com')
        ],
        actions: [
          'kms:Decrypt',
          'kms:CreateGrant',
          'kms:GenerateDataKey'
        ],
        resources: ['*']
      })
    );
    

    
    // Output the table name
    new CfnOutput(this, 'UserCredentialsTableName', {
      value: userCredentialsTable.tableName,
      description: 'The name of the user credentials DynamoDB table',
    });
    
    

    const identityPool = new cognito.CfnIdentityPool(this, 'QBizIdentityPool', {
      identityPoolName: params.CognitoUserPoolName,
      
      // Allow unauthenticated identities - set to false if not needed
      allowUnauthenticatedIdentities: false,
      
      // Configure the custom developer provider
      developerProviderName: 'qbiz.customProvider',     

    });
    
    // Create authenticated and unauthenticated IAM roles
    const authenticatedRole = new iam.Role(this, 'CognitoDefaultAuthenticatedRole', {
      roleName: params.CognitoIdentityPoolRole,
      assumedBy: new iam.FederatedPrincipal('cognito-identity.amazonaws.com', {
        StringEquals: {
          'cognito-identity.amazonaws.com:aud': identityPool.ref
        },
        'ForAnyValue:StringLike': {
          'cognito-identity.amazonaws.com:amr': 'authenticated'
        }
      }, 'sts:AssumeRoleWithWebIdentity'),
      inlinePolicies:{
            "cognito-authenticated-policy": new iam.PolicyDocument({
              statements: [
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: ["cognito-identity:GetCredentialsForIdentity"],
                    resources: ["*"]
                })
              ]
            })
        }
    });
    
    // Attach the roles to the Identity Pool
    new cognito.CfnIdentityPoolRoleAttachment(this, 'IdentityPoolRoleAttachment', {
      identityPoolId: identityPool.ref,
      roles: {
        'authenticated': authenticatedRole.roleArn
      }
    });
    
    // Output the Identity Pool ID
    new CfnOutput(this, 'IdentityPoolId', {
      value: identityPool.ref,
      description: 'Identity Pool ID'
    });
    
    // Lambda IAM Role
    const lambdaRole = new iam.Role(this, 'amazon-q-unauth-chat-lambda-role', {
      roleName: params.LambdaroleName,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [                            
          iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole"),
          iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonCognitoDeveloperAuthenticatedIdentities"),
      ],
      inlinePolicies: {
          "lambda-assume-policy-for-web-identity": new iam.PolicyDocument({
              statements: [
                  new iam.PolicyStatement({
                      effect: iam.Effect.ALLOW,
                      actions: ["sts:AssumeRoleWithWebIdentity"],
                      resources: [`arn:aws:iam::${this.account}:role/${params.CognitoRoleName}`]
                  }),
                  new iam.PolicyStatement({
                      effect: iam.Effect.ALLOW,
                      actions: ["qbusiness:ChatSync"],
                      resources: [`arn:aws:qbusiness:${Stack.of(this).region}:${Stack.of(this).account}:application/${params.QbizAppId}`]
                  }),
                  new iam.PolicyStatement({
                      effect: iam.Effect.ALLOW,
                      actions: ["cognito-identity:ListIdentities"],
                      resources: [`arn:aws:cognito-identity:${Stack.of(this).region}:${Stack.of(this).account}:identitypool/${identityPool.ref}`]
                  }),
                  // Add explicit CloudWatch Logs permissions if not using managed policy
                  new iam.PolicyStatement({
                      effect: iam.Effect.ALLOW,
                      actions: [
                          "logs:CreateLogGroup",
                          "logs:CreateLogStream",
                          "logs:PutLogEvents"
                      ],
                      resources: [
                          `arn:aws:logs:${Stack.of(this).region}:${Stack.of(this).account}:log-group:/aws/lambda/${params.LambdafunctionName}:*`
                      ]
                  })
              ]
          })
      }
    });
    
    // First create the OIDC Provider
    const oidcProvider = new iam.OpenIdConnectProvider(this, 'CognitoOIDCProvider', {
      url: 'https://cognito-identity.amazonaws.com',
      clientIds: [identityPool.ref], // Using Identity Pool ID as the audience
    });

    // Create the IAM role for cognito
    const amazonQUnauthChatCognitoRole = new iam.Role(this, 'amazon-q-unauth-chat-cognito-role',{
      roleName: params.CognitoidentityPoolChatRoleName,
      assumedBy: new iam.CompositePrincipal(
        new iam.FederatedPrincipal(
          oidcProvider.openIdConnectProviderArn,
          {
            "StringEquals": {
              "cognito-identity.amazonaws.com:aud": identityPool.ref
            },
            "StringLike": {
              "aws:RequestTag/Email": "*"
            }
          },
          "sts:AssumeRoleWithWebIdentity"
        ),
        new iam.FederatedPrincipal(
          oidcProvider.openIdConnectProviderArn,
          {
            "StringLike": {
              "aws:RequestTag/Email": "*"
            }
          },
          "sts:TagSession"
        ),
        new iam.ServicePrincipal(
          "application.qbusiness.amazonaws.com",
          {
            "StringEquals": {
              "cognito-identity.amazonaws.com:aud": identityPool.ref
            },
            "ArnEquals": {
              "aws:SourceArn": `arn:aws:qbusiness:${this.region}:${this.account}:application/${params.QbizAppId}`
            }
          },
          ["sts:AssumeRole", "sts:SetContext"],
        )  
      ),
      inlinePolicies:{
          "cognito-assume-policy-for-web-identity": new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                  effect: iam.Effect.ALLOW,
                  actions: ["qbusiness:Chat", "qbusiness:ChatSync", "qbusiness:ListMessages", "qbusiness:ListConversations", "qbusiness:PutFeedback"],
                  resources: [`arn:aws:qbusiness:${this.region}:${this.account}:application/${params.QbizAppId}`]
              }),
              new iam.PolicyStatement({
                  effect: iam.Effect.ALLOW,
                  actions: ["sts:SetContext"],
                  resources: ["arn:aws:sts::*:self"],
                  conditions: {
                    StringLike: {
                        "aws:CalledViaLast": ["qbusiness.amazonaws.com"]
                    }
                }
              }),
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: ["user-subscriptions:CreateClaim"],
                resources: [`arn:aws:user-subscriptions:${Stack.of(this).region}:${Stack.of(this).account}:subscription/*`]
              })
            ]
          })
        }
    });    

    const q_biz_chat = new lambda.DockerImageFunction(this, 'amazon-q-unauth-chat', {
          functionName: params.LambdafunctionName,
          description: 'Amazon Q Lambda Function for unauthenticated public chat',   
          code: lambda.DockerImageCode.fromImageAsset(path.join(__dirname, '../src/lambda')),    
          environment:{
              LOG_LEVEL: params.LogLevel,
              QBIZ_APP_ID: params.QbizAppId,
              QBIZ_DATA_SOURCE_ID: params.QbizDataSourceId,
              COGNITO_IDENTITY_PROVIDER_NAME: params.CognitoIdentityProviderName,
              COGNITO_IDENTITY_POOL_ID: identityPool.ref,  
              ASSUME_ROLE_ARN: amazonQUnauthChatCognitoRole.roleArn,
              CREDS_TABLE: userCredentialsTable.tableName,
          },
          role: lambdaRole,
          timeout: Duration.minutes(5),
          memorySize: params.LambdaMemorySize,
          reservedConcurrentExecutions: params.LambdaReservedConcurrency
      }); 

    userCredentialsTable.grantReadWriteData(q_biz_chat)

    // Create a KMS key for CloudWatch Logs encryption
    const apiLogsEncryptionKey = new kms.Key(this, 'ApiGatewayLogsKey', {
      description: 'KMS key for API Gateway CloudWatch Logs encryption',
      enableKeyRotation: true,
      alias: 'alias/' + params.RestApiName.replace(/[^a-zA-Z0-9-_]/g, '-') + '-logs-key',
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7)
    });

    // Add necessary permissions for CloudWatch Logs to use the KMS key
    apiLogsEncryptionKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'Enable CloudWatch Logs Encryption',
        effect: iam.Effect.ALLOW,
        principals: [
          new iam.ServicePrincipal('logs.' + Stack.of(this).region + '.amazonaws.com')
        ],
        actions: [
          'kms:Encrypt*',
          'kms:Decrypt*',
          'kms:ReEncrypt*',
          'kms:GenerateDataKey*',
          'kms:Describe*'
        ],
        resources: ['*'],
        conditions: {
          ArnLike: {
            'kms:EncryptionContext:aws:logs:arn': 'arn:aws:logs:' + Stack.of(this).region + ':' + Stack.of(this).account + ':*'
          }
        }
      })
    );


    // Create the API Gateway
    const api = new apigateway.RestApi(this, 'QBizChatApi', {
      restApiName: params.RestApiName,
      description: 'This service handles QBiz chat requests.',
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: apigateway.Cors.DEFAULT_HEADERS,
        statusCode: 200,
        allowCredentials: false          
      },
      apiKeySourceType: apigateway.ApiKeySourceType.HEADER,
      deployOptions: {
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: true,
        // Fixed AccessLogSetting configuration
        accessLogDestination: new apigateway.LogGroupLogDestination(
          new logs.LogGroup(this, 'ApiGatewayAccessLogs', {
            // Ensure log group name follows the pattern
            logGroupName: '/aws/apigateway/' + params.RestApiName.replace(/[^a-zA-Z0-9-_]/g, '-'),
            retention: logs.RetentionDays.ONE_WEEK,
            removalPolicy: RemovalPolicy.DESTROY,
            encryptionKey: apiLogsEncryptionKey
          })
        ),
        accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields({
          caller: true,
          httpMethod: true,
          ip: true,
          protocol: true,
          requestTime: true,
          resourcePath: true,
          responseLength: true,
          status: true,
          user: true
        })
      },
      cloudWatchRole: true
    });
    
  
    // Create the /chat resource
    const chat = api.root.addResource('chat');
    const feedback = api.root.addResource('feedback');
  
    // Add the POST method to /chat
    chat.addMethod('POST', new apigateway.LambdaIntegration(q_biz_chat), {
        apiKeyRequired: true
    });
    // Add the POST method to /feedback
    feedback.addMethod('POST',new apigateway.LambdaIntegration(q_biz_chat), {
      apiKeyRequired: true
    })


    // Create an API Key
    const apiKey = api.addApiKey('QBizChatApiKey');
  
      // Create a usage plan
    const plan = api.addUsagePlan('QBizChatUsagePlan', {
      name: 'QBiz Chat Usage Plan',
      apiKey,
      throttle: {
        rateLimit: params.ApiRateLimit,
        burstLimit: params.ApiBurstLimit
    },
    quota: {
        limit: params.ApiQuota,
        period: apigateway.Period.DAY
    }
    });

    // Add the API to the usage plan
    plan.addApiStage({
        stage: api.deploymentStage,
        api: api
    });

    // Output the API URL and API Key    
    new CfnOutput(this, 'qbiz-app-services-apikey', { 
        value: apiKey.keyId,
        description: "QBiz API Key",
        exportName: "QBizAppServicesApiKey"
    });

    new CfnOutput(this, 'qbiz-app-services-api-url', {
        value: api.url,
        description: 'QBiz Chat Backend Services API URL',
        exportName: 'QBizAppServicesApiUrl'
    });
      
  }
}

module.exports = { QbizUnauthCdkAppStack }
