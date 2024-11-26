#!/usr/bin/env node

const cdk = require('aws-cdk-lib');
const { QbizUnauthCdkAppStack } = require('../lib/qbiz-unauth-cdk-app-stack');
const fs = require('fs');
const path = require('path');

const app = new cdk.App();

// Read the params file path from context
const paramsFilePath = app.node.tryGetContext('paramsFile');
const paramsPath = path.join(__dirname, '..', paramsFilePath);

// Read and parse the params file
const params = JSON.parse(fs.readFileSync(paramsPath, 'utf8'));


new QbizUnauthCdkAppStack(app, 'QbizUnauthCdkAppStack', {
  /* If you don't specify 'env', this stack will be environment-agnostic.
   * Account/Region-dependent features and context lookups will not work,
   * but a single synthesized template can be deployed anywhere. */

  /* Uncomment the next line to specialize this stack for the AWS Account
   * and Region that are implied by the current CLI configuration. */
  // env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },

  /* Uncomment the next line if you know exactly what Account and Region you
   * want to deploy the stack to. */
  //env: { account: '733449663725', region: 'us-east-1' },
  env: { account: params.AccountId, region: params.Region },
  

  /* For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html */
});
