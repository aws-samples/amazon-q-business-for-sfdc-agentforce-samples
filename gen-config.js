// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Generates Amplify Auth config for the react app with the Cognito resources created by the 
 * CDK Application and places it in the React Applications config directory
 */

const fs = require('fs');
const data = require('./cdk-outputs.json');

const deploy_config = {
    "api":{
        "endpoint" : data["QbizUnauthCdkAppStack"]["qbizappservicesapiurl"],
        "key": data["QbizUnauthCdkAppStack"]["qbizappservicesapikey"]
    }
};

fs.writeFileSync("../qbiz-unauth-react-app/public/apiconfig.js", "window.apidata="+JSON.stringify(deploy_config));   
fs.writeFileSync("../qbiz-unauth-react-app/dist/apiconfig.js", "window.apidata="+JSON.stringify(deploy_config));


console.log("IDP Proof of Concept Application deployed and accessible at url → https://main."+data['QbizUnauthCdkAppStack']['qbizwebappdomain']);
