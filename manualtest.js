#!/usr/bin/env node
//
// Script to test the ldap-jwt authentication and verification endpoints.
// To see argument list:
//  node deploytest.js --help
//
const axios = require('axios');
const https = require('https');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const readline = require('readline-sync');

const argv = yargs(hideBin(process.argv))
  .option('username', {
    alias: 'u',
    type: 'string',
    description: 'Username to test. REQUIRED'
  })
  .option('base_url', {
    type: 'string',
    description: 'Base URL to test. E.g. https://locahost:3000. REQUIRED'
  })
  .option('authorized_groups', {
    alias: 'a',
    type: 'string',
    description: 'LDAP group(s) to test.'
  })
  .option('check_cert', {
    alias: 'c',
    default: true,
    type: 'boolean',
    description: 'Whether or not to check for self-signed certificate.'
  })
  .demandOption(['username'], 'Please provide the required username argument to run this script.')
  .demandOption(['base_url'], 'Please provide the required base_url argument to run this script.')
  .argv;

const username = argv.username;
const password = readline.question(`Enter password for ${username}: `, { hideEchoBack: true });
const authorized_groups = [argv.authorized_groups];
const data = argv.authorized_groups ? {username, password, authorized_groups: authorized_groups } : { username, password };
const authenticate_url = `${argv.base_url}/ldap-jwt/authenticate`;
const verify_url = `${argv.base_url}/ldap-jwt/verify`;


// Create an https agent to allow self-signed certificates (if rejectUnauthorized is false)
const agent = new https.Agent({
  rejectUnauthorized: argv.check_cert
});

// Post to /authenticate and if successful, post to /verify
console.log(`Making POST to /authenticate endpoint: ${authenticate_url}`);
axios.post(authenticate_url, data, { validateStatus: false, httpsAgent: agent })
  .then(response => {
    if (response.status === 200) {
      console.log('Response from /authenticate:');
      console.log(response.data);
      console.log(`Making POST to /verify endpoint: ${verify_url}`);
      axios.post(verify_url, {token: response.data.token}, { validateStatus: false, httpsAgent: agent })
        .then(response => {
          if (response.status === 200) {
            console.log('Response from /verify:');
            console.log(response.data);
          } else {
            console.error(`ERROR: Verify request failed with status code ${response.status}`);
            console.error(`ERROR:     statusText: ${response.statusText}`);
            console.error(`ERROR:     Message: ${response.data.error}`);
          }
        })
    } else {
      // log keys of response object
      console.error(`ERROR: Authenticate request failed with status code ${response.status}`);
      console.error(`ERROR:     statusText: ${response.statusText}`);
      console.error(`ERROR:     Message: ${response.data.error}`);
    }
  })
  .catch(error => {
    console.error("ERROR: " + error.message);
  });
