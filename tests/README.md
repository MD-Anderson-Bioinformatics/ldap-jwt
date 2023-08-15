# Testing

This directory contains python unit tests. (TODO: write these tests in node instead of python).

These tests read in the same .env file as used by the docker container in order to get environment variables relevant to the server. 

There is an additional file of environment variables described in step 1 below.

These tests are configured to allow for self-signed certificates.

A requriements.txt file is provided to allow using a python virtual environment to run tests.

## Usage

Instructions for running tests:

1. Create a file of test usernames, passwords, and authorized groups with entries corresponding to test LDAP server. See example file: `user_env_file.example`

   Format for file:

   ```
   AUTHORIZED_GROUP_A=<example group A>
   AUTHORIZED_GROUP_B=<example group B>
   
   ## User in AUTHORIZED_GROUP_A but not in AUTHORIZED_GROUP_B
   VALID_USERNAME_A=<username A>
   VALID_USER_PASSWORD_A=<password A>

   ## User in AUTHORIZED_GROUP_B but not in AUTHORIZED_GROUP_A
   VALID_USERNAME_B=<username B>
   VALID_USER_PASSWORD_B=<password B>

   INVALID_USERNAME=invalidUsername
   INVALID_USER_PASSWORD=invalidPassword
   ```

2. Create python virtual environment

   These are typical instructions for creating a virutal environment.

   ```bash
   python3 -m venv .env
   source .env/bin/activate
   pip install -r requirements.txt
   ```

3. Run unit tests

   ```bash
   python3 unitTests.py -u http://<servername>:<port>/ldap-jwt -f <user_env_file> -l <log level>
   ```

   For help info:
   
   ```bash
   python3 unitTests.py --help
   ```

4. Deactivate virtual environment

   ```bash
   deactivate
   ```

