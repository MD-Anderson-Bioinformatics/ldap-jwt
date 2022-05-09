# Simple "ldap-jwt" service
Lightweight node.js based web service that provides user authentication against LDAP server (Active Directory / Windows network) credentials and returns a JSON Web Token.

Heavily based on the work of [gregfroese/ldapservice](https://github.com/gregfroese/ldapservice).


## Changes

* Replaced yaml config-files with json
* Removed support for RabbitMQ
* Updated npm dependencies
* Simplified endpoints
* Added option to use SSL (httpS) 
* Added option to specify authorized groups


## Usage


#### 1. Configuration variables

Place configuration variables in .env file. Example:

```bash
LDAP=enabled
LDAPAUTH_URL=ldaps://hostname
LDAPAUTH_BINDCREDENTIALS=secret
LDAPAUTH_SEARCHBASE=dc=example,dc=com
LDAPAUTH_BINDDN=cn=bind_user,dc=examle,dc=com
CLIENT_ID=test-client-id
CLIENT_SECRET=test-client-secret
DEBUG=true  ## <-- turns on debugging
SSL=true ## <-- turns on SSL (httpS)
```

#### 2. SSL Certificates

If setting SSL=true, generate / obtain SSL certificates, and place the .crt and .key files in an 'ssl' directory at the top-level of the directory: ssl/server.key and ssl/server.crt


#### 3. Build image

```bash
$ docker build -t ldap_jwt .
```

#### 4. Start container

```bash
$ docker run -p 3000:3000 --rm -it --env-file .env --name ldap-jwt ldap_jwt
```

#### 5. Verify server is running

Request with username and password:

```bash
$ curl -k -d '{"username":"<username>","password":"<password>"}' -H "Content-Type: application/json" -X POST "https://<hostname>/ldap-jwt/authenticate"
```

Request with username and password with authorized group (only allows access if username is in authorized group):

```bash
$ curl -k -d '{"username":"<username>","password":"<password>","authorized_groups":[<authorized group]}' -H "Content-Type: application/json" -X POST "https://<hostname>/ldap-jwt/authenticate"
```

#### 5. Run tests

The README in the tests directory describes the setup and procedure for running tests. 

For quick help:

```bash
cd tests
python3 unitTests.py --help
```

TODO: write these tests in node (instead of python)

## Endpoints

### /ldap-jwt/authenticate

#### No authorozed\_groups

This example returns a token if <username> is any user in LDAP (and of course has the correct password).

*Body of POST request:*

```json
{
    "username": <username>,
    "password": <password>
}
```

*Response:*

```json
{
  "full_name": <user's full name>,
  "mail": <user's email address>,
  "token": <JWT>
}
```

*Payload of JWT:*

```json
  "aud": <CLIENT_ID from .env file>,
  "exp": <expiration date>,
  "full_name": <user's full name>,
  "mail": <user's email address>,
  "user_name": <username>
```

#### w/ authorized_groups

This example returns a token if <username> is in LDAP and is a member of either <LDAP group1> or <LDAP group2> (and of course has the correct password).

*Body of POST request:*

```json
{
    "username": <username>,
    "password": <password>,
    "authorized_groups": [ <LDAP group1>, <LDAP group2> ]
}
```

Note: requests that incorporate authorized\_groups should only be made from the server side of an application. This practice 1) protects potentially sensitive LDAP group information and 2) prevents malicious users from substituting groups they belong to and potentially gaining unauthorized application access.

*Response:*

```json
{
  "full_name": <user's full name>,
  "mail": <user's email address>,
  "token": <JWT>
}
```

*Payload of JWT:*

```json
  "aud": <CLIENT_ID from .env file>,
  "exp": <expiration date>,
  "full_name": <user's full name>,
  "mail": <user's email address>,
  "user_authorized_groups": [ <LDAP group1>, <LDAP groupA> ],
  "user_name": <username>
```

In the JWT payload, the user\_authorized\_groups list is the intersection of the "authorized_groups" in the initial request and the user's groups in LDAP.


### /ldap-jwt/verify 

#### w/o authorized groups in token

In this example, the JWT payload does NOT contain an encoded authorized\_groups key.

*Body of POST request:*

```json
{
  "token": <JWT>
}
```

*Response:*

```json
{
  "aud": <CLIENT_ID from .env file>,
  "exp": <expiration date>,
  "full_name": <user's full name>,
  "mail": <user's email address>,
  "user_name": <username>
}
```

#### w/ authorized groups in token

In this example, the JWT payload contains an encoded authorized\_groups key with values [ \<LDAP group1\>, \<LDAP groupA\> ].

*Body of POST request:*

```json
{
  "token": <JWT>
}
```

*Response:*

```json
{
  "aud": <CLIENT_ID from .env file>,
  "exp": <expiration date>,
  "full_name": <user's full name>,
  "mail": <user's email address>,
  "user_authorized_groups": [ <LDAP group1>, <LDAP groupA> ],
  "user_name": <username>
}
```
