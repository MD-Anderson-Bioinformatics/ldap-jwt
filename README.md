# Simple "ldap-jwt" service
Lightweight node.js based web service that provides user authentication against LDAP server (Active Directory / Windows network) credentials and returns a JSON Web Token.

Heavily based on the work of [gregfroese/ldapservice](https://github.com/gregfroese/ldapservice).


## Changes

* Replaced yaml config-files with json
* Removed support for RabbitMQ
* Updated npm dependencies
* Simplified endpoints
* Added SSL 


## Usage

#### 1. SSL Certificates

Generate / obtain SSL certificates, and place the .crt and .key files in an
'ssl' directory at the top-level of the directory: ssl/server.key and ssl/server.crt

#### 2. Configuration variables

Place configuration variables in .env file. Example:

```
LDAP=enabled
LDAPAUTH_URL=ldaps://hostname
LDAPAUTH_BINDCREDENTIALS=secret
LDAPAUTH_SEARCHBASE=dc=example,dc=com
LDAPAUTH_BINDDN=cn=bind_user,dc=examle,dc=com
CLIENT_ID=test-client-id
CLIENT_SECRET=test-client-secret
DEBUG=true
```

#### 3. Build image

```bash
$ docker build -t ldap_jwt .
```

#### 4. Start container

```bash
$ docker run -p 3000:3000 --rm -it --env-file .env --name ldap-jwt ldap_jwt
```

#### 5. Manual test

```bash
$ curl -k -d '{"username":"<username>","password":"<password>"}' -H "Content-Type: application/json" -X POST "https://<hostname>/ldap-jwt/authenticate"
```

## Endpoints

### /ldap-jwt/authenticate

**Payload**

```json
{
    "username": "euler",
    "password": "password"
}
```

**Response**

```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NjE3OTQxMjY0NjAsInVzZXJfbmFtZSI6ImV1bGVyIiwiZnVsbF9uYW1lIjoiTGVvbmhhcmQgRXVsZXIiLCJtYWlsIjoiZXVsZXJAbGRhcC5mb3J1bXN5cy5jb20ifQ.bqSjshvLnHsTJwcXBXsNVtGGNatvQHyqhL8MSXuMwFI",
  "full_name": "Leonhard Euler"
}
```

### /ldap-jwt/verify

**Payload**

```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NjE3OTQxMjY0NjAsInVzZXJfbmFtZSI6ImV1bGVyIiwiZnVsbF9uYW1lIjoiTGVvbmhhcmQgRXVsZXIiLCJtYWlsIjoiZXVsZXJAbGRhcC5mb3J1bXN5cy5jb20ifQ.bqSjshvLnHsTJwcXBXsNVtGGNatvQHyqhL8MSXuMwFI"
}
```

**Response**

```json
{
  "exp": 1495058246,
  "user_name": "euler",
  "full_name": "Leonhard Euler",
  "mail": "euler@ldap.forumsys.com"
}
```

## ToDo

* Write Tests
