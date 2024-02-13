#!/usr/local/bin/python3
import base64
from dotenv import dotenv_values
import json
import jwt
import logging
import requests

## Read the same .env file used to create LDAP-JWT instance:
server_env = dotenv_values("../.env")

def authenticate(username, password, authorized_groups, host):
  """Make request to authenticate endpoint"""
  url = host + "/authenticate"
  if authorized_groups is None:
    data = { "username":username,"password":password}
  else:
    data = { "username":username,"password":password,"authorized_groups": authorized_groups }
  log.debug("Sending authenticate request: " + json.dumps(data, indent=10, sort_keys=True))
  r = requests.post(url, data=data, verify=False)
  if r.status_code == 200:
    token = r.json()["token"]
    logAuthenticate200(r)
    return r.status_code, token
  else:
    logNon200(r)
    return r.status_code, None

def verify(token, authorized_groups, host):
  """Make request to verify endpoint"""
  url = host + "/verify"
  if authorized_groups is None:
    data = {"token" : token}
  else:
    data = {"token": token, "authorized_groups": authorized_groups}
  log.debug("Sending verify request: " + json.dumps(data, indent=10, sort_keys=True))
  r = requests.post(url, data=data, verify=False)
  if r.status_code == 200:
    logVerify200(r)
    return r.status_code
  else:
    logNon200(r)
    return r.status_code

def logNon200(r):
  """Logs debugging information for non-200 response code"""
  log.debug("Response from ldap-jwt server: "+str(r.status_code))
  log.debug("r.text: "+r.text)
  log.debug(json.dumps(r.json(), indent=10, sort_keys=True))
  for h in r.headers:
    log.debug("    " + h + " : " + r.headers[h])
  return None

def logAuthenticate200(r):
  """Logs debugging information for 200 response code

     If this script is unable to decode the token (usually because the CLIENT_SECRET is unavailable for testing),
     a warning is logged.
  """
  log.debug("Authenticate Response: ")
  log.debug(json.dumps(r.json(),indent=10,sort_keys=True))
  log.debug("Authenticate Response Headers: ")
  for h in r.headers:
    log.debug("    " + h + " : " + r.headers[h])
  token = r.json()["token"]
  try:
    decoded_token = jwt.decode(token, server_env["CLIENT_SECRET"], algorithms=["HS256"], audience=server_env["CLIENT_ID"])
    log.debug("Decoded token: ")
    log.debug(json.dumps(decoded_token, indent=30, sort_keys=True))
    header = base64.b64decode(token.split('.')[0]).decode('utf-8')
    log.debug("header:")
    log.debug(json.dumps(json.loads(header), indent=4, sort_keys=True))
    payload = base64.b64decode(token.split('.')[1]+"==").decode('utf-8')
    log.debug("payload:")
    log.debug(json.dumps(json.loads(payload), indent=4, sort_keys=True))
  except jwt.exceptions.InvalidSignatureError as err:
    log.warn("Unable to decode token: " + str(err))
  return None

def logVerify200(r):
  log.debug("Response from verify: " + r.text)
  return None

def init_logging(log_level):
  """Sets up basic logging; defines global log variable"""
  LOG_LEVEL = log_level.upper()
  LOGFORMAT = "%(log_color)s[%(asctime)s:L%(lineno)4s:%(funcName)10s():%(levelname)s]%(reset)s %(message)s"
  logging.getLogger('requests').setLevel(logging.ERROR)
  logging.getLogger('urllib3').setLevel(logging.ERROR)
  from colorlog import ColoredFormatter
  logging.root.setLevel(LOG_LEVEL)
  formatter = ColoredFormatter(LOGFORMAT)
  stream = logging.StreamHandler()
  stream.setLevel(LOG_LEVEL)
  stream.setFormatter(formatter)
  global log 
  log = logging.getLogger('pythonConfig')
  log.setLevel(LOG_LEVEL)
  log.addHandler(stream)

