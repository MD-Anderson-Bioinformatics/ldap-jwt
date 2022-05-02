#!/usr/local/bin/python3
import argparse
import authenticate_utils as au
from dotenv import dotenv_values
import json
from os.path import exists
import requests
import sys
import unittest

class TestLDAPJWT(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    """Read envs, configure logging.

       Enviornment variables of test users, passwords, and authorized groups are read
       from file. See README, example file "user_env_file.example", or code below for details.
    """
    if self.user_env_file == None:
       sys.exit("Missing required argument: user_env_file")
    if not exists(self.user_env_file):
       sys.exit("File '"+self.user_env_file+"' does not exist")
    self.test_envs = dotenv_values(self.user_env_file)
    au.init_logging(self.log_level)

  def test01(self):
    """Test username/password access for valid user with valid password."""
    username = self.test_envs["VALID_USERNAME_A"]
    password = self.test_envs["VALID_USER_PASSWORD_A"]
    authenticate_status, token = au.authenticate(username, password, None, self.host)
    self.assertNotEqual(token, None)
    verify_status = au.verify(token, None, self.host)
    self.assertEqual(verify_status, 200)

  def test02(self):
    """Test username/password fails for valid user with wrong password."""
    username = self.test_envs["VALID_USERNAME_A"]
    password = "notCorrectPassword"
    authenticate_status, token = au.authenticate(username, password, None, self.host)
    self.assertEqual(token, None)
    verify_status = au.verify(token, None, self.host)
    self.assertEqual(verify_status, 400)

  def test03(self):
    """Test username/password access fails for non-valid user."""
    username = self.test_envs["INVALID_USERNAME"]
    password = self.test_envs["INVALID_USER_PASSWORD"]
    authenticate_status, token = au.authenticate(username, password, None, self.host)
    self.assertEqual(token, None)
    verify_status = au.verify(token, None, self.host)
    self.assertEqual(verify_status, 400)

  def test04(self):
    """Test username/password access with authorized group"""
    username = self.test_envs["VALID_USERNAME_A"]
    password = self.test_envs["VALID_USER_PASSWORD_A"]
    a_groups = [self.test_envs["AUTHORIZED_GROUP_A"]]
    authenticate_status, token = au.authenticate(username, password, a_groups, self.host)
    self.assertNotEqual(token, None)
    verify_status = au.verify(token, a_groups, self.host)
    self.assertEqual(verify_status, 200)

  def test05(self):
    """Test multiple authorized groups

       Verify the authentication endpoint can handle more than one group in list.
    """
    username = self.test_envs["VALID_USERNAME_A"]
    password = self.test_envs["VALID_USER_PASSWORD_A"]
    a_groups = [self.test_envs["AUTHORIZED_GROUP_A"], self.test_envs["AUTHORIZED_GROUP_B"]]
    authenticate_status, token = au.authenticate(username, password, a_groups, self.host)
    self.assertNotEqual(token, None)
    verify_status = au.verify(token, a_groups, self.host)
    self.assertEqual(verify_status, 200)

  def test06(self):
    """Test authorized group sent as string

       Verify the authentication endpoint can handle group send as string (rather than list)
    """
    username = self.test_envs["VALID_USERNAME_A"]
    password = self.test_envs["VALID_USER_PASSWORD_A"]
    a_groups = self.test_envs["AUTHORIZED_GROUP_A"]
    authenticate_status, token = au.authenticate(username, password, a_groups, self.host)
    self.assertNotEqual(token, None)
    verify_status = au.verify(token, a_groups, self.host)
    self.assertEqual(verify_status, 200)

  def test07(self):
    """Test username/password access fails for user not in authorized group"""
    username = self.test_envs["VALID_USERNAME_A"]
    password = self.test_envs["VALID_USER_PASSWORD_A"]
    a_groups = [self.test_envs["AUTHORIZED_GROUP_B"]]
    authenticate_status, token = au.authenticate(username, password, a_groups, self.host)
    self.assertEqual(authenticate_status, 401)

  def test08(self):
    """Test wrong group in token
    
       User gets token for a group the are a part of, then tries to use that token
       for verify endpoint for group user is NOT a part of.
    """
    username = self.test_envs["VALID_USERNAME_A"]
    password = self.test_envs["VALID_USER_PASSWORD_A"]
    a_groups = [self.test_envs["AUTHORIZED_GROUP_A"]]
    authenticate_stauts, token = au.authenticate(username, password, a_groups, self.host)
    self.assertNotEqual(token, None)
    a_groups = [self.test_envs["AUTHORIZED_GROUP_B"]]
    verify_status = au.verify(token, a_groups, self.host)
    self.assertEqual(verify_status, 401)

  def test09(self):
    """Test no group in token

       User gets a token that does not contain authorized group information, and tries
       to use that token on the verify enpoint with group access.
    """
    username = self.test_envs["VALID_USERNAME_A"]
    password = self.test_envs["VALID_USER_PASSWORD_A"]
    authenticate_stauts, token = au.authenticate(username, password, None, self.host)
    self.assertNotEqual(token, None)
    a_groups = [self.test_envs["AUTHORIZED_GROUP_A"]]
    verify_status = au.verify(token, a_groups, self.host)
    self.assertEqual(verify_status, 401)

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Testing LDAP-JWT server", add_help=False)
  parser.add_argument("--help", action="help", default=argparse.SUPPRESS, help=argparse._("Show this help message and exit."))
  parser.add_argument("-h", "--host", dest="host", action="store", 
       help="Hostname and port of LDAP-JWT server. Default: https://localhost:3000/ldap-jwt",
       default="https://localhost:3000/ldap-jwt")
  parser.add_argument("-f", "--user_env_file", dest="user_env_file", action="store",
       help="Filename of test usernames, passwords, and groups. See user_env_file.example or README for details.")
  parser.add_argument("-l", "--log_level", dest="log_level", action="store", 
       help="Log level for unit tests. Default: INFO", default="INFO")
  args = parser.parse_args()
  for a in vars(args):
    setattr(TestLDAPJWT, a, getattr(args,a))
  for i in range(len(sys.argv)-1):
    sys.argv.pop()
  unittest.main(failfast=True)


