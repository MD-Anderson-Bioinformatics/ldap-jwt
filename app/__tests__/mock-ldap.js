"use strict";
/*
  This module is a mock LDAP server that can be used for testing purposes, based on
  the ldap-server-mock package.

  It does not support actual authentication--the passwords are not checked.
*/
const logger = require('../logger');
const lsm = require('ldap-server-mock');

const users = [
  {
    dn: 'cn=user1,dc=example,dc=com',
    attributes: {
      objectClass: 'person',
      cn: 'user1',
      memberOf: [
        'cn=group1,dc=group,dc=example,dc=com',
        'cn=groupA,dc=group,dc=example,dc=com'
      ],
      title: 'user-title1',
      uid: 'user1',
      mail: 'user1@example',
      displayName: 'User One'
    }
  },
  {
    dn: 'cn=user2,dc=example,dc=com',
    attributes: {
      objectClass: 'person',
      cn: 'user2',
      memberOf: [
        'cn=group2,dc=group,dc=example,dc=com',
        'cn=groupB,dc=group,dc=example,dc=com'
      ],
      title: 'user-title2',
      uid: 'user2',
      mail: 'user2@example',
      displayName: 'User Two'
    }
  },
  {
    dn: 'cn=bothelper,dc=service,dc=example,dc=com', /* no email for service account */
    attributes: {
      objectClass: 'person',
      cn: 'bothelper',
      memberOf: [
        'cn=bots,dc=group,dc=example,dc=com',
      ],
      uid: 'bothelper',
      displayName: 'Bot Helper'
    }
  }
];
const serverConfiguration = {
    port: 3004,
    searchBase: 'dc=example,dc=com'
};
const server = new lsm.LdapServerMock(users, serverConfiguration, null, null, logger);

/**
 * Starts the mock LDAP server.
 * 
 * This is for use in development/test environments.
 *
 * @async
 * @returns {LdapServerMock} Mock server from ldap-server-mock package.
 */
async function startServer() {
  await server.start();
  logger.info("Mock LDAP server started");
  return server;
}
/**
 * Stops the mock LDAP server.
 *
 * @async
 */
async function stopServer() {
  logger.info("Stopping mock LDAP server");
  await server.stop();
}

module.exports = {
  startServer: startServer,
  stopServer: stopServer
}
