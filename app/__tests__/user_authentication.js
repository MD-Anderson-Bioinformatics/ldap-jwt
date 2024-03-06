"use strict";
const logger = require('../logger');
const ut = require('../utils');
const settings = require('./settings.json');

// Note: the mock ldap server does not check password, so any password will work.
describe("test valid user", () => {
  test("should return valid user", async () => {
    const user = await ut.authenticate('user1', 'password1', settings);
    logger.debug("user: ", user);
    expect(user).toEqual({
      dn: 'cn=user1,dc=example,dc=com',
      controls: [],
      memberOf: 'cn=group1,cn=group,dc=example,dc=com',
      uid: 'user1',
      mail: 'user1@example',
      displayName: 'User One'
    })
  });
});

// Note: the mock ldap server does not check password, so any password will work.
// The best we can do for testing is use a user not in the database.
describe("test invalid user", () => {
  test("should return invalid user", async () => {
    try {
      await ut.authenticate('user3', 'password3', settings);
    } catch (e) {
      expect(e).toBeDefined();
    }
  });
})