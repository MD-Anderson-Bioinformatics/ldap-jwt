"use strict";
const logger = require('../logger');
const request = require('supertest');
const app = require('../index');
const e = require('express');

const baseUrlPath = '/ldap-jwt';

describe('GET /health', () => {
  test('health test', async() => {
    const res = await request(app).get(baseUrlPath + '/health');
    expect(res.statusCode).toEqual(200);
  });
});

describe('POST /authenticate and /verify', () => {

  test('valid user no groups', async() => {
    let res = await request(app).post(baseUrlPath + '/authenticate').send({
      username: 'user1',
      password: 'password1'
    });
    expect(res.statusCode).toEqual(200); // valid user, so authenticate should pass
    let token = res.body.token;
    res = await request(app).post(baseUrlPath + '/verify').send({
      token: token
    });
    expect(res.statusCode).toEqual(200); // valid token, so verify should pass
  });

  test('invalid user', async() => {
    let res = await request(app).post(baseUrlPath + '/authenticate').send({
      username: 'user-not-in-database',
      password: 'password3'
    });
    expect(res.statusCode).toEqual(401); // invalid user, so authenticate should fail
    let token = res.body.token;
    expect(token).toBeUndefined(); // invalid user, so no token returned
    res = await request(app).post(baseUrlPath + '/verify').send({
      token: token
    });
    expect(res.statusCode).toEqual(400); // no token supplied
  });

  // see mock-server.js for user's group membership

  test('no group in token', async() => {
    let res = await request(app).post(baseUrlPath + '/authenticate').send({
      username: 'user1',
      password: 'password1'
    });
    expect(res.statusCode).toEqual(200);
    let token = res.body.token;
    res = await request(app).post(baseUrlPath + '/verify').send({
      token: token,
      authorized_groups: 'cn=group1,dc=group,dc=example,dc=com'
    });
    expect(res.statusCode).toEqual(401); // user1 in group1, but no group in token, so this verify should fail
  });

  test('token for right and wrong group', async() => {
    let res = await request(app).post(baseUrlPath + '/authenticate').send({
      username: 'user1',
      password: 'password1',
      authorized_groups: 'cn=group1,dc=group,dc=example,dc=com'
    });
    expect(res.statusCode).toEqual(200); // user1 is in group 1, so authenticate should pass
    let token = res.body.token;
    res = await request(app).post(baseUrlPath + '/verify').send({
      token: token,
      authorized_groups: 'cn=group1,dc=group,dc=example,dc=com'
    });
    expect(res.statusCode).toEqual(200); // user1 in group1 and token encodes group1, so this verify should pass
    res = await request(app).post(baseUrlPath + '/verify').send({
      token: token,
      authorized_groups: 'cn=group2,dc=group,dc=example,dc=com'
    });
    expect(res.statusCode).toEqual(401); // user1 not in group2, so this verify should fail
    res = await request(app).post(baseUrlPath + '/verify').send({
      token: token,
      authorized_groups: 'cn=groupA,dc=group,dc=example,dc=com'
    });
    expect(res.statusCode).toEqual(401); // user1 in groupA, but token does not encode groupA, so this verify should fail
  });

  test('User not in group', async() => {
    let res = await request(app).post(baseUrlPath + '/authenticate').send({
      username: 'user1',
      password: 'password1',
      authorized_groups: 'cn=group2,dc=group,dc=example,dc=com'
    });
    expect(res.statusCode).toEqual(401); // user1 is not in group2
    let token = res.body.token;
    expect(token).toBeUndefined(); // so no token returned
  });

  test('token for right and wrong groups variation', async() => {
    let res = await request(app).post(baseUrlPath + '/authenticate').send({
      username: 'user1',
      password: 'password1',
      authorized_groups: [
        'cn=group1,dc=group,dc=example,dc=com',
        'cn=groupA,dc=group,dc=example,dc=com',
        'cn=group2,dc=group,dc=example,dc=com'
      ]
    });
    expect(res.statusCode).toEqual(200); // user1 in group1 and groupA, so authenticate should pass
    let token = res.body.token;
    res = await request(app).post(baseUrlPath + '/verify').send({
      token: token,
      authorized_groups: [
        'cn=group1,dc=group,dc=example,dc=com',
        'cn=groupA,dc=group,dc=example,dc=com',
        'cn=group2,dc=group,dc=example,dc=com'
      ]
    });
    expect(res.statusCode).toEqual(200); // user1 in group1 and groupA, so this verify should pass
    res = await request(app).post(baseUrlPath + '/verify').send({
      token: token,
      authorized_groups: 'cn=group2,dc=group,dc=example,dc=com'
    });
    expect(res.statusCode).toEqual(401); // user1 not in group2, so this verify should fail
    res = await request(app).post(baseUrlPath + '/verify').send({
      token: token,
      authorized_groups: 'cn=groupB,dc=group,dc=example,dc=com'
    });
    expect(res.statusCode).toEqual(401); // user1 not in groupB, and token does not encode groupB, so this verify should fail
  });
});

afterAll(async () => {
  await app.close();
})
