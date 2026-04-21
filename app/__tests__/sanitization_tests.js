"use strict";

describe('Testing sanitization', () => {
  const { _test } = require('../utils');
  test('escapeLdapDnValue test', () => {
    // Enumerate replacement cases in function
    expect(_test.escapeLdapDnValue('john\\doe')).toEqual('john\\\\doe');
    expect(_test.escapeLdapDnValue('john,=+<>#;"doe')).toEqual('john\\,\\=\\+\\<\\>\\#\\;\\"doe');
    expect(_test.escapeLdapDnValue('#johndoe')).toEqual('\\#johndoe');
    expect(_test.escapeLdapDnValue(' john,doe ')).toEqual('\\ john\\,doe\\ ');
    expect(_test.escapeLdapDnValue('john\0doe')).toEqual('john\\00doe');
    // Backslash before a special char — ordering matters
    expect(_test.escapeLdapDnValue('john\\,doe')).toEqual('john\\\\\\,doe');
    // Some extras just as examples
    expect(_test.escapeLdapDnValue('john.doe')).toEqual('john.doe');
    expect(_test.escapeLdapDnValue('John Doe')).toEqual('John Doe');
    expect(_test.escapeLdapDnValue('zeta@example.com')).toEqual('zeta@example.com');
    expect(_test.escapeLdapDnValue('admin,dc=example,dc=com')).toEqual('admin\\,dc\\=example\\,dc\\=com');
  });
  test('escapeLdapFilterValue test', () => {
    // Enumerate replacement cases in function
    expect(_test.escapeLdapFilterValue('john\\doe')).toEqual('john\\5cdoe');
    expect(_test.escapeLdapFilterValue('john\0doe')).toEqual('john\\00doe');
    expect(_test.escapeLdapFilterValue('john*doe')).toEqual('john\\2adoe');
    expect(_test.escapeLdapFilterValue('john(doe')).toEqual('john\\28doe');
    expect(_test.escapeLdapFilterValue('john)doe')).toEqual('john\\29doe');
    // test backslash ordering
    expect(_test.escapeLdapFilterValue('john\\\0doe')).toEqual('john\\5c\\00doe');
    expect(_test.escapeLdapFilterValue('john\\*doe')).toEqual('john\\5c\\2adoe');
    expect(_test.escapeLdapFilterValue('john\\(doe')).toEqual('john\\5c\\28doe');
    expect(_test.escapeLdapFilterValue('john\\)doe')).toEqual('john\\5c\\29doe');
    // Some extras just as examples
    expect(_test.escapeLdapFilterValue('john.doe')).toEqual('john.doe');
    expect(_test.escapeLdapFilterValue('John Doe')).toEqual('John Doe');
    expect(_test.escapeLdapFilterValue('zeta@example.com')).toEqual('zeta@example.com');
    expect(_test.escapeLdapFilterValue('*)(|(uid=*)')).toEqual('\\2a\\29\\28|\\28uid=\\2a\\29');
  });
})

