const logger = require("./logger");
const { Client, InvalidCredentialsError } = require("ldapts");
var moment = require("moment");
var jwt = require("jwt-simple");

/**
 * Authenticates a user and if user is authenticated, generates a token
 *
 * @async
 * @param {string} username - The username of the user.
 * @param {string} password - The password of the user.
 * @param {Object} settings - The settings for the authentication.
 * @param {Array} authorized_groups - The groups that are authorized to authenticate.
 * @returns {Promise<Object>} A promise that resolves to an object containing the approriate HTTP response code,
 * token and user information if the user is authenticated, or rejects with an error message and HTTP status code
 * if the user is not authenticated or an error occurs.
 */
async function authenticateHandler(username, password, settings, authorized_groups) {
  // First handle credentials and reject if invalid
  try {
    var user = await authenticateWithLdap(username, password, settings);
  } catch (err) {
    return new Promise(function (resolve, reject) {
      if (
        err.name === "InvalidCredentialsError" ||
        (typeof err === "string" && err.match(/no such user/i))
      ) {
        logger.warn("InvalidCredentialsError for '" + username + "'");
        reject({ httpStatus: 401, message: "Wrong username or password" });
        return;
      } else {
        logger.error("Error from authenticate promise: ", err);
        reject({ httpStatus: 500, message: "Sorry about that! Unexpected Error." });
        return;
      }
    });
  }
  // Then handle authorized_groups and generate token
  return new Promise(function (resolve, reject) {
    try {
      if (authorized_groups != undefined) {
        logger.debug("authorized_groups specified: " + authorized_groups);
        if (!user.hasOwnProperty("memberOf")) {
          logger.error("Server not configured for authorized_group verification");
          reject({ httpStatus: 500, message: "Unexpected error. Sorry about that!" });
          return;
        }
        var userGroupsForPayload = userGroupAuthGroupIntersection(user.memberOf, authorized_groups);
        if (!userInAuthorizedGroups(user.memberOf, authorized_groups)) {
          logger.warn(user.displayName + "' not in '" + getGroupCN(authorized_groups) + "'");
          reject({ httpStatus: 401, message: "User is not authorized" });
          return;
        }
      }
      let token = generateToken(user, settings, userGroupsForPayload);
      resolve({ httpStatus: 200, token: token, full_name: user.displayName, mail: user.mail });
    } catch (err) {
      if (err == "Server not configured for authorized_group verification") {
        logger.warn(
          "Request included authorized_groups, but server not configured for authorized_group verification"
        );
        reject({ httpStatus: 401, message: "User is not authorized" });
        return;
      } else if (err == "User not in authorized_groups") {
        reject({ httpStatus: 401, message: "User is not authorized" });
        return;
      } else {
        logger.error("Error from authenticate promise: ", err);
        reject({ httpStatus: 500, message: "Unexpected Error. Sorry about that!" });
        return;
      }
    }
  });
}
/**
 * Verifies a JWT token. If authorized_groups supplied, verfication includes checking if token includes the authorized_groups.
 *
 * @param {string} token - The JWT token to verify.
 * @param {Array} authorized_groups - The groups that are authorized to authenticate.
 * @returns {Object} An object containing the HTTP status and either the decoded token if the verification was
 * successful or an error message if it was not.
 */
function verifyHandler(token, authorized_groups) {
  // first try/catch is for decoding the token
  try {
    var decodedToken = jwt.decode(token, app.get("jwtTokenSecret"));
    var groupsInToken = decodedToken.user_authorized_groups;
    var usernameInToken = decodedToken.user_name;
  } catch (err) {
    logger.warn("Error decoding token: " + err);
    return { httpStatus: 401, message: "User is not authorized" };
  }
  // second try/catch is for verifying token is valid
  try {
    if (decodedToken.exp <= Date.now()) {
      logger.warn("Verification failed: expired token for '" + usernameInToken + "'");
      return { httpStatus: 400, message: "Access token has expired" };
    } else if (authorized_groups != undefined) {
      if (groupsInToken && userInAuthorizedGroups(groupsInToken, authorized_groups)) {
        logger.info("Token valid for '" + usernameInToken + "', " + "requested groups: '" + getGroupCN(authorized_groups)
            + "', token groups: '" + getGroupCN(groupsInToken) + "'");
        return { httpStatus: 200, decodedToken: decodedToken };
      } else {
        logger.warn("Invalid token: token/authorized group mismatch for user '" +
            usernameInToken + "', requested groups: '" + getGroupCN(authorized_groups) +
            "', token groups: '" + getGroupCN(groupsInToken) + "'");
        return { httpStatus: 401, message: "User is not authorized" };
      }
    } else {
      logger.info("Token verified for '" + usernameInToken + "'");
      return { httpStatus: 200, decodedToken: decodedToken };
    }
  } catch (err) {
    logger.warn("Verification failed: " + err);
    return { httpStatus: 500, message: "Sever error. Unable to validate token" };
  }
}

/**
 * Replaces sensitive information and logger objects in a given key-value pair with placeholder strings.
 *
 * This function was written to bue used as the replacer function for JSON.stringify to avoid logging sensitive
 * data and circular references.
 *
 * @param {string} key - The key of the key-value pair.
 * @param {*} value - The value of the key-value pair.
 * @returns {*} If the key is 'bindCredentials' or 'password', returns a string of asterisks.
 * If the key is 'log' or 'logger', returns a placeholder string (because these cause a circular reference.
 * Otherwise, returns the original value.
 */
function hideSecretsAndLogger(key, value) {
  if (key === "bindCredentials" || key === "password") {
    return "********";
  }
  if (key === "log" || key === "logger") {
    return "<log object (hidden because it creates circular reference)>";
  }
  return value;
}

/**
 * Extracts the Common Name (CN) from a group or a list of groups.
 *
 * @private
 * @param {string|string[]} groups - A single group string or an array of group strings.
 * Each string should be in the format 'CN=GroupName,OU=OrgUnit,...'.
 * @returns {string|string[]} The CN of the group(s). If `groups` is a string, returns a single CN string.
 * If `groups` is an array, returns an array of CN strings. If an error occurs during extraction,
 * returns the original `groups` value.
 */
function getGroupCN(groups) {
  if (groups == undefined) {
    return undefined;
  }
  try {
    if (typeof groups === "string") {
      return getCommonName(groups);
    } else {
      return groups.map(function (group) {
        return getCommonName(group);
      });
    }
  } catch (e) {
    logger.error('Error getting CN from "' + groups + '": ' + e);
    return groups;
  }
}

/**
 * Authenticates a user against the LDAP server by binding with search credentials or service account,
 * searching for the user, and verifying the password with a second bind.
 *
 * @async
 * @private
 * @param {string} username - The username of the user.
 * @param {string} password - The password of the user.
 * @param {Object} settings - The settings for the authentication.
 * @returns {Promise<Object>} A promise that resolves with the authenticated user object if authentication is successful,
 * or rejects with an error if authentication fails.
 */
async function authenticateWithLdap(username, password, settings) {
  const ldapSettings = settings.ldap;
  logger.debug(`ldapSettings: ${JSON.stringify(ldapSettings, hideSecretsAndLogger, 4)}`);
  let authenticateName = username;
  if (isDistinguishedName(username)) { // typically, the LDAP search filter prevents authenticating with DN
    authenticateName = getCommonName(username);
  }

  // Determine search bind credentials (wither user or a service accoint
  let searchBindDn, searchBindCredentials;
  if (ldapSettings.bindAsUser) { // user
    searchBindCredentials = password;
    if (isDistinguishedName(username)) {
      searchBindDn = username;
    } else {
      searchBindDn = ldapSettings.binddn_prefix + username + ldapSettings.binddn_suffix;
    }
    let loggableSettings = structuredClone(ldapSettings);
    loggableSettings.bindDn = searchBindDn;
    loggableSettings.bindCredentials = password;
    logger.debug("Binding info: " + JSON.stringify(loggableSettings, hideSecretsAndLogger, 4));
  } else { // service account
    searchBindDn = ldapSettings.bindDn;
    searchBindCredentials = ldapSettings.bindCredentials;
  }

  const clientOpts = { url: ldapSettings.url };
  if (ldapSettings.timeout !== undefined) clientOpts.timeout = ldapSettings.timeout;
  if (ldapSettings.connectTimeout !== undefined) clientOpts.connectTimeout = ldapSettings.connectTimeout;
  if (ldapSettings.tlsOptions !== undefined) clientOpts.tlsOptions = ldapSettings.tlsOptions;

  // Step 1: Bind and search for user to get DN and attributes
  logger.debug(`clientOpts: ${JSON.stringify(clientOpts, hideSecretsAndLogger, 4)}`);
  const searchClient = new Client(clientOpts);
  let userEntry;
  try {
    await searchClient.bind(searchBindDn, searchBindCredentials);
    const searchFilter = ldapSettings.searchFilter.replace(/\{\{username\}\}/g, authenticateName);
    logger.debug(`searchFilter: ${searchFilter}`);
    const { searchEntries } = await searchClient.search(ldapSettings.searchBase, {
      filter: searchFilter,
      scope: 'sub',
    });
    if (searchEntries.length === 0) {
      throw "no such user";
    }
    userEntry = searchEntries[0];
  } catch (err) {
    if (err instanceof InvalidCredentialsError && !ldapSettings.bindAsUser) {
      logger.error("Invalid credentials for service account: '" + searchBindDn + "'");
    }
    throw err;
  } finally {
    try { await searchClient.unbind(); } catch (_) {}
  }

  // Step 2: Verify password by binding as the found user
  const verifyClient = new Client(clientOpts);
  try {
    await verifyClient.bind(userEntry.dn, password);
  } finally {
    try { await verifyClient.unbind(); } catch (_) {}
  }

  return userEntry;
}

/**
 * Generates a JWT token for a given user.
 *
 * @private
 * @param {Object} user - The user for whom to generate the token.
 * The user object should have `uid`,`displayName`, and `mail` properties.
 * @param {Object} settings - The settings for the JWT token.
 * The settings object should have a `jwt` property that is an object with `timeout`, `timeout_units`, and `clientid` properties.
 * @param {string|string[]} userGroupsForPayload - A single user group string or an array of user group strings to include
 * in the token payload. If undefined, then the token will not include user groups.
 * @returns {string} The generated JWT token.
 * @throws Will throw an error if the token cannot be generated.
 */
let generateToken = function (user, settings, userGroupsForPayload) {
  try {
    let expires = moment().add(settings.jwt.timeout, settings.jwt.timeout_units).valueOf();
    let token_json = {
      exp: expires,
      aud: settings.jwt.clientid,
      user_name: user.uid,
      full_name: user.displayName,
      mail: user.mail
    };
    if (userGroupsForPayload != undefined) {
      token_json.user_authorized_groups = userGroupsForPayload;
    }
    let token = jwt.encode(token_json, app.get("jwtTokenSecret"));
    if (userGroupsForPayload != undefined) {
      logger.info("Token generated for '" + user.displayName + "' with groups '" +
          getGroupCN(userGroupsForPayload).join("; ") + "'." + " JWT expires: " +
          moment(expires).format("MMMM Do YYYY, h:mm:ss a"));
    } else {
      logger.info("Token generated for '" + user.displayName + "'." + " JWT expires: " +
          moment(expires).format("MMMM Do YYYY, h:mm:ss a"));
    }
    return token;
  } catch (err) {
    logger.error("Error generating token: ", err);
    throw "Unable to generate token";
  }
};

/**
 * Returns an array that represents the intersection of user groups and authorized groups.
 *
 * @private
 * @param {string|string[]} userGroups - A single user group string or an array of user group strings.
 * @param {string|string[]} authorized_groups - A single authorized group string or an array of authorized group strings.
 * @returns {string[]} An array of strings that are present in both `userGroups` and `authorized_groups`.
 * If either parameter is not an array, it is converted to a single-element array before the intersection is computed.
 * @throws {string} Will throw a string error message if unable to determine the intersection.
 */
let userGroupAuthGroupIntersection = function (userGroups, authorized_groups) {
  try {
    if (!Array.isArray(userGroups)) userGroups = [userGroups];
    if (!Array.isArray(authorized_groups)) authorized_groups = [authorized_groups];
    let userGroupsIntersection = userGroups.filter((group) => authorized_groups.includes(group));
    return userGroupsIntersection;
  } catch (err) {
    logger.error("Error in userGroupAuthGroupIntersection: ", err);
    throw "Unable to determine userGroupsAuthGroupIntersection";
  }
};

/**
 * Checks if a user is part of any of the authorized groups.
 *
 * @private
 * @param {(Array|string)} userGroups - The groups that the user is a part of. Can be a single group (string) or
 * multiple groups (array).
 * @param {(Array|string)} authorized_groups - The groups that are authorized. Can be a single group (string) or
 * multiple groups (array).
 * @returns {boolean} Returns true if the user is part of any of the authorized groups, false otherwise.
 * @throws {string} Throws an error message if an error occurs during the process.
 */
let userInAuthorizedGroups = function (userGroups, authorized_groups) {
  try {
    if (!Array.isArray(userGroups)) userGroups = [userGroups];
    if (!Array.isArray(authorized_groups)) authorized_groups = [authorized_groups];
    return userGroups.some((group) => authorized_groups.includes(group));
  } catch (err) {
    logger.error("Error in userInAuthorizedGroups: ", err);
    throw "Unable to determine if user in authorized groups";
  }
};

/**
 * Checks if the given username is a Distinguished Name (DN) according to RFC 2253.
 *
 * A Distinguished Name is a string composed of key=value pairs separated by commas,
 * such as "CN=JohnDoe,OU=Users,DC=example,DC=com".
 *
 * @private
 * @param {string} username - The username to check.
 * @returns {boolean} - Returns true if the username matches the RFC 2253 DN format, otherwise false.
 */
let isDistinguishedName = function (username) {
  const rfc2253Regex = /^([a-zA-Z]+=[^,]+,)*[a-zA-Z]+=[^,]+$/; // e.g. CN=JohnDoe,OU=Users,DC=example,DC=com
  if (username.match(rfc2253Regex)) {
    return true;
  }
  return false;
}

/**
 * Extracts the Common Name (CN) from a Distinguished Name (DN).
 *
 * A Distinguished Name is a string composed of key=value pairs separated by commas,
 * such as "CN=JohnDoe,OU=Users,DC=example,DC=com". This function extracts the value
 * associated with the "CN" key.
 *
 * @private
 * @param {string} dn - The Distinguished Name (DN) from which to extract the Common Name (CN).
 * @returns {string} - The extracted Common Name (CN).
 */
let getCommonName = function (dn) {
  return dn.split(",")[0].split("=")[1];
}

module.exports = {
  authenticateHandler: authenticateHandler,
  verifyHandler: verifyHandler,
  hideSecretsAndLogger: hideSecretsAndLogger
};
