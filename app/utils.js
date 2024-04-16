const logger = require('./logger');
var LdapAuth = require('ldapauth-fork');
var moment = require('moment');
var jwt = require('jwt-simple');

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
		var user = await queryAuthentication(username, password, settings)
	} catch(err) {
		return new Promise(function (resolve, reject) {
			if (err.name === 'InvalidCredentialsError' || (typeof err === 'string' && err.match(/no such user/i)) ) {
				logger.warn("InvalidCredentialsError for '" + username + "'");
				reject({httpStatus: 401, message: 'Wrong username or password'});
			} else {
				logger.error("Error from authenticate promise: ", err);
				reject({httpStatus: 500, message: 'Sorry about that! Unexpected Error.'});
			}
		})
	}
	// Then handle authorized_groups and generate token
	return new Promise(function (resolve, reject) {
		try {
			if (authorized_groups != undefined) {
				logger.debug("authorized_groups specified: " + authorized_groups);
				if (!user.hasOwnProperty("memberOf")) {
					logger.error("Server not configured for authorized_group verification");
					reject({httpStatus: 500, message: 'Unexpected error. Sorry about that!'});
				}
				var userGroupsForPayload = userGroupAuthGroupIntersection(user.memberOf, authorized_groups);
				if (!userInAuthorizedGroups(user.memberOf, authorized_groups)) {
					logger.warn(user.displayName + "' not in '" + getGroupCN(authorized_groups) + "'");
					reject({httpStatus: 401, message: "User is not authorized"});
				}
			}
			let token = generateToken(user, settings, userGroupsForPayload);
			resolve ({httpStatus: 200, token: token, full_name: user.displayName, mail: user.mail});
		} catch (err) {
			if (err == "Server not configured for authorized_group verification") {
				logger.warn("Request included authorized_groups, but server not configured for authorized_group verification");
				reject({httpStatus: 401, message: "User is not authorized"});
			} else if (err == "User not in authorized_groups") {
				reject({httpStatus: 401, message: "User is not authorized"});
			} else {
				logger.error("Error from authenticate promise: ", err);
				reject({httpStatus: 500, message: 'Unexpected Error. Sorry about that!'});
			}
		}
	})
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
		var decodedToken = jwt.decode(token, app.get('jwtTokenSecret'));
		var groupsInToken = decodedToken.user_authorized_groups;
		var usernameInToken = decodedToken.user_name;
	} catch (err) {
		logger.warn("Error decoding token: " + err);
		return({httpStatus: 401, message: 'User is not authorized'});
	}
	// second try/catch is for verifying token is valid
	try {
		if (decodedToken.exp <= Date.now()) {
			logger.warn("Verification failed: expired token for '" + usernameInToken + "'");
			return({httpStatus: 400, message: 'Access token has expired'});
		} else if (authorized_groups != undefined) {
			if (groupsInToken && userInAuthorizedGroups(groupsInToken, authorized_groups)) {
				logger.info("Token valid for '" + usernameInToken + "', " +
					"requested groups: '" + getGroupCN(authorized_groups) +
					"', token groups: '" + getGroupCN(groupsInToken) + "'");
				return({httpStatus: 200, decodedToken: decodedToken});
			} else {
				logger.warn("Invalid token: token/authorized group mismatch for user '" +
					usernameInToken + "', requested groups: '" + getGroupCN(authorized_groups) +
					"', token groups: '" + getGroupCN(groupsInToken) + "'");
				return({httpStatus: 401, message: 'User is not authorized'});
			}
		} else {
			logger.info("Token verified for '" + usernameInToken + "'");
			return({httpStatus: 200, decodedToken: decodedToken});
		}
	} catch (err) {
		logger.warn("Verification failed: " + err);
		return({httpStatus: 500, message: "Sever error. Unable to validate token"});
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
	if (key === 'bindCredentials' || key === 'password') {
		return "********";
	}
	if (key === 'log' || key === 'logger') {
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
		if (typeof groups === 'string') {
			return groups.split(',')[0].split('=')[1];
		} else {
			return groups.map(function (group) {
				return group.split(',')[0].split('=')[1];
			})
		}
	} catch (e) {
		logger.error('Error getting CN from "' + groups + '": ' + e);
		return groups;
	}
}

/**
 * Queries auth.authenticate for a user with given username and password.
 *
 * @async
 * @private
 * @param {string} username - The username of the user.
 * @param {string} password - The password of the user.
 * @param {Object} settings - The settings for the authentication.
 * @returns {Promise<Object>} A promise that resolves with the authenticated user object if authentication is successful,
 * or rejects with an error if authentication fails.
 */
async function queryAuthentication(username, password, settings) {
	let auth = await bind(username, password, settings);
	return new Promise(function (resolve, reject) {
		auth.authenticate(username, password, async function (err, user) {
			await unbind(auth, settings);
			if(err) {
				logger.warn("Authentication error: ", err);
				reject(err);
			} else if (!user) {
				logger.debug("ERROR: Reject because no user");
				reject();
			} else {
				resolve(user);
			}
		});
	});
};

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
		}
		if (userGroupsForPayload != undefined) {
			token_json.user_authorized_groups = userGroupsForPayload;
		}
		let token = jwt.encode(token_json, app.get('jwtTokenSecret'));
		if (userGroupsForPayload != undefined) {
			logger.info("Token generated for '" + user.displayName + "' with groups '" +
				getGroupCN(userGroupsForPayload).join("; ") + "'." +
				" JWT expires: " + moment(expires).format("MMMM Do YYYY, h:mm:ss a"));
		} else {
			logger.info("Token generated for '" + user.displayName + "'." +
				" JWT expires: " + moment(expires).format("MMMM Do YYYY, h:mm:ss a"));
		}
		return token;
	} catch (err) {
		logger.error("Error generating token: ", err);
		throw "Unable to generate token";
	}
}

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
let userGroupAuthGroupIntersection = function(userGroups, authorized_groups) {
	try {
		if (!Array.isArray(userGroups)) userGroups = [ userGroups ];
		if (!Array.isArray(authorized_groups)) authorized_groups = [ authorized_groups ];
		let userGroupsIntersection = userGroups.filter(group => authorized_groups.includes(group));
		return userGroupsIntersection;
	} catch (err) {
		logger.error("Error in userGroupAuthGroupIntersection: ", err);
		throw "Unable to determine userGroupsAuthGroupIntersection";
	}
}

/**
 * Binds a user with given username and password to the LDAP server.
 *
 * @private
 * @async
 * @param {string} username - The username of the user.
 * @param {string} password - The password of the user.
 * @param {Object} settings - The settings for the LDAP server and binding options.
 * @returns {Promise<Object>} A promise that resolves with the LDAPAuth object if binding is successful, or rejects
 * if an error occurs during binding.
 */
let bind = async function (username, password, settings) {
	return new Promise(function (resolve, reject) {
		try {
			let settingsForBind = structuredClone(settings.ldap); // structuredClone to avoid changing the original settings
			settingsForBind.log = logger; // adding bunyan logger to LdapAuth settings
			if (settings.ldap.bindAsUser) {
				settingsForBind.bindCredentials = password;
				settingsForBind.bindDn = settings.ldap.binddn_prefix + username + settings.ldap.binddn_suffix;
				logger.debug("Binding info: " + JSON.stringify(settingsForBind, hideSecretsAndLogger, 4));
			} else {
				settingsForBind.bindCredentials = settings.ldap.bindCredentials;
				settingsForBind.bindDn = settings.ldap.bindDn;
			}
			let auth = new LdapAuth(settingsForBind);
			resolve(auth);
		} catch (err) {
			logger.error("Error creating new bind: ", err);
			reject();
		}
	})
}

/**
 * Unbinds a user from the LDAP server.
 *
 * @private
 * @async
 * @param {Object} auth - The LDAPAuth object representing the authenticated user.
 * @param {Object} settings - The settings for the LDAP server and unbinding options.
 * @returns {Promise<void>} A promise that resolves if unbinding is successful, or rejects if an error occurs during unbinding.
 */
let unbind = async function (auth, settings) {
	return new Promise(function (resolve, reject) {
		try {
			auth.close();
			resolve();
		} catch (err) {
			logger.error("Error unbinding: ", err);
			reject();
		}
	})
}

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
let userInAuthorizedGroups = function(userGroups, authorized_groups) {
	try {
		if (!Array.isArray(userGroups)) userGroups = [ userGroups ];
		if (!Array.isArray(authorized_groups)) authorized_groups = [ authorized_groups ];
		return userGroups.some(group => authorized_groups.includes(group));
	} catch (err) {
		logger.error("Error in userInAuthorizedGroups: ", err);
		throw "Unable to determine if user in authorized groups";
	}
}

module.exports = {
	authenticateHandler: authenticateHandler,
	verifyHandler: verifyHandler,
	hideSecretsAndLogger: hideSecretsAndLogger
}
