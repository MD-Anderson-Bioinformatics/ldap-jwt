const logger = require('./logger');
var LdapAuth = require('ldapauth-fork');

/**
 * Replaces sensitive information and logger objects in a given key-value pair with placeholder strings.
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
 * @param {string|string[]} groups - A single group string or an array of group strings.
 * Each string should be in the format 'CN=GroupName,OU=OrgUnit,...'.
 * @returns {string|string[]} The CN of the group(s). If `groups` is a string, returns a single CN string.
 * If `groups` is an array, returns an array of CN strings. If an error occurs during extraction,
 * returns the original `groups` value.
 * @throws Will log an error if an exception occurs during CN extraction.
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
 * Authenticates a user with given username and password.
 *
 * @async
 * @param {string} username - The username of the user.
 * @param {string} password - The password of the user.
 * @param {Object} settings - The settings for the authentication.
 * @returns {Promise<Object>} A promise that resolves with the authenticated user object if authentication is successful, or rejects with an error if authentication fails.
 * @throws Will reject if an error occurs during authentication or if no user is found.
 */
async function authenticate (username, password, settings) {
	let auth = await bind(username, password, settings);
	logger.debug("Authenticating user: " + username);
	return new Promise(function (resolve, reject) {
		logger.debug("In authenticate promise");
		auth.authenticate(username, password, async function (err, user) {
			await unbind(auth, settings);
			if(err) {
				logger.debug("ERROR: Reject because of err: ", err);
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
 * Binds a user with given username and password to the LDAP server.
 *
 * @private
 * @async
 * @param {string} username - The username of the user.
 * @param {string} password - The password of the user.
 * @param {Object} settings - The settings for the LDAP server and binding options.
 * @returns {Promise<Object>} A promise that resolves with the LDAPAuth object if binding is successful, or rejects if an error occurs during binding.
 * @throws Will reject if an error occurs during binding.
 */
let bind = async function (username, password, settings) {
	return new Promise(function (resolve, reject) {
		try {
			let settingsForBind = structuredClone(settings.ldap); // structuredClone to avoid changing the original settings
			settingsForBind.log = logger; // adding bunyan logger to LdapAuth settings
			if (settings.ldap.bindAsUser) {
				logger.debug("Binding as user");
				settingsForBind.bindCredentials = password;
				settingsForBind.bindDn = settings.ldap.binddn_prefix + username + settings.ldap.binddn_suffix;
			} else {
				logger.debug("Binding as service account");
				settingsForBind.bindCredentials = settings.ldap.bindCredentials;
				settingsForBind.bindDn = settings.ldap.bindDn;
			}
			logger.debug("Creating new bind with settings: " + JSON.stringify(settingsForBind, hideSecretsAndLogger, 2));
			let auth = new LdapAuth(settingsForBind);
			logger.debug("New bind created");
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
 * @throws Will reject if an error occurs during unbinding.
 */
let unbind = async function (auth, settings) {
	return new Promise(function (resolve, reject) {
		try {
			logger.debug("Unbinding")
			logger.debug("Original settings: " + JSON.stringify(settings.ldap, hideSecretsAndLogger, 2));
			auth.close();
			resolve();
		} catch (err) {
			logger.error("Error unbinding: ", err);
			reject();
		}
	})
}

module.exports = {
	authenticate: authenticate,
	getGroupCN: getGroupCN,
	hideSecretsAndLogger: hideSecretsAndLogger
}
