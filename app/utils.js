const logger = require('./logger');
var LdapAuth = require('ldapauth-fork');

/*
* Function to remove confidential keys from the object
* Designed to be used in JSON.stringify
*
* Also removes the logger object, because it causes a circular reference
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

/*
* Function to get the CN from the groups
*
* LDAP groups have long distinguished names (DN).
* The CN is the first part of the DN, e.g. CN=group1,OU=groups,DC=example,DC=com
*
* @param groups - string or array of strings
* @return string or array of strings
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
