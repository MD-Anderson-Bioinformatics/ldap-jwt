const logger = require('./logger');

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

module.exports = {
	hideSecretsAndLogger: hideSecretsAndLogger,
	getGroupCN: getGroupCN
}
