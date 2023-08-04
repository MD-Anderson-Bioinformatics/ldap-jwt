const logger = require('./logger');

/*
* Function to remove confidential keys from the object
* Designed to be used in JSON.stringify
*/
function hideSecrets(key, value) {
	if (key === 'bindCredentials' || key === 'password') {
		return "********";
	}
	return value;
}

module.exports = {
	hideSecrets: hideSecrets,
}
