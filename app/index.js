var settings = require('./config/config.json');
const ut = require('./utils');
const logger = require('./logger');

logger.debug("Node version: "+process.version);
logger.debug("Settings: " + JSON.stringify(settings, ut.hideSecretsAndLogger, 2));

var bodyParser = require('body-parser');
var jwt = require('jwt-simple');
var fs = require('fs'),
    express = require('express');

if (settings.ssl) {
	var https = require('https');
	if (!fs.existsSync("./ssl/server.key") || !fs.existsSync("./ssl/server.crt")) {
		logger.error("Missing required SSL certificates. Exiting.");
		process.exit(1);
	}
} else {
	var http = require('http');
}

if (process.env.BASE_URL_PATH === undefined) {
	logger.warn("BASE_URL_PATH environment variable not set. Using default 'ldap-jwt'.");
	process.env.BASE_URL_PATH = "ldap-jwt";
}
const baseUrlPath = "/" + process.env.BASE_URL_PATH;

app = require('express')();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(require('cors')());

if (process.env.BUILD_TARGET === 'dev') {
	logger.info("Starting mock LDAP server because BUILD_TARGET is dev");
	const mockserver = require('./mock-server');
	mockserver.startServer();
}

if (settings.hasOwnProperty( 'ldap' ) && settings.hasOwnProperty( 'jwt' )) {
	if (!settings.ldap.hasOwnProperty('bindDn')) {
		settings.ldap.bindAsUser = true;
	}
	logger.debug("LdapAuth settings: " + JSON.stringify(settings.ldap, ut.hideSecretsAndLogger, 2));
} else {
	logger.error("LDAP and JWT settings are required. Exiting.");
	process.exit(1);
}

if (settings.hasOwnProperty( 'jwt' )) {
	if (!settings.jwt.hasOwnProperty('timeout')) {
		settings.jwt.timeout = 1;
		logger.warn("Settings.jwt.timeout not set - using default: " + settings.jwt.timeout);
	}
	if (!settings.jwt.hasOwnProperty('timeout_units')) {
		settings.jwt.timeout_units = 'hour';
		logger.warn("Settings.jwt.timeout_units not set - using default: " + settings.jwt.timeout_units);
	}
	app.set('jwtTokenSecret',
		settings.jwt.base64 ? new Buffer(settings.jwt.secret, 'base64') : settings.jwt.secret);
}

app.post(baseUrlPath + '/authenticate', function (req, res) {
	if(!req.body.username || !req.body.password) {
		logger.warn("No username or password supplied in request");
		res.status(400).send({error: 'No username or password supplied'});
		return false;
	}
	ut.authenticateHandler(req.body.username, req.body.password, settings, req.body.authorized_groups)
		.then(function (authResponse) {
			res.status(authResponse.httpStatus).send({
				token: authResponse.token,
				full_name: authResponse.full_name,
				mail: authResponse.mail
			});
		})
		.catch(function (err) {
			res.status(err.httpStatus).send({error: err.message});
		});
});

app.post(baseUrlPath + '/verify', function (req, res) {
	if (!req.body.token) {
		logger.warn("No token supplied in request");
		res.status(400).send({error: 'No token supplied'});
		return false;
	}
	if (!settings.hasOwnProperty( 'jwt' )) {
		logger.error("JWT settings not found!");
		res.status(500).send({error: 'Server error'});
		return false;
	}
	let validation = ut.verifyHandler(req.body.token, req.body.authorized_groups);
	if (validation.httpStatus == 200) {
		res.status(200).send(validation.decodedToken);
	} else {
		res.status(validation.httpStatus).send({error: validation.message});
	}
});

app.get(baseUrlPath + '/health', function (req, res) {
	res.status(200).send({message: 'OK'});
});

var port = (process.env.PORT || 3000);

if (settings.ssl) { // use httpS
	var options = {
	    key:  fs.readFileSync("./ssl/server.key"),
	    cert: fs.readFileSync("./ssl/server.crt"),
	};
	var server = https.createServer(options,app).listen(port,function(){
		logger.info("Server running. Base URL: https://localhost:" + port + baseUrlPath);
		logger.info('JWT tokens will expire after ' + settings.jwt.timeout + ' ' + settings.jwt.timeout_units);
		logger.info("LDAP URL: " + settings.ldap.url);
		if (settings.ldap.bindAsUser) {
			logger.info("Will bind with authenticating user's credentials");
		} else {
			logger.info("Will bind with service account: " + ut.getGroupCN(settings.ldap.bindDn));
		}
		app.on("error",(err) => {
			logger.error("ERROR: " + err.stack);
		});
	});
} else { // use http
	var server = http.createServer(app).listen(port,function(){
		logger.info("Server running. Base URL: http://localhost:" + port + baseUrlPath);
		logger.info('JWT tokens will expire after ' + settings.jwt.timeout + ' ' + settings.jwt.timeout_units);
		logger.info("LDAP URL: " + settings.ldap.url);
		if (settings.ldap.bindAsUser) {
			logger.info("Will bind with authenticating user's credentials");
		} else {
			logger.info("Will bind with service account: " + settings.ldap.bindDn);
		}
		logger.warn("Server configured for http (not httpS).");
		app.on("error",(err) => {
			logger.error("ERROR: " + err.stack);
		});
	});
}

// export server for testing
module.exports = server;