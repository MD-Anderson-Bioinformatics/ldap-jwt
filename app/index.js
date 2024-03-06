var settings = require('./config/config.json');
const ut = require('./utils');
const logger = require('./logger');

logger.debug("Node version: "+process.version);
logger.debug("Settings: " + JSON.stringify(settings, ut.hideSecretsAndLogger, 2));

var bodyParser = require('body-parser');
var jwt = require('jwt-simple');
var moment = require('moment');
var LdapAuth = require('ldapauth-fork');
var Promise  = require('promise');
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



app.post('/ldap-jwt/authenticate', function (req, res) {
	if(req.body.username && req.body.password) {
		logger.debug(JSON.stringify(req.body, ut.hideSecretsAndLogger, 2));
		ut.authenticate(req.body.username, req.body.password, settings)
			.then(function(user) {
				logger.debug("User authenticated");
				if (req.body.authorized_groups != undefined) {
					logger.debug("authorized_groups specified: " + req.body.authorized_groups);
					if (!user.hasOwnProperty("memberOf")) {
						throw "Server not configured for authorized_group verification";
					}
					var userGroupsForPayload = userGroupAuthGroupIntersection(user.memberOf, req.body.authorized_groups);
					if (!userInAuthorizedGroups(user.memberOf, req.body.authorized_groups)) {
						throw "User not in authorized_groups";
					}
					logger.debug("userGroupsForPayload: " + userGroupsForPayload);
				}
				var expires = moment().add(settings.jwt.timeout, settings.jwt.timeout_units).valueOf();
				var token = jwt.encode({
					exp: expires,
					aud: settings.jwt.clientid,
					user_name: user.uid,
					full_name: user.displayName,
					mail: user.mail,
					user_authorized_groups: userGroupsForPayload
				}, app.get('jwtTokenSecret'));
				if (req.body.authorized_groups != undefined) {
					logger.info("Token generated for '" + req.body.username + "' with groups '" +
						ut.getGroupCN(userGroupsForPayload).join("; ") + "'." +
						" JWT expires: " + moment(expires).format("MMMM Do YYYY, h:mm:ss a"));
				} else {
					logger.info("Token generated for '" + req.body.username + "'." +
						" JWT expires: " + moment(expires).format("MMMM Do YYYY, h:mm:ss a"));
				}
				res.json({token: token, full_name: user.displayName, mail: user.mail});
			})
			.catch(function (err) {
				if (err.name === 'InvalidCredentialsError' || (typeof err === 'string' && err.match(/no such user/i)) ) {
					logger.warn("Token generation failed: InvalidCredentialsError for '" + req.body.username + "'");
					res.status(401).send({ error: 'Wrong username or password'});
				} else if (err == "Server not configured for authorized_group verification") {
					logger.warn("Request included authorized_groups, but server not configured for authorized_group verification");
					res.status(401).send({error: "User is not authorized"});
				} else if (err == "User not in authorized_groups") {
					logger.warn("Token generation failed: user '" + req.body.username + "' not in '" +
					ut.getGroupCN(req.body.authorized_groups) + "'");
					res.status(401).send({error: "User is not authorized"});
				} else {
					logger.error("Error from authenticate promise: ", err);
					res.status(500).send({ error: 'Unexpected Error. Please try again.'});
				}
			});
		} else {
			logger.warn("No username or password supplied in request");
			res.status(400).send({error: 'No username or password supplied'});
		}
});

app.post('/ldap-jwt/verify', function (req, res) {
	logger.debug("verify endpoint: " + JSON.stringify(req.body, ut.hideSecretsAndLogger, 2));
	var token = req.body.token;
	if (token && settings.hasOwnProperty( 'jwt' )) {
		// jwtTokenSecret is defined iff there is a settings.jwt object.
		try {
			var decoded = jwt.decode(token, app.get('jwtTokenSecret'));
			if (decoded.exp <= Date.now()) {
				res.status(400).send({ error: 'Access token has expired'});
				logger.debug("verify 400 expired");
				logger.debug("Expiry data: " + new Date(decoded.exp).toLocaleString());
				logger.debug("Current time: " + new Date(Date.now()).toLocaleString());
				logger.warn("Verification failed: expired token for '" + decoded.user_name + "'");
			} else if (req.body.authorized_groups != undefined) {
				if (decoded.hasOwnProperty("user_authorized_groups") && userInAuthorizedGroups(decoded.user_authorized_groups, req.body.authorized_groups)) {
					res.json(decoded);
					logger.info("Verification success for '" + decoded.user_name + "', " +
						"requested groups: '" + ut.getGroupCN(req.body.authorized_groups) +
						"', token groups: '" + ut.getGroupCN(decoded.user_authorized_groups) + "'");
				} else {
					res.status(401).send({error: 'Token not authorized for specified groups'});
					logger.warn("Verification failed: token/authorized group mismatch for user '" +
						decoded.user_name + "', requested groups: '" + ut.getGroupCN(req.body.authorized_groups) +
						"', token groups: '" + ut.getGroupCN(decoded.user_authorized_groups) + "'");
				}
			} else {
				res.json(decoded);
				logger.info("Verification success for '" + decoded.user_name + "'");
			}
		} catch (err) {
			res.status(500).send({ error: 'Invalid token'});
			logger.warn("Verification failed: " + err);
		}
	} else {
		res.status(400).send({ error: 'Access token is missing or invalid'});
		logger.warn("Verification failed: No token sent");
	}
});

let userInAuthorizedGroups = function(userGroups, authorized_groups) {
	if (!Array.isArray(userGroups)) userGroups = [ userGroups ];
	if (!Array.isArray(authorized_groups)) authorized_groups = [ authorized_groups ];
	logger.debug("userGroups: " + userGroups);
	logger.debug("authorized_groups: " + authorized_groups);
	return userGroups.some(group => authorized_groups.includes(group));
}

let userGroupAuthGroupIntersection = function(userGroups, authorized_groups) {
	if (!Array.isArray(userGroups)) userGroups = [ userGroups ];
	if (!Array.isArray(authorized_groups)) authorized_groups = [ authorized_groups ];
	return userGroups.filter(group => authorized_groups.includes(group));
}

// Health check endpoint
app.get('/ldap-jwt/health', function (req, res) {
	logger.debug("GET Health check");
	res.status(200).send({message: 'OK'});
});

var port = (process.env.PORT || 3000);


if (settings.ssl) {
	var options = {
	    key:  fs.readFileSync("./ssl/server.key"),
	    cert: fs.readFileSync("./ssl/server.crt"),
	};
	var server = https.createServer(options,app).listen(port,function(){
		logger.info("Express server listening on port " + port + " using httpS");
		logger.info('JWT tokens will expire after ' + settings.jwt.timeout + ' ' + settings.jwt.timeout_units);
		logger.info("LDAP url: " + settings.ldap.url);
		if (settings.ldap.bindAsUser) {
			logger.info("Will bind with authenticating user's credentials");
		} else {
			logger.info("Will bind with service account: " + ut.getGroupCN(settings.ldap.bindDn));
		}
		app.on("error",(err) => {
			logger.error("ERROR: " + err.stack);
		});
	});
} else {
	var server = http.createServer(app).listen(port,function(){
		logger.info("Express server listening on port " + port + " using http");
		logger.info('JWT tokens will expire after ' + settings.jwt.timeout + ' ' + settings.jwt.timeout_units);
		logger.info("LDAP url: " + settings.ldap.url);
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

