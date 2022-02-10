var settings = require('./config/config.json');

if (settings.debug) {
  console.log("Node version: "+process.version);
  var settingsToShow = JSON.parse(JSON.stringify(settings));
  delete settingsToShow.ldap.bindCredentials;
  console.log( 'Settings: (bindCredentials not displayed) ' + JSON.stringify( settingsToShow, null, 2 ) );
}

var bodyParser = require('body-parser');
var jwt = require('jwt-simple');
var moment = require('moment');
var LdapAuth = require('ldapauth-fork');
var Promise  = require('promise');
var fs = require('fs'),
    express = require('express');

if (settings.ssl) {
	var https = require('https');
} else {
	var http = require('http');
}

app = require('express')();

if (settings.debug) {
    app.use( function (err, req, res, next) {
        console.log( 'Got error on request: ' + JSON.stringify( req.originalUrl ) );
        console.log( '    error: ' + JSON.stringify( err ) );
        next();
    });

    app.use( function (req, res, next) {
        console.log( 'Got request: ' + req.method + ' ' + req.originalUrl );
        next();
    });
}


app.use(bodyParser.json());

if (settings.debug) {
    app.use( function (req, res, next) {
        console.log( 'After bodyParser.json()' );
        //console.log( '  body: ' + JSON.stringify( req.body ) ); <-- this can print passwords to log
        next();
    });
    app.use( function (err, req, res, next) {
        console.log( 'Error after bodyParser.json(): ' + JSON.stringify( err ) );
        next();
    });
}


app.use(bodyParser.urlencoded({ extended: false }));
app.use(require('cors')());

var auth = null;
if (settings.hasOwnProperty( 'ldap' ) && settings.hasOwnProperty( 'jwt' )) auth = new LdapAuth(settings.ldap);

if (settings.hasOwnProperty( 'jwt' )) {
    if (!settings.jwt.hasOwnProperty('timeout')) {
        console.log ('Settings.jwt.timeout not set - using default');
        settings.jwt.timeout = 1;
    }
    if (!settings.jwt.hasOwnProperty('timeout_units')) {
        console.log ('Settings.jwt.timeout_units not set - using default');
        settings.jwt.timeout_units = 'hour';
    }
    console.log('JWT tokens will expire after ' + settings.jwt.timeout + ' ' + settings.jwt.timeout_units);
    app.set('jwtTokenSecret',
            settings.jwt.base64 ? new Buffer(settings.jwt.secret, 'base64') : settings.jwt.secret);
}

var authenticate = function (username, password) {
	return new Promise(function (resolve, reject) {
		auth.authenticate(username, password, function (err, user) {
                        if (settings.debug) {
                            console.log( 'In authenticate callback' );
                        }
			if(err)
				reject(err);
			else if (!user)
				reject();
			else
				resolve(user);
		});
	});
};

app.post('/ldap-jwt/authenticate', function (req, res) {
	if(auth && req.body.username && req.body.password) {
		if (settings.debug) {
			console.log( 'Request to authenticate ' + req.body.username );
		}
		authenticate(req.body.username, req.body.password, req.body.authorized_groups)
			.then(function(user) {
				if (settings.debug) console.log({user: user});
				if (req.body.authorized_groups != undefined) {
					if (settings.debug) console.log("authorized_groups specified: " + req.body.authorized_groups);
					if (!user.hasOwnProperty("memberOf")) {
						throw "Server not configured for authorized_group verification";
					}
					var userGroupsForPayload = userGroupAuthGroupIntersection(user.memberOf, req.body.authorized_groups);
					if (!userInAuthorizedGroups(user.memberOf, req.body.authorized_groups)) {
						throw "User not in authorized_groups";
					}
					if (settings.debug) console.log({userGroupsForPayload: userGroupsForPayload});
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
				if (settings.debug) {
					console.log('Authentication succeeded for ' + req.body.username );
					console.log("JWT expiration: " + moment(expires).format("MMMM Do YYYY, h:mm:ss a"));
				}
				res.json({token: token, full_name: user.displayName, mail: user.mail});
			})
			.catch(function (err) {
				// Ldap reconnect config needs to be set to true to reliably
				// land in this catch when the connection to the ldap server goes away.
				// REF: https://github.com/vesse/node-ldapauth-fork/issues/23#issuecomment-154487871

				console.log(err);

				if (err.name === 'InvalidCredentialsError' || (typeof err === 'string' && err.match(/no such user/i)) ) {
					res.status(401).send({ error: 'Wrong user or password'});
				} else if (err == "Server not configured for authorized_group verification" || err == "User not in authorized_groups") {
					res.status(401).send({error: "User is not authorized"});
				} else {
					// ldapauth-fork or underlying connections may be in an unusable state.
					// Reconnect option does re-establish the connections, but will not
					// re-bind. Create a new instance of LdapAuth.
					// REF: https://github.com/vesse/node-ldapauth-fork/issues/23
					// REF: https://github.com/mcavage/node-ldapjs/issues/318

					res.status(500).send({ error: 'Unexpected Error'});
					auth = new LdapAuth(settings.ldap);
				}

			});
		} else {
		        if (settings.debug) {
			    console.log( 'No username or password supplied' );
		        }
			res.status(400).send({error: 'No username or password supplied'});
		}
});

app.post('/ldap-jwt/verify', function (req, res) {
	if (settings.debug) console.log("> verify");
	var token = req.body.token;
	if (token && settings.hasOwnProperty( 'jwt' )) {
                // jwtTokenSecret is defined iff there is a settings.jwt object.
		try {
			var decoded = jwt.decode(token, app.get('jwtTokenSecret'));

			if (decoded.exp <= Date.now()) {
				res.status(400).send({ error: 'Access token has expired'});
				if (settings.debug) {
					console.log("< verify 400 expired");
					console.log("Expiry data: " + new Date(decoded.exp).toLocaleString());
					console.log("Now: " + new Date(Date.now()).toLocaleString());
				}
			} else if (req.body.authorized_groups != undefined) {
				if (decoded.hasOwnProperty("user_authorized_groups") && userInAuthorizedGroups(decoded.user_authorized_groups, req.body.authorized_groups)) {
					res.json(decoded);
					if (settings.debug) console.log('< verify succeeded for user in authorized_groups');
				} else {
					res.status(401).send({error: 'Token not authorized for specified groups'});
					if (settings.debug) console.error('< verify failed; user not in authorized_groups');
				}
			} else {
				res.json(decoded);
				if (settings.debug){
					console.log("< verify succeeded");
					console.log("decoded: "+JSON.stringify(decoded,undefined,10));
				}
			}
		} catch (err) {
			res.status(500).send({ error: 'Access token could not be decoded'});
			if (settings.debug) console.log("< verify 500 cannot decode");
		}
	} else {
		res.status(400).send({ error: 'Access token is missing'});
		if (settings.debug) console.log("< verify 500 no token");
	}
});

let userInAuthorizedGroups = function(userGroups, authorized_groups) {
	if (!Array.isArray(userGroups)) userGroups = [ userGroups ];
	if (!Array.isArray(authorized_groups)) authorized_groups = [ authorized_groups ];
	if (settings.debug) console.log({msg: 'Checking groups in userInAuthorizedGroups', userGroups: userGroups, authorized_groups: authorized_groups});
	return userGroups.some(group => authorized_groups.includes(group));
}

let userGroupAuthGroupIntersection = function(userGroups, authorized_groups) {
	if (!Array.isArray(userGroups)) userGroups = [ userGroups ];
	if (!Array.isArray(authorized_groups)) authorized_groups = [ authorized_groups ];
	return userGroups.filter(group => authorized_groups.includes(group));
}

var port = (process.env.PORT || 3000);


if (settings.ssl) {
	var options = {
	    key:  fs.readFileSync("./ssl/server.key"),
	    cert: fs.readFileSync("./ssl/server.crt"),
	};
	var server = https.createServer(options,app).listen(port,function(){
		console.log("Express server listenting on port " + port + " using httpS");
			app.on("error",(err) => {
			console.warn("ERROR: "+err.stack);
		});
	});
} else {
	console.warn("WARNING: Server configured for http (not httpS).");
	var server = http.createServer(app).listen(port,function(){
		console.log("Express server listenting on port " + port + " using http");
			app.on("error",(err) => {
			console.warn("ERROR: "+err.stack);
		});
	});
}




