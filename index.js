var settings = require('./config/config.json');

if (settings.debug) {
    console.log( 'Settings: ' + JSON.stringify( settings ) );
}

var bodyParser = require('body-parser');
var jwt = require('jwt-simple');
var moment = require('moment');
var LdapAuth = require('ldapauth-fork');
var Promise  = require('promise');

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

app.post('/authenticate', function (req, res) {
	if(auth && req.body.username && req.body.password) {
		if (settings.debug) {
                    console.log( 'Request to authenticate ' + req.body.username );
		}
		authenticate(req.body.username, req.body.password)
			.then(function(user) {
				var expires = parseInt(moment().add(2, 'days').format("X"));
				var token = jwt.encode({
					exp: expires,
					aud: settings.jwt.clientid,
					user_name: user.uid,
					full_name: user.displayName,
					mail: user.mail
				}, app.get('jwtTokenSecret'));

		                if (settings.debug) {
			            console.log( 'Authentication succeeded ' + req.body.username );
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

app.post('/verify', function (req, res) {
	var token = req.body.token;
	if (token && settings.hasOwnProperty( 'jwt' )) {
                // jwtTokenSecret is defined iff there is a settings.jwt object.
		try {
			var decoded = jwt.decode(token, app.get('jwtTokenSecret'));

			if (decoded.exp <= parseInt(moment().format("X"))) {
				res.status(400).send({ error: 'Access token has expired'});
			} else {
				res.json(decoded);
			}
		} catch (err) {
			res.status(500).send({ error: 'Access token could not be decoded'});
		}
	} else {
		res.status(400).send({ error: 'Access token is missing'});
	}
});


var port = (process.env.PORT || 3000);
app.listen(port, function() {
	console.log('Listening on port: ' + port);

	if (settings.hasOwnProperty( 'ldap' )) {
		if (typeof settings.ldap.reconnect === 'undefined' || settings.ldap.reconnect === null || settings.ldap.reconnect === false) {
			console.warn('WARN: This service may become unresponsive when ldap reconnect is not configured.')
		}
	}
});
