'use strict';

var enforce = require('express-sslify');
var helmet = require('helmet');
var csp = require('helmet-csp');
var uuid = require('node-uuid');
var parseDomain = require("parse-domain");

// From http://jsfiddle.net/DanielD/8S4nq/
var isIPv4v6 = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))|(^\s*((?=.{1,255}$)(?=.*[A-Za-z].*)[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?)*)\s*$)/;

module.exports = function reallySecure(options) {
	options = options || {}
	if (options.csp === undefined) options.csp = {};

	return function reallySecure(req, res, next) {

		var makeSecure = function() {
			res.locals.nonce = uuid.v4();
			var nonceArray = ["'nonce-"+res.locals.nonce+"'"];
			// Sets "X-DNS-Prefetch-Control: on".
			helmet.dnsPrefetchControl({
				allow: true
			})(req, res, function() {
				// Don't allow me to be in ANY frames.
				// Sets "X-Frame-Options: DENY".
				helmet.frameguard({
					action: 'deny'
				})(req, res, function() {
					// Set X-Powered-By to Aicial Engine
					helmet.hidePoweredBy({
						setTo: options.poweredBy || 'The Internet'
					})(req, res, function() {
						// Sets "X-Download-Options: noopen".
						helmet.ieNoOpen()(req, res, function() {
							// Sets "X-Content-Type-Options: nosniff".
							helmet.noSniff()(req, res, function() {
								// Sets "Referrer-Policy: same-origin".
								helmet.referrerPolicy({
									policy: 'origin-when-cross-origin'
								})(req, res, function() {
									// Sets "X-XSS-Protection: 1; mode=block".
									helmet.xssFilter()(req, res, function() {
										if (options.csp === undefined) options.csp = {};

										var defaultSrc = JSON.parse(JSON.stringify(options.csp.defaultSrc)) || ["'self'"];
										var connectSrc = JSON.parse(JSON.stringify(options.csp.connectSrc)) || ["'self'"];
										var scriptSrc = JSON.parse(JSON.stringify(options.csp.scriptSrc)) || ["'self'"];
										var styleSrc = JSON.parse(JSON.stringify(options.csp.styleSrc)) || ["'self'"];
										var fontSrc = JSON.parse(JSON.stringify(options.csp.fontSrc)) || ["'self'"];
										var imgSrc = JSON.parse(JSON.stringify(options.csp.imgSrc)) || ["'self'"];
										var objectSrc = JSON.parse(JSON.stringify(options.csp.objectSrc)) || ["'none'"];
										var frameSrc = JSON.parse(JSON.stringify(options.csp.frameSrc)) || ["'none'"];

										var upgradeInsecureRequests = options.csp.upgradeInsecureRequests || true;

										var hostnameParts = parseDomain(req.hostname);
										if (hostnameParts) {
											var hostname = hostnameParts.domain + '.' + hostnameParts.tld;
										} else {
											var hostname = req.hostname;
										}

										var noSubs = ['localhost', 'appspot.com'];

										if (!noSubs.includes(hostname) && !isIPv4v6.test(hostname)) {
											if (defaultSrc.indexOf("api." + hostname) === -1) defaultSrc.push("api." + hostname);
											if (connectSrc.indexOf("data." + hostname) === -1) connectSrc.push("data." + hostname);
											if (scriptSrc.indexOf("script." + hostname) === -1) scriptSrc.push("script." + hostname);
											if (styleSrc.indexOf("sytle." + hostname) === -1) styleSrc.push("sytle." + hostname);
											if (fontSrc.indexOf("font." + hostname) === -1) fontSrc.push("font." + hostname);
											if (imgSrc.indexOf("img." + hostname) === -1) imgSrc.push("img." + hostname);
										}

										if (hostname === 'localhost') {
											upgradeInsecureRequests = false;
										}

										var cspConfig = {
											// Specify directives as normal.
											directives: {
												defaultSrc: (!defaultSrc.includes("'unsafe-inline'") && !defaultSrc.includes("'none'"))?defaultSrc.concat(nonceArray):defaultSrc,
												connectSrc: (!connectSrc.includes("'unsafe-inline'") && !connectSrc.includes("'none'"))?connectSrc.concat(nonceArray):connectSrc,
												scriptSrc: (!scriptSrc.includes("'unsafe-inline'") && !scriptSrc.includes("'none'"))?scriptSrc.concat(nonceArray):scriptSrc,
												styleSrc: (!styleSrc.includes("'unsafe-inline'") && !styleSrc.includes("'none'"))?styleSrc.concat(nonceArray):styleSrc,
												fontSrc: (!fontSrc.includes("'unsafe-inline'") && !fontSrc.includes("'none'"))?fontSrc.concat(nonceArray):fontSrc,
												imgSrc: (!imgSrc.includes("'unsafe-inline'") && !imgSrc.includes("'none'"))?imgSrc.concat(nonceArray):imgSrc,
												objectSrc: (!objectSrc.includes("'unsafe-inline'") && !objectSrc.includes("'none'"))?objectSrc.concat(nonceArray):objectSrc,
												frameSrc: (!frameSrc.includes("'unsafe-inline'") && !frameSrc.includes("'none'"))?frameSrc.concat(nonceArray):frameSrc
											},

											sandbox: options.csp.sandbox || ['allow-forms', 'allow-scripts'],
											reportUri: options.csp.reportUri || '/report-violation',

											// This module will detect common mistakes in your directives and throw errors
											// if it finds any. To disable this, enable "loose mode".
											loose: false,

											// Set to true if you only want browsers to report errors, not block them.
											// You may also set this to a function(req, res) in order to decide dynamically
											// whether to use reportOnly mode, e.g., to allow for a dynamic kill switch.
											reportOnly: false,

											// Set to true if you want to blindly set all headers: Content-Security-Policy,
											// X-WebKit-CSP, and X-Content-Security-Policy.
											setAllHeaders: false,

											// Set to true if you want to disable CSP on Android where it can be buggy.
											disableAndroid: false,

											// Set to false if you want to completely disable any user-agent sniffing.
											// This may make the headers less compatible but it will be much faster.
											// This defaults to `true`.
											browserSniff: true
										};

										if (upgradeInsecureRequests) {
											cspConfig.directives.upgradeInsecureRequests = true
										}

										csp(cspConfig)(req, res, next);
									});
								});
							});
						});
					});
				});
			});
		}

		//When in production make sure we force SSL and send HSTS headers
		if (process.env.NODE_ENV === 'production') {
			var enforceHTTPS = function() {
				enforce.HTTPS({
					trustProtoHeader: true
				})(req, res, makeSecure);
			}
			if (options.hsts !== undefined) {
				// Add HSTS Strict-Transport-Security headers
				helmet.hsts({
					maxAge: options.hsts.maxAge || 10886400, // Must be at least 18 weeks to be approved by Google
					includeSubDomains: options.hsts.includeSubDomains || true, // Must be enabled to be approved by Google
					preload: options.hsts.preload || true,
					force: options.hsts.force || true
				})(req, res, function() {
					enforceHTTPS();
				});
			} else {
				enforceHTTPS();
			}
		} else {
			makeSecure();
		}

	}

}
