/*jslint node: true */
/*jslint esversion: 6 */
'use strict';

const enforce = require('express-sslify');
const helmet = require('helmet');
const csp = require('helmet-csp');
const uuidv4 = require('uuid/v4');
const parseDomain = require("parse-domain");

var isIPv4v6 = /^(((([1]?\d)?\d|2[0-4]\d|25[0-5])\.){3}(([1]?\d)?\d|2[0-4]\d|25[0-5]))|([\da-fA-F]{1,4}(\:[\da-fA-F]{1,4}){7})|(([\da-fA-F]{1,4}:){0,5}::([\da-fA-F]{1,4}:){0,5}[\da-fA-F]{1,4})$/;

module.exports = function reallySecure(options) {
  options = options || {};
  if (options.csp === undefined) options.csp = {};

  return function reallySecure(req, res, next) {

    var makeSecure = function() {
      res.locals.nonce = uuidv4();
      var nonceArray = ["'nonce-" + res.locals.nonce + "'"];
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
                var referrerPolicy = 'strict-origin-when-cross-origin';
                if (options.referrer_policy) {
                  referrerPolicy = options.referrer_policy;
                }
                helmet.referrerPolicy({
                  policy: referrerPolicy
                })(req, res, function() {
                  // Sets "X-XSS-Protection: 1; mode=block".
                  helmet.xssFilter()(req, res, function() {
                    if (options.csp === undefined) options.csp = {};

                    var defaultSrc = (options.csp.defaultSrc) ? JSON.parse(JSON.stringify(options.csp.defaultSrc)) : ["'self'"];
                    var scriptSrc = (options.csp.scriptSrc) ? JSON.parse(JSON.stringify(options.csp.scriptSrc)) : ["'self'"];
                    var styleSrc = (options.csp.styleSrc) ? JSON.parse(JSON.stringify(options.csp.styleSrc)) : ["'self'"];
                    var imgSrc = (options.csp.imgSrc) ? JSON.parse(JSON.stringify(options.csp.imgSrc)) : ["'self'"];
                    var connectSrc = (options.csp.connectSrc) ? JSON.parse(JSON.stringify(options.csp.connectSrc)) : ["'self'"];
                    var fontSrc = (options.csp.fontSrc) ? JSON.parse(JSON.stringify(options.csp.fontSrc)) : ["'self'"];
                    var objectSrc = (options.csp.objectSrc) ? JSON.parse(JSON.stringify(options.csp.objectSrc)) : ["'none'"];
                    var mediaSrc = (options.csp.mediaSrc) ? JSON.parse(JSON.stringify(options.csp.mediaSrc)) : ["'none'"];
                    var frameSrc = (options.csp.frameSrc) ? JSON.parse(JSON.stringify(options.csp.frameSrc)) : ["'none'"]; //Deprecated
                    var childSrc = (options.csp.childSrc) ? JSON.parse(JSON.stringify(options.csp.childSrc)) : ["'none'"];

                    var upgradeInsecureRequests = options.csp.upgradeInsecureRequests || true;

                    var hostnameParts = parseDomain(req.hostname);
										let hostname;
                    if (hostnameParts) {
                      hostname = hostnameParts.domain + '.' + hostnameParts.tld;
                    } else {
                      hostname = req.hostname;
                    }

                    var noSubs = ['localhost', 'appspot.com'];

                    if (hostname === 'localhost' || process.env.NODE_ENV === 'development') {
                      upgradeInsecureRequests = false;
                    }

                    var cspConfig = {
                      // Specify directives as normal.
                      directives: {
                        defaultSrc: (!defaultSrc.includes("'unsafe-inline'") && !defaultSrc.includes("'none'")) ? defaultSrc.concat(nonceArray) : defaultSrc,
                        scriptSrc: (!scriptSrc.includes("'unsafe-inline'") && !scriptSrc.includes("'none'")) ? scriptSrc.concat(nonceArray) : scriptSrc,
                        styleSrc: (!styleSrc.includes("'unsafe-inline'") && !styleSrc.includes("'none'")) ? styleSrc.concat(nonceArray) : styleSrc,
                        imgSrc: (!imgSrc.includes("'unsafe-inline'") && !imgSrc.includes("'none'")) ? imgSrc.concat(nonceArray) : imgSrc,
                        connectSrc: (!connectSrc.includes("'unsafe-inline'") && !connectSrc.includes("'none'")) ? connectSrc.concat(nonceArray) : connectSrc,
                        fontSrc: (!fontSrc.includes("'unsafe-inline'") && !fontSrc.includes("'none'")) ? fontSrc.concat(nonceArray) : fontSrc,
                        objectSrc: (!objectSrc.includes("'unsafe-inline'") && !objectSrc.includes("'none'")) ? objectSrc.concat(nonceArray) : objectSrc,
                        mediaSrc: (!mediaSrc.includes("'unsafe-inline'") && !mediaSrc.includes("'none'")) ? mediaSrc.concat(nonceArray) : mediaSrc,
                        frameSrc: (!frameSrc.includes("'unsafe-inline'") && !frameSrc.includes("'none'")) ? frameSrc.concat(nonceArray) : frameSrc,
                        childSrc: (!childSrc.includes("'unsafe-inline'") && !childSrc.includes("'none'")) ? childSrc.concat(nonceArray) : childSrc
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
                      cspConfig.directives.upgradeInsecureRequests = true;
                    }

                    csp(cspConfig)(req, res, next);
                  });
                });
              });
            });
          });
        });
      });
    };

    //When in production make sure we force SSL and send HSTS headers
    if (process.env.NODE_ENV === 'production') {
      var enforceHTTPS = function() {
        enforce.HTTPS({
          trustProtoHeader: true
        })(req, res, makeSecure);
      };
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

  };

};
