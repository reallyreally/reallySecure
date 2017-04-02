'use strict';

var enforce = require('express-sslify');
var helmet = require('helmet');
var csp = require('helmet-csp');
var uuid = require('node-uuid');
var parseDomain = require("parse-domain");

module.exports = function reallySecure (options) {
  options = options || {}

  return function reallySecure(req, res, next) {

    var makeSecure = function(){
      res.locals.nonce = uuid.v4();
      // Sets "X-DNS-Prefetch-Control: on".
      helmet.dnsPrefetchControl({ allow: true })(req, res, function(){
        // Don't allow me to be in ANY frames.
        // Sets "X-Frame-Options: DENY".
        helmet.frameguard({ action: 'deny' })(req, res, function(){
          // Set X-Powered-By to Aicial Engine
          helmet.hidePoweredBy({ setTo: options.poweredBy || 'The Internet' })(req, res, function(){
            // Sets "X-Download-Options: noopen".
            helmet.ieNoOpen()(req, res, function(){
              // Sets "X-Content-Type-Options: nosniff".
              helmet.noSniff()(req, res, function(){
                // Sets "Referrer-Policy: same-origin".
                helmet.referrerPolicy({ policy: 'origin-when-cross-origin' })(req, res, function(){
                  // Sets "X-XSS-Protection: 1; mode=block".
                  helmet.xssFilter()(req, res, function(){
                    if(options.csp === undefined) options.csp = {};
                    var defaultSrc = options.csp.defaultSrc || ["'self'"];
                    var scriptSrc = options.csp.scriptSrc || ["'self'"];
                    var styleSrc = options.csp.styleSrc || ["'self'"];
                    var fontSrc = options.csp.fontSrc || ["'self'"];
                    var imgSrc = options.csp.imgSrc || ["'self'"];
                    var upgradeInsecureRequests = options.csp.upgradeInsecureRequests || true;

                    var hostnameParts = parseDomain(req.hostname);
                    if(hostnameParts) {
                      var hostname = hostnameParts.domain + '.' + hostnameParts.tld;
                    } else {
                      var hostname = req.hostname;
                    }

                    var noSubs = ['localhost', 'appspot.com'];

                    if(!noSubs.includes(hostname)) {
                      if(defaultSrc.indexOf("api." + hostname) === -1) defaultSrc.push("api." + hostname);
                      if(scriptSrc.indexOf("script." + hostname) === -1) scriptSrc.push("script." + hostname);
                      if(styleSrc.indexOf("sytle." + hostname) === -1) styleSrc.push("sytle." + hostname);
                      if(fontSrc.indexOf("font." + hostname) === -1) fontSrc.push("font." + hostname);
                      if(imgSrc.indexOf("img." + hostname) === -1) imgSrc.push("img." + hostname);
                    } else {
                      upgradeInsecureRequests = false;
                    }

                    var cspConfig = {
                      // Specify directives as normal.
                      directives: {
                        defaultSrc: defaultSrc,
                        scriptSrc: scriptSrc,
                        styleSrc: styleSrc,
                        fontSrc: fontSrc,
                        imgSrc: imgSrc,
                        objectSrc: options.csp.objectSrc || ["'none'"]
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

                    if(upgradeInsecureRequests) {
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
    if(process.env.NODE_ENV === 'production') {
      var enforceHTTPS = function(){
        enforce.HTTPS({ trustProtoHeader: true })(req, res, makeSecure);
      }
      if(options.hsts !== undefined) {
        // Add HSTS Strict-Transport-Security headers
        helmet.hsts({
          maxAge: options.hsts.maxAge || 10886400,        // Must be at least 18 weeks to be approved by Google
          includeSubDomains: options.hsts.includeSubDomains || true, // Must be enabled to be approved by Google
          preload: options.hsts.preload || true,
          force: options.hsts.force || true
        })(req, res, function(){
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
