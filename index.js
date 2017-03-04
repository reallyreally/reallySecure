'use strict';

var enforce = require('express-sslify');
var helmet = require('helmet');
var csp = require('helmet-csp');
var uuid = require('node-uuid');

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

                    if(!req.hostname.startsWith("api.")) {
                      defaultSrc.push("api." + req.hostname);
                    }
                    if(!req.hostname.startsWith("script.")) {
                      scriptSrc.push("script." + req.hostname);
                    }
                    if(!req.hostname.startsWith("sytle.")) {
                      styleSrc.push("sytle." + req.hostname);
                    }
                    if(!req.hostname.startsWith("font.")) {
                      fontSrc.push("font." + req.hostname);
                    }
                    if(!req.hostname.startsWith("img.")) {
                      imgSrc.push("img." + req.hostname);
                    }

                    csp({
                      // Specify directives as normal.
                      directives: {
                        defaultSrc: defaultSrc,
                        scriptSrc: scriptSrc,
                        styleSrc: styleSrc,
                        fontSrc: fontSrc,
                        imgSrc: imgSrc,
                        sandbox: options.csp.sandbox || ['allow-forms', 'allow-scripts'],
                        reportUri: options.csp.reportUri || '/report-violation',
                        objectSrc: options.csp.objectSrc || ["'none'"],
                        upgradeInsecureRequests: true
                      },

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
                    })(req, res, next);
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