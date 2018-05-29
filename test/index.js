/*jslint node: true */
/*jslint esversion: 6 */
'use strict';

var securityLayer = require('../index');

var securityLayerOptions = require('./test001');

var dummyExpressReq = {
  hostname: "www.really.ai",
  headers: {
    "x-forwarded-proto": "https"
  }
};

var requestStatus = 200;

var dummyExpressRes = function() {};

dummyExpressRes.locals = {};

dummyExpressRes.setHeader = function(headerToSet, headerValue) {
  console.log(headerToSet, headerValue);
  dummyExpressReq[headerToSet] = headerValue;
};

dummyExpressRes.status = function(statusValue) {
  console.log(statusValue);
  requestStatus = statusValue;
};

dummyExpressRes.send = function(sendText) {
  console.log("Sending:" + sendText);
};

var dummyExpressNext = function() {
  console.log("Finished");
};

var currentEnv = process.env.NODE_ENV;

process.env.NODE_ENV = "production";

try {
  var securityLayerTest = securityLayer(securityLayerOptions);
  securityLayerTest(dummyExpressReq, dummyExpressRes, dummyExpressNext);
} catch (err) {
  console.log(err);
}
