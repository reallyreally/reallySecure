# ExpressJS Security Layer

Introduces comprehensive security for your ExpressJS based application.

## Is this for you?

This package has been built for our specific needs. Your mileage may vary. Be very cautious enabling HSTS - do not turn it on unless you understand the implications for your domain and subdomains.

### Prerequisites

This package is called while instantiating your ExpressJS based application. It is not a stand-alone package.

### Installing

Assuming you are starting an ExpressJS project from scratch.
Create your ExpressJS project.

```
express --view=hbs --css=less --git my-secure-project
```

Then install ExpressJS

```
cd my-secure-project && npm install
```

Then install this package

```
npm install --save @really/really-secure
```

Now you should be able to add it to your application layer

## Using with ExpressJS

In your app.js require the package

```
var securityLayer = require('@really/really-secure');
```

Prepare your configuration

```
var reallySecureConfig = {
  "csp": {
    "fontSrc": ["'self'", "use.typekit.net"],
    "imgSrc": ["'self'", "data:"],
    "defaultSrc": ["'self'"],
    "reportUri": "/cspreport",
    "upgradeInsecureRequests": true
  },
  "poweredBy": "A Secure Engine"
}
```

Now add it to the application flow

```
// Secure site
app.use(securityLayer(reallySecureConfig));
```

**Using Google Cloud App Engine?**

You will need to trust the proxy or you will end up with SSL issues.

```
// Trust App Engine proxy
app.enable('trust proxy')
```

### Example app.js

Your app.js may end up looking like this

```
var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var securityLayer = require('@really/really-secure');

var index = require('./routes/index');
var users = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

var reallySecureConfig = {
  "csp": {
    "fontSrc": ["'self'", "use.typekit.net"],
    "imgSrc": ["'self'", "data:"],
    "defaultSrc": ["'self'"],
    "reportUri": "/cspreport",
    "upgradeInsecureRequests": true
  },
  "poweredBy": "A Secure Engine"
}

// Secure site
app.use(securityLayer(reallySecureConfig));

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(require('less-middleware')(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', index);
app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;

```

## Using a nonce

For your security pleasure - we generate a nonce for each request. Where your site has inline script or other elements, and those elements are inserted intentionally - you can use the nonce to validate the insertion.

The nonce is automatically added to all the CSP types, so no extra work is required here. The nonce value is available in `res.locals` - as `res.locals.nonce`.

If you are using handlebars - you might end up with something like this `layout.hbs` example. (Note the `<script nonce="{{ nonce }}">`)

```
<!doctype html>
<html class="no-js" lang="en-US">
    <head>
      <!-- Google Tag Manager -->
      <script nonce="{{ nonce }}">(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
      new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
      j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
      'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
      })(window,document,'script','dataLayer','GTM-A0A0000');</script>
      <!-- End Google Tag Manager -->
        <meta charset="utf-8">
        <meta http-equiv="x-ua-compatible" content="ie=edge">
        <title>Example Layout</title>
        <meta name="description" content="">
        <meta name="viewport" content="width=device-width, initial-scale=1">
    </head>
    <body>
      <!-- Google Tag Manager (noscript) -->
      <noscript><iframe nonce="{{ nonce }}" src="https://www.googletagmanager.com/ns.html?id=GTM-A0A0000"
      height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>
      <!-- End Google Tag Manager (noscript) -->
        <!--[if lt IE 8]>
        <p class="browserupgrade">You are using an <strong>outdated</strong> browser. Please <a href="http://browsehappy.com/">upgrade your browser</a> to improve your experience.</p>
        <![endif]-->
{{{body}}}
    </body>
</html>
```

## Configuration

Apart from the example above - configuration is typically passed to each component. A more exhaustive example would be:

```
{
  "csp":{
    "fontSrc":[
      "'self'",
      "fonts.gstatic.com"
    ],
    "imgSrc":[
      "'self'",
      "data:",
      "platform.slack-edge.com",
      "www.google-analytics.com",
      "stats.g.doubleclick.net",
      "www.google.com"
    ],
    "defaultSrc":[
      "'self'"
    ],
    "reportUri":"/v1/cspreport",
    "styleSrc":[
      "'self'",
      "fonts.googleapis.com",
      "'sha256-tFH5KRmizb/+eruMkSeYor+UVhiMbPUtVTRTEMsQopc='",
      "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"
    ],
    "scriptSrc":[
      "'self'",
      "www.googletagmanager.com"
    ],
    "upgradeInsecureRequests":true
  },
  "hsts":{
    "maxAge":10886400,
    "includeSubDomains":true,
    "preload":true,
    "force":true
  },
  "poweredBy":"really-secure"
}
```

**Another note about HSTS**

This example would activate HSTS. It is important that you only do this knowing what the implication for your whole domain / environment is. It will (for example) break Google's G Suite domain redirection if you use this on your base domain.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags).

## Authors

* **Troy Kelly** - *Initial work* - [troykelly](https://github.com/troykelly)
* **Daniel Walton** - [imdanwalton](https://github.com/imdanwalton)

See also the list of [contributors](https://github.com/reallyreally/reallySecure/contributors) who participated in this project.

## License

This project is licensed under the Apache-2.0 License
