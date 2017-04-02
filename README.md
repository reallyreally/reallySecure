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
var securityLayer = require('really-secure');
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

### Example app.js

Your app.js may end up looking like this

```
var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var securityLayer = require('really-secure');

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

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags).

## Authors

* **Troy Kelly** - *Initial work* - [troykelly](https://github.com/troykelly)

See also the list of [contributors](https://github.com/reallyreally/reallySecure/contributors) who participated in this project.

## License

This project is licensed under the Apache-2.0 License
