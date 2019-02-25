"use strict";

const express = require('express');
const session = require('express-session');
const passport = require('passport');

const NtlmStrategy = require('.');

const app = express();
app.disable('x-powered-by');

app.use((req, res, next) => {
	console.log((new Date()).toString(),
		req.method,
		req.url,
        req.header('x-real-ip') || req.ip
		);
	next();
});

app.use(session({
    secret: 'test-passport-ad',
    resave: true,
    saveUninitialized: true
}));

passport.use(new NtlmStrategy({
    domain: process.env.DOMAIN,
    domaincontroller: process.env.DOMAINCONTROLLER,
    domainuser: {
        user: process.env.USER,
        pass: process.env.PSWD
    },
    session: true
}, function(user, verified) {

    return verified(null, user, null);
}));

app.use(passport.initialize({session: false}));
app.use(passport.authenticate('ntlm', {session: false}));

app.get('/', (req, res) => {
    return res.json({});
});

const port = process.env.PORT || 8080;
console.log(`Start http server on ${port}`);

app.listen(port, '0.0.0.0');
