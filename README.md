# passport-ad

This is simple PassportJS strategy for NTLM auth in Active Directory Domain.

Active Directory support is heavily inspired by [express-ntlm](https://www.npmjs.com/package/express-ntlm).

## Installation

```bash
npm i passport-ad --save
```

## Basic Usage

### Without session

```js
const PassportStrategy = require('passport-ad');

passport.use(new PassportStrategy({
    domain: process.env.DOMAIN,
    domaincontroller: process.env.DOMAINCONTROLLER
}, function(user, verified) {
    return verified(null, user, null);
}));

app.use(passport.initialize({session: false}));
app.use(passport.authenticate('ntlm', {session: false}));
```

### With session

```js

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
    session: true,
    ttl: 1000
}, function(user, verified) {

    return verified(null, user, null);
}));

app.use(passport.initialize({session: false}));
app.use(passport.authenticate('ntlm', {session: false}));

```

### Options
- `domain` - domain name
- `domaincontroller` - ldap url for domain controller
- `ttl` - msec to store unused credentials.
- `domainuser.user` - domain user
- `domainuser.user` - domain user
- `session` - is use session for store credentials


If a `domainuser` is specified, then this user will be prompted for a domain for extended information.
