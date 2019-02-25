"use strict";
/**
 * Module dependencies.
 */
const passport = require('passport-strategy');
const util = require('util');
const uuidv4 = require('uuid/v4');
const url = require('url');
const AD = require('ad');

const AdProxy = require('./lib/adproxy.js');

const toBinary = require('./lib/tobinary.js');

const Cache = require('./lib/cache');
const cache = new Cache();

/**
 * `Strategy` constructor.
 * Examples:
 *
 * @param {Function} verify Verifies the user.
 * @api public
 */

const isFlagSet = (field, flag) => {
	return (field & flag) === flag;
};

const decodeHttpAuthorizatioHeader = (header) =>  {
	const header_data = header.split(' ');
	if (header_data.length == 2 && header_data[0] == 'NTLM') {
		return Buffer.from(header_data[1], 'base64');
	}
};

const ntlmMessageType = (msg) => {
	if (msg.toString('utf8', 0, 8) != 'NTLMSSP\0') {
		return null;
	}
	const msg_type = msg.readUInt8(8);
	if (![1, 3].includes(msg_type)) {
		return null;
	}
	return msg_type;
};

const connectToProxy = (self, req, msg) => {
	const serverUrl = url.parse(self._options.domaincontroller);
	const adProxy = new AdProxy(serverUrl.hostname,
		serverUrl.port,
		self._options.domain,
		decodeURI(serverUrl.path),
		(serverUrl.protocol === 'ldaps:'),
		self._options.tlsOptions
		);

	adProxy.negotiate(msg, (err, challenge) => {
		if (err) {
			adProxy.close();
			self._options.warn('Error query to ad', self._options.domaincontroller, err);
			return self.error('Error query to ad');
		}

		self._options.debug(`Send msg type 2 - '${req.url}' / '${req.connection.id}}'`);

		cache.setProxy(req.connection.id, adProxy);

		return self.fail(`NTLM ${challenge.toString('base64')}`);
	});
};

const messageType1 = (self, req, msg) => {
	connectToProxy(self, req, msg);
};

const parseNtlmAuthenticate = (msg) => {
	let domainNameLen = msg.readUInt16LE(0x1C),
		domainNameBufferOffset = msg.readUInt32LE(0x20),
		domainName = msg.slice(domainNameBufferOffset, domainNameBufferOffset + domainNameLen),
		userNameLen = msg.readUInt16LE(0x24),
		userNameBufferOffset = msg.readUInt32LE(0x28),
		userName = msg.slice(userNameBufferOffset, userNameBufferOffset + userNameLen),
		workstationLen = msg.readUInt16LE(0x2C),
		workstationBufferOffset = msg.readUInt32LE(0x30),
		workstation = msg.slice(workstationBufferOffset, workstationBufferOffset + workstationLen);

	if (isFlagSet(msg.readUInt8(0x3C), toBinary('00000001'))) {
		domainName = domainName.toString('utf16le');
		userName = userName.toString('utf16le');
		workstation = workstation.toString('utf16le');
	} else {
		domainName = domainName.toString();
		userName = userName.toString();
		workstation = workstation.toString();
	}

	return {
		user: userName,
		domain: domainName,
		workstation: workstation
	};
};

const messageType3 = (self, req, msg) => {
	self._options.debug(`Query msg type 3 - '${req.url}' / '${req.connection.id}}'`);

	const adProxy = cache.getProxy(req.connection.id);
	if(!!!adProxy) {
		self._options.warn(`Not found ad proxy '${req.connection.id}'`);
		return self.error('Error get ad proxy');
	}

	let { user, domain, workstation } = parseNtlmAuthenticate(msg);

	if (!!!domain) {
		domain = self._options.domain;
	}

	adProxy.authenticate(msg, (err, result) => {
		if (!!err) {
			cache.remove(req.connection.id);
			self._options.warn('Error authenticate ad proxy', req.connection.id);
			return self.error('Error authenticate ad proxy');
		}

		const userData = {
			domain: domain,
			user: user,
			workstation: workstation,
			authenticated: false
		};

		if (!!!result) {
			cache.remove(req.connection.id);
			self._options.warn(`Forbidden ${userData.user}@${userData.domain} - '${req.url}'`);
			return self.fail();
		} else {
			const _ = () => {
				userData.authenticated = true;
				self._options.debug(`Success ${userData.user}@${userData.domain} - '${req.url}' / '${req.connection.id}}'`);
				return self._verify(userData, (err, userData, info) => {
					if (!!err) {
						cache.remove(req.connection.id);
						return self.error(err);
					}
					if (!!!user) {
						cache.remove(req.connection.id);
						return self.fail(info);
					}

					cache.setUser(req.connection.id, userData);
					cache.closeProxy(req.connection.id);
					self.success(userData, info);
				});
			};

			if(self._options.domainuser) {
				(new AD(Object.assign({
					url: self._options.domaincontroller
				}, self._options.domainuser)))
				.user(`${userData.user}@${userData.domain}`)
				.get()
				.then((user) => {
					Object.assign(userData, {
						dn: user.dn,
						displayName: user.displayName,
						groups: user.groups.map((group) => { return group.cn; })
					});

					_();
				})
				.catch((err) => {
					cache.remove(req.connection.id);
					self._options.warn(`Error ad query: ${err}`);
					return self.error('Error ad query');
				});
			}
			else {
				_();
			}
		}
	});
};

function Strategy(options, verify) {
	this._options = Object.assign(options, {
		ttl: 1000 * 60 * 10,
		debug: console.log,
		warn: console.warn
	});

	if (!!!this._options.domain) {
		throw new Error('Not set domain option');
	}

	if (!!!this._options.domaincontroller) {
		throw new Error('Not set domaincontroller option');
	}

	this._verify = verify;
	if (!!!verify) {
        throw new TypeError('NTLM Strategy requires a verify callback');
	}

	if('domainuser' in this._options) {
		if(!!!this._options.domainuser.user || !!!this._options.domainuser.pass) {
			throw new Error('Not set domainuser option');
		}
	}

	passport.Strategy.call(this);
	this.name = 'ntlm';

	cache.setTTL(this._options.ttl);
	cache.setDebug(this._options.debug);
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 * @param {Object} req HTTP request object.
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
	const self = this;

	cache.clean();

	if(!!self._options.session) {
		if(!!!req.session || !!!req.session.id) {
			throw new Error('Not create session');
		}

		if(req.connection.id != req.session.id) {
			if(!!req.connection.id) {
				cache.copy(req.connection.id, req.session.id);
			}
			req.connection.id = req.session.id;
		}
	}
	else {
		if (!!!req.connection.id) {
			req.connection.id = uuidv4();
		}
	}

	const userData = cache.user(req.connection.id);

	if(!!userData) {
		self._options.debug(`User ${userData.user}@${userData.domain} - '${req.url}' / '${req.connection.id}}' already login`);
		return self.success(userData);
	}

	cache.add(req.connection.id);

	const authHeader = req.headers.authorization;
	if (!!!authHeader) {
		self._options.debug(`Send NTLM http header - '${req.url}' / '${req.connection.id}}'`);
		return self.fail('NTLM');
	}

	const msg = decodeHttpAuthorizatioHeader(authHeader);
	if (!!!msg) {
		self._options.debug(`Error parse http header '${authHeader}' - '${req.url}' / '${req.connection.id}}'`);
		return self.error('Error parse header');
	}

	const ntlmVersion = ntlmMessageType(msg);
	if(!!!ntlmVersion) {
		self._options.debug(`Error parse ntlm message '${authHeader}' - '${req.url}' / '${req.connection.id}}'`);
		return self.error('Error parse ntlm message');
	}

	if (ntlmVersion == 1) {
		return messageType1(self, req, msg);
	}

	if (ntlmVersion == 3) {
		return messageType3(self, req, msg);
	}

	self._options.warn(`Unsupported ntlm version '${authHeader}' ${ntlmVersion} - '${req.url}' / '${req.connection.id}}'`);
	return self.error('Unsupported ntlm version');
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
