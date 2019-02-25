const net = require('net');
const tls = require('tls');

function Proxy(ipaddress, port, domain, protoFactory, use_tls, tlsOptions) {
    this.ipaddress = ipaddress;
    this.port = port;
    this.domain = domain;
    this.protoFactory = protoFactory;
    this.use_tls = use_tls;
    this.tlsOptions = tlsOptions;
    this.socket = null;
}

Proxy.prototype._openConnection = function() {
    this.close();

    if (this.use_tls) {
        this.socket = tls.connect(this.port, this.ipaddress, this.tlsOptions);
    } else {
        this.socket = net.createConnection(this.port, this.ipaddress);
    }

    this.socket.setTimeout(5000);
    this.socket.setKeepAlive(true);
};

Proxy.prototype._transaction = function(msg) {
    if (!this.socket) {
        throw new Error('Transaction on closed socket.');
    }

    this.socket.write(msg);
};

Proxy.prototype.close = function() {
    if (this.socket) {
        this.socket.end();
    }
};

Proxy.prototype.negotiate = function(ntlmNegotiate, cb) {
    this._openConnection();
    this.socket.on('data', (data) => {
        if (cb) {
            this.proto.parse_session_setup_resp(data, (error, result, challenge) => {
                if (!!!result) {
                    cb(error, false);
                } else {
                    cb(error, challenge);
                }
                cb = null;
            });
        }
    });
    this.socket.on('error', function(err) {
        if (cb) {
            cb(err);
        }
        cb = null;
    });
    this.proto = new this.protoFactory();

    var msg = this.proto.make_session_setup_req(ntlmNegotiate, true);
    this._transaction(msg);
};

Proxy.prototype.authenticate = function(ntlmAuthenticate, cb) {
    this.socket.on('data', (data) => {
        if (cb) {
            this.proto.parse_session_setup_resp(data, function(error, result) {
                cb(null, result);
                cb = null;
            });
        }
    });
    this.socket.on('error', (err) => {
        if (cb) {
            cb(err);
            cb = null;
        }
    });

    const msg = this.proto.make_session_setup_req(ntlmAuthenticate, false);
    this._transaction(msg);
};

module.exports = Proxy;
