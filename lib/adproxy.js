const util = require('util');

const ASN1 = require('./asn1');
const Proxy = require('./proxy.js');

function LdapContext() {
    this.messageID = 0;

    this.LDAP_Result_success = 0;
    this.LDAP_Result_saslBindInProgress = 14;
}

LdapContext.prototype.make_session_setup_req = function(ntlm_token, type1) {
    const authentication = ASN1.maketlv(0xA3, Buffer.concat([ASN1.makeoctstr('GSS-SPNEGO'), ASN1.makeoctstr(ntlm_token)])),
        bindRequest = ASN1.maketlv(0x60, Buffer.concat([ASN1.makeint(3), ASN1.makeoctstr(''), authentication]));

    this.messageID++;

    return ASN1.makeseq(Buffer.concat([ASN1.makeint(this.messageID), bindRequest]));
};

LdapContext.prototype.make_negotiate_protocol_req = function() {
    return;
};

LdapContext.prototype.parse_session_setup_resp = function(response, callback) {
    try {
        let data = ASN1.parseseq(response);

        let messageID = ASN1.parseint(data, true);
        data = messageID[1];
        messageID = messageID[0];


        if (messageID != this.messageID) {
            throw new Error(`Unexpected MessageID: ${messageID} instead of ${this.messageID}`);
        }

        let controls = ASN1.parsetlv(0x61, data, true);
        data = controls[0];
        controls = controls[1];

        let resultCode = ASN1.parseenum(data, true);
        data = resultCode[1];
        resultCode = resultCode[0];

        let matchedDN = ASN1.parseoctstr(data, true);
        data = matchedDN[1];
        matchedDN = matchedDN[0];

        let diagnosticMessage = ASN1.parseoctstr(data, true);
        data = diagnosticMessage[1];
        diagnosticMessage = diagnosticMessage[0];

        if (resultCode == this.LDAP_Result_success) {
            return callback(null, true, '');
        }

        if (resultCode != this.LDAP_Result_saslBindInProgress) {
            return callback(null, false, '');
        }

        const serverSaslCreds = ASN1.parsetlv(0x87, data);
        return callback(null, true, serverSaslCreds);
    }
    catch (error) {
        return callback(error);
    }
};

function AdProxy(ipad, port, domain, base, use_tls, tlsOptions) {
    this._ipad = ipad;
    this._portad = port || (use_tls ? 636 : 389);

    Proxy.call(this, this._ipad, this._portad, domain, LdapContext, use_tls, tlsOptions);
    this.base = base;
}

util.inherits(AdProxy, Proxy);

module.exports = AdProxy;
