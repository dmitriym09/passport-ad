/* jshint node:true */
/* global toBinary */

const assert = require('assert');

const toBinary = require('./tobinary.js');

const ASN1 = {
    maketlv: function(dertype, payload) {
        if (typeof payload === 'string') {
            payload = Buffer.from(payload);
        }

        let tlv,
            offset;
        if (payload.length < 128) {
            tlv = Buffer.alloc(1 + 1 + payload.length);
            tlv.writeUInt8(dertype, 0);
            tlv.writeUInt8(payload.length, 1);
            offset = 2;
        } else if (payload.length < 256) {
            tlv = Buffer.alloc(1 + 2 + payload.length);
            tlv.writeUInt8(dertype, 0);
            tlv.writeUInt8(toBinary('10000001'), 1); // Number of length bytes = 1
            tlv.writeUInt8(payload.length, 2);
            offset = 3;
        } else {
            tlv = Buffer.alloc(1 + 3 + payload.length);
            tlv.writeUInt8(dertype, 0);
            tlv.writeUInt8(toBinary('10000010'), 1); // Number of length bytes = 2
            tlv.writeUInt16BE(payload.length, 2);
            offset = 4;
        }

        for (let i = 0; i < payload.length; i++) {
            tlv.writeUInt8(payload.readUInt8(i), offset++);
        }

        return tlv;
    },
    makeint: function(number, tag) {
        if (!tag) {
            tag = 0x02;
        }

        let payload;

        if (number <= 0) {
            payload = Buffer.from('\0');
        } else {
            payload = Buffer.alloc(0);
            while (number > 0) {
                const buf = Buffer.alloc(1);
                buf.writeUInt8(number & 255, 0);
                payload = buf + payload;
                number = number >>> 8;
            }
        }

        return ASN1.maketlv(tag, payload);
    },
    makeseq: function(payload) {
        return ASN1.maketlv(0x30, payload);
    },
    makeoctstr: function(payload) {
        return ASN1.maketlv(0x04, payload);
    },

    parselen: function(berobj) {
        let length = berobj.readUInt8(1);

        if (length < 128) {
            return [length, 2];
        }

        let nlength = length & toBinary('01111111');
        length = 0;

        for (let i = 2; i < 2 + nlength; i++) {
            length = length * 256 + berobj.readUInt8(i); 
        }

        return [length, 2 + nlength];
    },
    parsetlv: function(dertype, derobj, partial) {
        if (!partial) partial = false;

        if (derobj.readUInt8(0) != dertype) {
            throw new Error('BER element ' + derobj.toString('hex') + ' does not start type 0x' + dertype.toString(16));
        }

        let lengths = ASN1.parselen(derobj),
            length = lengths[0],
            pstart = lengths[1];

        if (partial) {
            if (derobj.length < length + pstart) {
                throw new Error('BER payload ' + derobj.toString('hex') + ' is shorter than expected (' + length + ' bytes, type 0x' + dertype.toString(16) + ').');
            }
            return [derobj.slice(pstart, pstart + length), derobj.slice(pstart + length)];
        }

        if (derobj.length != length + pstart) {
            throw new Error('BER payload ' + derobj.toString('hex') + ' is not ' + length + ' bytes long (type 0x' + dertype.toString(16) + ').');
        }
        return derobj.slice(pstart);
    },
    parseint: function(payload, partial, tag) {
        if (!partial) partial = false;
        if (!tag) tag = 0x02;

        let res = ASN1.parsetlv(tag, payload, partial);
        if (partial) {
            payload = res[0];
        } else {
            payload = res;
        }

        let value = 0;

        assert.equal(payload.readUInt8(0) & toBinary('10000000'), 0x00);
        for (let i = 0; i < payload.length; i++) {
            value = value * 256 + payload.readUInt8(i);
        }
        if (partial) {
            return [value, res[1]];
        } else {
            return value;
        }
    },
    parseenum: function(payload, partial) {
        if (!partial) partial = false;

        return ASN1.parseint(payload, partial, 0x0A);
    },
    parseseq: function(payload, partial) {
        if (!partial) partial = false;

        return ASN1.parsetlv(0x30, payload, partial);
    },
    parseoctstr: function(payload, partial) {
        if (!partial) partial = false;

        return ASN1.parsetlv(0x04, payload, partial);
    }
};

module.exports = ASN1;
