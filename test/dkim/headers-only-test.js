/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { authenticate, dkimSign, dkimVerify } = require('../../lib/mailauth');
const { zoneResolver } = require('../helpers/dns-zone');
const { dkimTxtRecord, privateKey } = require('../helpers/keys');

chai.config.includeStack = true;

// RFC 5322 allows a message without a body, and then there is no empty line
// that would end the header block

describe('DKIM headers-only message Tests', () => {
    const resolver = zoneResolver({ 'test._domainkey.example.com': { TXT: [[dkimTxtRecord('public-rsa.pem')]] } });
    const signOptions = {
        signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: privateKey('private-rsa.pem'), algorithm: 'rsa-sha256' }]
    };

    for (const [name, message] of [
        ['a message without a body', 'From: user@example.com\r\nSubject: test'],
        ['a message whose headers end with a line break but no empty line', 'From: user@example.com\r\nSubject: test\r\n'],
        ['a message with an empty body', 'From: user@example.com\r\nSubject: test\r\n\r\n']
    ]) {
        it('Should sign and verify ' + name, async () => {
            const { signatures } = await dkimSign(Buffer.from(message), signOptions);
            expect(signatures).to.include('DKIM-Signature:');
            // the body hash of an empty body
            expect(signatures).to.include('bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');

            const result = await dkimVerify(Buffer.from(signatures + message), { resolver });
            expect(result.results).to.have.lengthOf(1);
            expect(result.results[0].status.result).to.equal('pass');
        });
    }

    // RFC 6376 section 5.4 requires the From header to be signed, and section 6.1.1 makes
    // a signature that leaves it out a PERMFAIL. An input with nothing to sign used to
    // produce a signature with an empty h= tag, which is not valid sig-h-tag syntax either
    for (const [name, input] of [
        ['an input with no header that can be signed', 'X-Foo: bar'],
        ['an input that is not a message at all', 'Hello world, this is not a message'],
        ['an input with no bytes', '']
    ]) {
        it('Should refuse to sign ' + name, async () => {
            const { signatures, errors } = await dkimSign(Buffer.from(input), signOptions);

            expect(signatures.trim()).to.equal('');
            expect(errors).to.have.lengthOf(1);
            expect(errors[0].err.code).to.equal('ENOFROM');
        });
    }

    it('Should not throw when sealing an input with no bytes', async () => {
        const result = await authenticate(Buffer.from(''), {
            ip: '192.0.2.1',
            helo: 'x.test',
            mta: 'mx.test',
            sender: 'a@example.com',
            resolver: zoneResolver({}),
            seal: { signingDomain: 'example.com', selector: 'test', privateKey: privateKey('private-rsa.pem') }
        });

        expect(result.headers).to.be.a('string');
        expect(result.arc.status.result).to.equal('none');
    });
});
