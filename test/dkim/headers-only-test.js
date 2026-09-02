/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { dkimSign, dkimVerify } = require('../../lib/mailauth');
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
});
