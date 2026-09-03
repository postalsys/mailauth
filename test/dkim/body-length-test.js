/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { dkimSign, dkimVerify } = require('../../lib/mailauth');
const parseDkimHeaders = require('../../lib/parse-dkim-headers');
const { zoneResolver } = require('../helpers/dns-zone');
const { dkimTxtRecord, privateKey } = require('../helpers/keys');

chai.config.includeStack = true;

// RFC 6376 section 3.5: sig-l-tag is 1*76DIGIT, so l=0 is a legal value and means that no
// body byte is covered by the signature

describe('DKIM body length Tests', () => {
    const resolver = zoneResolver({ 'test._domainkey.example.com': { TXT: [[dkimTxtRecord('public-rsa.pem')]] } });
    const message = 'From: user@example.com\r\nSubject: test\r\n\r\nHello world\r\n';

    const sign = maxBodyLength =>
        dkimSign(Buffer.from(message), {
            signatureData: [
                {
                    signingDomain: 'example.com',
                    selector: 'test',
                    privateKey: privateKey('private-rsa.pem'),
                    algorithm: 'rsa-sha256',
                    maxBodyLength
                }
            ]
        });

    it('Should serialize l=0 as a value and read it back as zero', async () => {
        const { signatures } = await sign(0);

        expect(signatures).to.include('l=0;');

        const parsed = parseDkimHeaders(signatures.split('\r\n').join(''));
        expect(parsed.parsed.l.value).to.equal(0);
    });

    it('Should verify its own l=0 signature', async () => {
        const { signatures } = await sign(0);

        const result = await dkimVerify(Buffer.from(signatures + message), { resolver });
        expect(result.results).to.have.lengthOf(1);
        expect(result.results[0].status.result).to.equal('pass');
    });

    it('Should verify a signature with a non-zero l=', async () => {
        const { signatures } = await sign(5);

        expect(signatures).to.include('l=5;');

        const result = await dkimVerify(Buffer.from(signatures + message), { resolver });
        expect(result.results[0].status.result).to.equal('pass');
    });

    it('Should not write to stdout when l= does not match the bytes hashed', async () => {
        const { signatures } = await sign(5);
        // an l= larger than the body is attacker controlled on any incoming signature
        const inflated = signatures.replace(/l=\d+/, 'l=999999');

        const written = [];
        const log = console.log;
        console.log = (...args) => written.push(args);
        try {
            await dkimVerify(Buffer.from(inflated + message), { resolver });
        } finally {
            console.log = log;
        }

        expect(written).to.deep.equal([]);
    });
});
