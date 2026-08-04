/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { authenticate, dkimSign } = require('../lib/mailauth');
const { zoneResolver } = require('./helpers/dns-zone');
const { dkimTxtRecord, privateKey } = require('./helpers/keys');
const { buildMessage } = require('./helpers/message');

const message = buildMessage({ from: 'user@mail.example.com', to: 'rcpt@example.net' });

// Signed by the organizational domain while the author is a subdomain of it, so the
// signature aligns under relaxed alignment but not under strict alignment.
const authenticateWith = async dmarcRecord => {
    const { signatures } = await dkimSign(message, {
        signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: privateKey('private-rsa.pem'), algorithm: 'rsa-sha256' }]
    });

    return authenticate(Buffer.concat([Buffer.from(signatures), message]), {
        ip: '198.51.100.1',
        helo: 'mail.example.com',
        sender: 'user@mail.example.com',
        mta: 'mx.example.net',
        disableBimi: true,
        resolver: zoneResolver({
            'test._domainkey.example.com': { TXT: [[dkimTxtRecord('public-rsa.pem')]] },
            '_dmarc.mail.example.com': { TXT: [[dmarcRecord]] }
        })
    });
};

describe('authenticate Tests', () => {
    it('Should report an org level signature as aligned under relaxed alignment', async () => {
        const result = await authenticateWith('v=DMARC1; p=reject');

        expect(result.dkim.results[0].status.result).to.equal('pass');
        expect(result.dkim.results[0].status.aligned).to.equal('example.com');
        expect(result.dmarc.status.result).to.equal('pass');
        expect(result.dmarc.alignment.dkim.result).to.equal('example.com');
    });

    it('Should not report an org level signature as aligned when the domain publishes adkim=s', async () => {
        const result = await authenticateWith('v=DMARC1; p=reject; adkim=s');

        expect(result.dkim.results[0].status.result).to.equal('pass');
        // the per signature flag must agree with the DMARC verdict, not with relaxed alignment
        expect(result.dkim.results[0].status.aligned).to.be.false;
        expect(result.dmarc.status.result).to.equal('fail');
        expect(result.dmarc.alignment.dkim.result).to.be.undefined;
    });
});
