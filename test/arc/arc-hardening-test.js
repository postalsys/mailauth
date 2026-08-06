/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { authenticate, sealMessage } = require('../../lib/mailauth');
const { zoneResolver } = require('../helpers/dns-zone');
const { dkimTxtRecord, privateKey } = require('../helpers/keys');
const { buildMessage } = require('../helpers/message');

const message = buildMessage({ from: 'sender@evil.example', to: 'rcpt@example.com' });

// Seals `message` with our own key, so the chain validates and the sealed values reach
// the ARC result formatting code. Anyone can do this, the sealer is not required to be trusted.
const authenticateSelfSealed = async (authResults, opts) => {
    opts = opts || {};

    const sealHeaders = await sealMessage(message, {
        signingDomain: 'evil.example',
        selector: 'test',
        privateKey: privateKey(opts.privateKey || 'private-rsa.pem'),
        algorithm: 'rsa-sha256',
        cv: 'none',
        i: 1,
        signTime: new Date(1700000000000),
        authResults: `mx.evil.example; ${authResults}`
    });

    const record = 'publicKey' in opts ? opts.publicKey : dkimTxtRecord('public-rsa.pem');

    return authenticate(Buffer.concat([sealHeaders, message]), {
        ip: '198.51.100.1',
        helo: 'evil.example',
        sender: 'sender@evil.example',
        mta: 'mx.example.com',
        disableDmarc: true,
        disableBimi: true,
        resolver: zoneResolver(record ? { 'test._domainkey.evil.example': { TXT: [[record]] } } : {})
    });
};

describe('ARC Hardening Tests', () => {
    describe('Crafted Authentication-Results values', () => {
        it('Should not throw when a dotted key turns header.i into an object', async () => {
            const result = await authenticateSelfSealed('dkim=pass header.i.x=1');

            expect(result.arc.status.result).to.equal('pass');
            // no dkdomain, because there is no usable string value for it
            expect(result.arc.status.comment).to.equal('i=1 dkim=pass');
        });

        it('Should not throw when a crafted key shadows an inherited method', async () => {
            const result = await authenticateSelfSealed('dmarc=pass header.from.toString.z=1');

            expect(result.arc.status.result).to.equal('pass');
            expect(result.arc.status.comment).to.equal('i=1 dmarc=pass');
        });

        it('Should not let a crafted key overwrite the method result', async () => {
            const result = await authenticateSelfSealed('spf=pass value.x=1; dkim=pass value.y=1; dmarc=pass value.z=1');

            expect(result.arc.status.result).to.equal('pass');
            // each of these used to render as "[object Object]" in the emitted header
            expect(result.arc.status.comment).to.equal('i=1 spf=pass dkim=pass dmarc=pass');
        });

        it('Should keep the authserv-id a string when a crafted value= part is present', async () => {
            const result = await authenticateSelfSealed('dkim=pass; value=evil');

            expect(result.arc.status.result).to.equal('pass');
            // a "value=" part used to overwrite the parsed authserv-id with an object
            expect(result.arc.authenticationResults.mta).to.equal('mx.evil.example');
        });

        it('Should still report dkdomain for a well formed header.i', async () => {
            const result = await authenticateSelfSealed('dkim=pass header.i=@ok.example');

            expect(result.arc.status.result).to.equal('pass');
            expect(result.arc.status.comment).to.equal('i=1 dkim=pass dkdomain=ok.example');
        });
    });

    describe('Public key failures', () => {
        // Every one of these used to report a bare arc=fail with no comment, because the
        // key lookup error never reached the branch that turns a code into a comment
        const cases = [
            {
                title: 'a weak sealing key',
                opts: { privateKey: 'private-small.pem', publicKey: dkimTxtRecord('public-small.pem') },
                comment: 'weak key for test._domainkey.evil.example',
                policy: { 'dkim-rules': 'weak-key' }
            },
            {
                title: 'a missing sealing key',
                opts: { publicKey: false },
                comment: 'no key for test._domainkey.evil.example'
            },
            {
                title: 'an unparseable sealing key',
                opts: { publicKey: 'v=DKIM1; k=rsa; p=bm90LWEta2V5' },
                comment: 'unknown key type for test._domainkey.evil.example'
            }
        ];

        for (let testCase of cases) {
            it(`Should report ${testCase.title}`, async () => {
                const result = await authenticateSelfSealed('dkim=pass', testCase.opts);

                expect(result.arc.status.result).to.equal('fail');
                expect(result.arc.status.comment).to.equal(testCase.comment);
                if (testCase.policy) {
                    expect(result.arc.status.policy).to.deep.equal(testCase.policy);
                }
            });
        }
    });
});
