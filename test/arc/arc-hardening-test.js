/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { authenticate, sealMessage } = require('../../lib/mailauth');
const { createSeal, arc } = require('../../lib/arc');
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

    describe('Sealing failures', () => {
        // An rsa-sha256 algorithm with an ed25519 key makes the ARC-Message-Signature fail
        // the key type check. The ARC-Seal used to be signed anyway, which left a seal
        // computed over a header that was never created, and an empty line where the header
        // should have been. (The ARC-Message-Signature used to be rsa-sha256 regardless of the
        // key, which is why ed25519-sha256 was the failing case here before ed25519 sealing
        // was supported)
        const brokenSeal = {
            signingDomain: 'evil.example',
            selector: 'test',
            privateKey: privateKey('private-ed25519.pem'),
            algorithm: 'rsa-sha256',
            cv: 'none',
            i: 1,
            authResults: 'mx.evil.example; dkim=pass'
        };

        it('Should not seal a message whose ARC-Message-Signature could not be signed', async () => {
            const { headers, errors } = await createSeal(message, { seal: Object.assign({}, brokenSeal) });

            expect(headers).to.deep.equal([]);
            expect(errors).to.have.lengthOf(1);
            expect(errors[0].err.code).to.equal('EINVALIDTYPE');
        });

        it('Should not emit a header block ending empty line instead of the missing header', async () => {
            const sealHeaders = await sealMessage(message, Object.assign({}, brokenSeal));

            expect(sealHeaders.length).to.equal(0);

            // an empty line here would push everything after it into the message body
            const sealed = Buffer.concat([sealHeaders, message]);
            const headerBlock = sealed.toString('binary').split('\r\n\r\n')[0];
            expect(headerBlock).to.include('From:');
        });
    });

    describe('createSeal result', () => {
        const seal = extra =>
            Object.assign(
                {
                    signingDomain: 'evil.example',
                    selector: 'test',
                    privateKey: privateKey('private-rsa.pem'),
                    authResults: 'mx.evil.example; dkim=pass'
                },
                extra || {}
            );

        it('Should return the instance of the created set', async () => {
            const first = await createSeal(message, { seal: seal() });
            expect(first.instance).to.equal(1);
            expect(first.headers[2]).to.match(/^ARC-Authentication-Results: i=1;/);

            const sealed = Buffer.concat([Buffer.from(first.headers.join('\r\n') + '\r\n'), message]);
            const second = await createSeal(sealed, { seal: seal({ cv: 'pass' }) });
            expect(second.errors).to.deep.equal([]);
            expect(second.instance).to.equal(2);
            expect(second.headers[2]).to.match(/^ARC-Authentication-Results: i=2;/);
        });

        it('Should not return an instance when no set was created', async () => {
            const result = await createSeal(message, { seal: seal({ i: 51 }) });
            expect(result.headers).to.deep.equal([]);
            expect(result.instance).to.be.undefined;
        });
    });

    describe('shouldSeal of a failed chain', () => {
        const failed = extra => arc(Object.assign({ chain: false, error: Object.assign(new Error('broken'), { code: 'invalid_arc_instance' }) }, extra));

        it('Should use the newest seal from the header fields when the data has it', async () => {
            expect((await failed({ latestCv: false })).status.shouldSeal).to.be.true;
            expect((await failed({ latestCv: 'pass' })).status.shouldSeal).to.be.true;
            expect((await failed({ latestCv: 'fail' })).status.shouldSeal).to.be.false;
        });

        it('Should use the parsed chain for data without latestCv', async () => {
            expect((await failed({})).status.shouldSeal).to.be.false;
            const lastEntry = { i: 1, 'arc-seal': { parsed: { cv: { value: 'none' } } } };
            expect((await failed({ lastEntry })).status.shouldSeal).to.be.true;
        });
    });
});
