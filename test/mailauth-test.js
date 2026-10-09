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
// signature aligns under relaxed alignment but not under strict alignment. The Tree Walk
// only makes example.com the Organizational Domain when it publishes a record of its own.
const authenticateWith = async (dmarcRecord, zone = { '_dmarc.example.com': { TXT: [['v=DMARC1; p=none']] } }) => {
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
            '_dmarc.mail.example.com': { TXT: [[dmarcRecord]] },
            ...zone
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

    it('Should not report an org level signature as aligned when the Tree Walk stops at the author domain', async () => {
        // example.com publishes no record, so mail.example.com is its own Organizational Domain
        // (RFC 9989 4.10.2) even though the Public Suffix List would say example.com
        const result = await authenticateWith('v=DMARC1; p=reject', {});

        expect(result.dkim.results[0].status.result).to.equal('pass');
        expect(result.dkim.results[0].status.aligned).to.be.false;
        expect(result.dmarc.status.result).to.equal('fail');
        expect(result.dmarc.domain).to.equal('mail.example.com');
        expect(result.dmarc.alignment.dkim.result).to.be.undefined;
    });

    it('Should report a signature as aligned when the Tree Walk finds an org domain the Public Suffix List does not', async () => {
        // blogspot.com is a private suffix on the Public Suffix List, but it publishes a DMARC
        // record, so the Tree Walk makes it the Organizational Domain of its subdomains
        const { signatures } = await dkimSign(buildMessage({ from: 'user@alice.blogspot.com', to: 'rcpt@example.net' }), {
            signatureData: [{ signingDomain: 'blogspot.com', selector: 'test', privateKey: privateKey('private-rsa.pem'), algorithm: 'rsa-sha256' }]
        });

        const result = await authenticate(Buffer.concat([Buffer.from(signatures), buildMessage({ from: 'user@alice.blogspot.com', to: 'rcpt@example.net' })]), {
            ip: '198.51.100.1',
            helo: 'mail.example.com',
            sender: 'user@alice.blogspot.com',
            mta: 'mx.example.net',
            disableBimi: true,
            resolver: zoneResolver({
                'test._domainkey.blogspot.com': { TXT: [[dkimTxtRecord('public-rsa.pem')]] },
                '_dmarc.blogspot.com': { TXT: [['v=DMARC1; p=reject']] }
            })
        });

        expect(result.dkim.results[0].status.result).to.equal('pass');
        expect(result.dkim.results[0].status.aligned).to.equal('blogspot.com');
        expect(result.dmarc.status.result).to.equal('pass');
        expect(result.dmarc.policy).to.equal('reject');
        expect(result.dmarc.domain).to.equal('blogspot.com');
    });

    describe('strict option', () => {
        const signWith = async (algorithm, msg = message) => {
            const { signatures } = await dkimSign(msg, {
                signatureData: [{ signingDomain: 'mail.example.com', selector: 'test', privateKey: privateKey('private-rsa.pem'), algorithm }]
            });
            return Buffer.concat([Buffer.from(signatures), msg]);
        };

        const run = (input, extra) =>
            authenticate(
                input,
                Object.assign(
                    {
                        ip: '198.51.100.1',
                        helo: 'mail.example.com',
                        sender: 'user@mail.example.com',
                        mta: 'mx.example.net',
                        disableBimi: true,
                        resolver: zoneResolver({
                            'test._domainkey.mail.example.com': { TXT: [[dkimTxtRecord('public-rsa.pem')]] },
                            '_dmarc.mail.example.com': { TXT: [['v=DMARC1; p=reject']] }
                        })
                    },
                    extra
                )
            );

        it('Should accept an rsa-sha1 signature by default and mark it', async () => {
            const result = await run(await signWith('rsa-sha1'));
            expect(result.dkim.results[0].status.result).to.equal('pass');
            expect(result.dkim.results[0].status.warnings).to.deep.equal(['rsa-sha1']);
            expect(result.dmarc.status.result).to.equal('pass');
            // the marker is never written into the header
            expect(result.headers).to.include('dkim=pass header.i=@mail.example.com header.s=test header.a=rsa-sha1 header.b=');
        });

        it('Should pass strict to the DKIM verification', async () => {
            const result = await run(await signWith('rsa-sha1'), { strict: true });
            expect(result.dkim.results[0].status.result).to.equal('policy');
            expect(result.dkim.results[0].status.policy).to.deep.equal({ 'dkim-rules': 'weak-algorithm' });
            expect(result.headers).to.include('dkim=policy (weak algorithm) policy.dkim-rules=weak-algorithm');
            expect(result.dmarc.status.result).to.equal('fail');
        });

        it('Should pass rejectRsaSha1 to the DKIM verification and keep the lenient defaults', async () => {
            const result = await run(await signWith('rsa-sha1'), { rejectRsaSha1: true });
            expect(result.dkim.results[0].status.result).to.equal('policy');
            expect(result.dkim.results[0].status.policy).to.deep.equal({ 'dkim-rules': 'weak-algorithm' });
            // the only DKIM signature does not count, so DMARC has nothing aligned
            expect(result.dmarc.status.result).to.equal('fail');
            // everything else is the default mode, for example the header order and header.i without header.d
            expect(result.headers).to.match(/^Received-SPF: /);
            expect(result.dkim.results[0].info).to.match(/^dkim=policy \(weak algorithm\) policy\.dkim-rules=weak-algorithm header\.i=@mail\.example\.com /);
        });

        it('Should put Authentication-Results above Received-SPF only in strict mode', async () => {
            // RFC 8601 section 5: above any other trace header field
            let result = await run(await signWith('rsa-sha256'));
            expect(result.headers).to.match(/^Received-SPF: /);
            expect(result.headers).to.match(/\r\nAuthentication-Results: mx\.example\.net;/);

            result = await run(await signWith('rsa-sha256'), { strict: true });
            expect(result.headers).to.match(/^Authentication-Results: mx\.example\.net;/);
            expect(result.headers).to.match(/\r\nReceived-SPF: /);
        });

        it('Should report the AUID and SDID in strict mode', async () => {
            let result = await run(await signWith('rsa-sha256'), { strict: true });
            expect(result.dkim.results[0].info).to.match(/^dkim=pass header\.d=mail\.example\.com header\.i=@mail\.example\.com header\.s=test /);
            result = await run(await signWith('rsa-sha256'));
            expect(result.dkim.results[0].info).to.match(/^dkim=pass header\.i=@mail\.example\.com header\.s=test /);
        });
    });

    describe('Header line length', () => {
        it('Should keep every generated line within 998 octets (RFC 5322 section 2.1.1)', async () => {
            for (let local of ['a'.repeat(1100), 'ü'.repeat(600), '('.repeat(700), `"${'word '.repeat(300)}"`]) {
                for (let strict of [false, true]) {
                    const result = await authenticate(message, {
                        ip: '198.51.100.1',
                        helo: 'h'.repeat(1000) + '.example',
                        sender: `${local}@mail.example.com`,
                        mta: 'mx.example.net',
                        strict,
                        disableBimi: true,
                        resolver: zoneResolver({})
                    });
                    for (let line of result.headers.split('\r\n')) {
                        expect(Buffer.byteLength(line), line.slice(0, 60)).to.be.at.most(998);
                    }
                    // the comments stay balanced, so the results after them are not hidden
                    expect(result.headers).to.include('dmarc=');
                }
            }
        });
    });

    describe('Authentication-Results authserv-id', () => {
        it('Should quote an mta value that is not a token', async () => {
            let res = await authenticate(message, {
                ip: '198.51.100.1',
                sender: 'user@mail.example.com',
                mta: 'mx.example; dkim=pass header.d=bank.example',
                resolver: zoneResolver({})
            });
            expect(res.headers).to.include('Authentication-Results: "mx.example; dkim=pass header.d=bank.example";\r\n');
        });

        it('Should refuse an mta value that is not a token in strict mode', async () => {
            let error;
            try {
                await authenticate(message, {
                    ip: '198.51.100.1',
                    sender: 'user@mail.example.com',
                    mta: 'mx.example; dkim=pass header.d=bank.example',
                    resolver: zoneResolver({}),
                    strict: true
                });
            } catch (err) {
                error = err;
            }
            expect(error).to.exist;
            expect(error.code).to.equal('EINVALIDAUTHSERVID');
        });

        it('Should keep a host name mta value as is', async () => {
            let res = await authenticate(message, {
                ip: '198.51.100.1',
                sender: 'user@mail.example.com',
                mta: 'mx.example.com',
                resolver: zoneResolver({})
            });
            expect(res.headers).to.include('Authentication-Results: mx.example.com;\r\n');
        });
    });

    describe('Author domain', () => {
        const runFrom = from =>
            authenticate(Buffer.from(`${from}Subject: x\r\n\r\nhi\r\n`), {
                ip: '192.0.2.1',
                helo: 'h.attacker.example',
                sender: 'x@attacker.example',
                mta: 'mx.example.net',
                disableBimi: true,
                resolver: zoneResolver({ '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] } })
            });

        it('Should evaluate DMARC for the mailbox of a group From (RFC 6854)', async () => {
            const result = await runFrom('From: Bank: CEO <ceo@bank.example>;\r\n');
            expect(result.dkim.headerFrom).to.deep.equal(['ceo@bank.example']);
            expect(result.dmarc.status.result).to.equal('fail');
            expect(result.dmarc.policy).to.equal('reject');
            expect(result.headers).to.include('dmarc=fail');
        });

        it('Should say why DMARC was not evaluated', async () => {
            let result = await runFrom('From: a@bank.example, b@other.example\r\n');
            expect(result.dmarc).to.be.false;
            expect(result.dmarcSkipReason).to.equal('multiple-author-domains');

            result = await runFrom('');
            expect(result.dmarc).to.be.false;
            expect(result.dmarcSkipReason).to.equal('no-author-domain');

            result = await runFrom('From: "Bank CEO" <ceo@bank.example;>, a@attacker.example\r\n');
            expect(result.dmarc).to.be.false;
            expect(result.dmarcSkipReason).to.equal('invalid-author-domain');
        });

        it('Should not evaluate DMARC for a message with several From header fields', async () => {
            // a prepended From of the same domain must not borrow the DMARC result of the
            // signed bottom-most From (RFC 5322 3.6, RFC 6376 5.4.2, RFC 9989 11.5)
            const result = await runFrom('From: "Bank Security" <security@bank.example>\r\nFrom: news@bank.example\r\n');
            expect(result.dkim.fromFields).to.equal(2);
            expect(result.dmarc).to.be.false;
            expect(result.dmarcSkipReason).to.equal('multiple-from-fields');
            expect(result.headers).to.not.include('dmarc=');
        });

        it('Should still evaluate several mailboxes of one domain in a single From field', async () => {
            const result = await runFrom('From: a@bank.example, b@bank.example\r\n');
            expect(result.dkim.fromFields).to.equal(1);
            expect(result.dmarc.status.result).to.equal('fail');
        });

        it('Should not take header fields after a leading empty line as the header section', async () => {
            // RFC 5322 section 2.1: the header section is empty and the From is body
            const result = await runFrom('\r\nFrom: ceo@bank.example\r\n');
            expect(result.dkim.headerFrom).to.deep.equal([]);
            expect(result.dmarc).to.be.false;
        });
    });

    describe('trustReceived', () => {
        const mtaFormats = require('./fixtures/received/mta-formats.json');
        const REAL = '192.0.2.66';
        const resolver = zoneResolver({
            'bank.example': { TXT: [['v=spf1 ip4:203.0.113.5 -all']] },
            '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] }
        });

        for (const entry of mtaFormats.filter(entry => entry.ip === REAL)) {
            it(`Should use the connecting address of ${entry.mta}, not the HELO literal`, async () => {
                const result = await authenticate(Buffer.from(`${entry.header}\r\nFrom: ceo@bank.example\r\nSubject: x\r\n\r\nhi\r\n`), {
                    trustReceived: true,
                    sender: 'ceo@bank.example',
                    mta: 'mx.receiver.example',
                    resolver,
                    disableArc: true,
                    disableBimi: true
                });
                expect(result.spf['client-ip']).to.equal(REAL);
                expect(result.spf.status.result).to.equal('fail');
                expect(result.dmarc.status.result).to.equal('fail');
            });
        }

        for (const helo of ['x (a [203.0.113.5]) by', 'x (y [203.0.113.5]']) {
            it(`Should not take a client address from the HELO "${helo}"`, async () => {
                // Postfix copies the HELO argument as it is, and writes the TCP-info comment after it
                const header = `Received: from ${helo} (unknown [${REAL}]) by mx.receiver.example (Postfix) with ESMTP id ABC for <u@[203.0.113.5]>; Thu, 1 Jan 2026 00:00:00 +0000`;
                const result = await authenticate(Buffer.from(`${header}\r\nFrom: ceo@bank.example\r\nSubject: x\r\n\r\nhi\r\n`), {
                    trustReceived: true,
                    sender: 'ceo@bank.example',
                    mta: 'mx.receiver.example',
                    resolver,
                    disableArc: true,
                    disableBimi: true
                });
                expect(result.spf['client-ip']).to.be.undefined;
                expect(result.spf.status.result).to.not.equal('pass');
                expect(result.dmarc.status.result).to.equal('fail');
            });
        }

        describe('HELO name', () => {
            const heloResolver = zoneResolver({ 'mail.sender.test': { TXT: [['v=spf1 ip4:192.0.2.1 -all']] } });
            const run = (header, opts) =>
                authenticate(Buffer.from(`${header}\r\nFrom: a@sender.test\r\nTo: rcpt@receiver.test\r\nSubject: t\r\n\r\nhello\r\n`), {
                    trustReceived: true,
                    mta: 'mx.receiver.test',
                    resolver: heloResolver,
                    disableArc: true,
                    disableBimi: true,
                    ...opts
                });
            const postfix =
                'Received: from mail.sender.test (rdns.sender.test [192.0.2.1])\r\n\tby mx.receiver.test (Postfix) with ESMTPS id 1234\r\n\tfor <rcpt@receiver.test>; Thu, 08 Oct 2026 10:00:00 +0000';

            it('Should take the HELO name together with the address', async () => {
                const result = await run(postfix);
                expect(result.spf['client-ip']).to.equal('192.0.2.1');
                expect(result.spf.helo).to.equal('mail.sender.test');
                // null reverse-path, the HELO identity is checked (RFC 7208 section 2.4)
                expect(result.spf.domain).to.equal('mail.sender.test');
                expect(result.spf.status.result).to.equal('pass');
            });

            it('Should take the HELO name of Exim from the helo= value', async () => {
                const result = await run(
                    'Received: from rdns.sender.test ([192.0.2.1] helo=mail.sender.test)\r\n\tby mx.receiver.test with esmtp (Exim 4.96)\r\n\tid 1abcDE-000001-AB; Thu, 08 Oct 2026 10:00:00 +0000'
                );
                expect(result.spf['client-ip']).to.equal('192.0.2.1');
                expect(result.spf.helo).to.equal('mail.sender.test');
                expect(result.spf.status.result).to.equal('pass');
            });

            it('Should keep the HELO name the caller provided', async () => {
                const result = await run(postfix, { helo: 'other.sender.test' });
                expect(result.spf['client-ip']).to.equal('192.0.2.1');
                expect(result.spf.helo).to.equal('other.sender.test');
            });

            it('Should not combine the HELO name of the header with the address the caller provided', async () => {
                const result = await run(postfix, { ip: '198.51.100.1' });
                expect(result.spf['client-ip']).to.equal('198.51.100.1');
                expect(result.spf.helo).to.equal('[198.51.100.1]');
            });
        });
    });

    describe('ARC sealing', () => {
        it('Should not add a 51st ARC set (RFC 8617 section 4.2.1)', async function () {
            this.timeout(60000);

            const seal = { signingDomain: 'example.com', selector: 'test', privateKey: privateKey('private-rsa.pem') };
            const resolver = zoneResolver({ 'test._domainkey.example.com': { TXT: [[dkimTxtRecord('public-rsa.pem')]] } });
            const opts = {
                ip: '198.51.100.1',
                helo: 'mail.example.com',
                sender: 'user@mail.example.com',
                mta: 'mx.example.net',
                disableBimi: true,
                resolver,
                seal
            };

            let msg = message;
            for (let i = 1; i <= 50; i++) {
                const result = await authenticate(msg, opts);
                expect(result.arc.sealErrors, `i=${i}`).to.be.undefined;
                expect(result.headers, `i=${i}`).to.include(`ARC-Seal: i=${i};`);
                msg = Buffer.concat([Buffer.from(result.headers), msg]);
            }

            const result = await authenticate(msg, opts);
            // the 50 sets validate, and no 51st one is added
            expect(result.arc.status.result).to.equal('pass');
            expect(result.arc.i).to.equal(50);
            expect(result.headers).to.not.include('ARC-Seal:');
            expect(result.arc.sealErrors).to.have.lengthOf(1);
            expect(result.arc.sealErrors[0].type).to.equal('ARC');
            expect(result.arc.sealErrors[0].err.code).to.equal('EINVALIDINSTANCE');
            expect(result.arc.sealErrors[0].err.message).to.equal('Can not add ARC set i=51, the chain already has 50 sets');
        });
    });
});
