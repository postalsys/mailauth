/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;
const libmime = require('libmime');

const { authenticate, dkimSign, dkimVerify } = require('../../lib/mailauth');
const { parseHeaders } = require('../../lib/tools');
const { zoneResolver } = require('../helpers/dns-zone');
const { dkimTxtRecord, privateKey } = require('../helpers/keys');

chai.config.includeStack = true;

// Where mailauth and the parser that later reads the message disagree about the shape of
// the header block, a signature can be made to cover something other than what a person
// ends up seeing. Every case here has to resolve the same way: not as a pass.

describe('DKIM header smuggling Tests', () => {
    const resolver = zoneResolver({
        'test._domainkey.example.com': { TXT: [[dkimTxtRecord('public-rsa.pem')]] },
        '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] },
        'example.com': { A: ['192.0.2.1'] }
    });

    const signOptions = {
        signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: privateKey('private-rsa.pem'), algorithm: 'rsa-sha256' }]
    };

    describe('A line an MUA appends to the header above it', () => {
        const message = 'From: real@example.com\r\nSubject: hello\r\n\r\nbody\r\n';

        // Everything JS \s matches, and so libmime folds in, in every spelling it has on
        // the wire. A test on the leading byte alone catches only the first three of these
        for (const bytes of [
            '\x0b', // vertical tab
            '\x0c', // form feed
            '\r', // a carriage return left by a lone <LF> line ending
            '\xa0', // latin1 NBSP
            '\xc2\xa0', // UTF-8 NBSP
            '\xe3\x80\x80', // UTF-8 ideographic space
            '\xe2\x80\xa8', // UTF-8 line separator
            '\xe2\x81\x9f' // UTF-8 medium mathematical space
        ]) {
            it(`Should not verify content appended after a signed header with ${JSON.stringify(bytes)}`, async () => {
                const { signatures } = await dkimSign(Buffer.from(message), signOptions);
                const tampered = (signatures + message).replace('From: real@example.com\r\n', `From: real@example.com\r\n${bytes}, evil@attacker.test\r\n`);

                const result = await dkimVerify(Buffer.from(tampered, 'binary'), { resolver });
                expect(result.results).to.have.lengthOf(1);
                expect(result.results[0].status.result).to.equal('fail');
            });
        }

        it('Should keep a non-ASCII line inside the value libmime reads', async () => {
            // the byte class this used to test only ever saw the first byte, so a UTF-8
            // spelling of the same character walked straight past it
            const tampered = message.replace('From: real@example.com\r\n', 'From: real@example.com\r\n\xc2\xa0, evil@attacker.test\r\n');
            const parsed = parseHeaders(Buffer.from(tampered.split('\r\n\r\n')[0], 'binary')).parsed;

            expect(parsed.map(row => row.key)).to.deep.equal(['from', 'subject']);
            expect(parsed[0].line.toString('binary')).to.include('evil@attacker.test');
        });

        it('Should read the From the same way libmime does', async () => {
            const tampered = message.replace('From: real@example.com\r\n', 'From: real@example.com\r\n\xa0, evil@attacker.test\r\n');
            const decoded = libmime.decodeHeaders(tampered.split('\r\n\r\n')[0]);

            // libmime folds the line in, so the value carries both addresses. mailauth has
            // to see the same bytes or the signature covers something else than is read
            expect(decoded.from[0]).to.include('evil@attacker.test');

            const result = await authenticate(Buffer.from(tampered, 'binary'), {
                ip: '198.51.100.7',
                helo: 'mail.attacker.test',
                mta: 'mx.test',
                sender: 'nobody@attacker.test',
                resolver
            });

            expect(result.dkim.headers.parsed.map(row => row.key)).to.deep.equal(['from', 'subject']);
        });
    });

    describe('A header whose colon sits on a folded continuation line', () => {
        // every MUA unfolds this and shows a From, so DMARC has to find one too
        const message = 'From\r\n : boss@example.com\r\nSubject: t\r\n\r\nbody\r\n';

        it('Should apply the DMARC policy of the domain in the folded From', async () => {
            const result = await authenticate(Buffer.from(message), {
                ip: '198.51.100.7',
                helo: 'mail.attacker.test',
                mta: 'mx.test',
                sender: 'nobody@attacker.test',
                resolver
            });

            expect(result.dmarc.status.result).to.equal('fail');
            expect(result.dmarc.domain).to.equal('example.com');
            expect(result.headers).to.include('dmarc=fail');
        });

        it('Should sign the folded From rather than leaving it out of h=', async () => {
            const { signatures } = await dkimSign(Buffer.from(message), signOptions);

            // the fold CRLF used to end up inside the key, and the header was then left
            // out of h= entirely, which RFC 6376 section 5.4 forbids
            expect(signatures.replace(/\r\n /g, '')).to.include('h=Subject: From;');

            const result = await dkimVerify(Buffer.from(signatures + message), { resolver });
            expect(result.results[0].status.result).to.equal('pass');
        });
    });
});
