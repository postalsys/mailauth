/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

let { parseReceived, getClientAddress, getClientHelo } = require('../lib/parse-received');
const mtaFormats = require('./fixtures/received/mta-formats.json');

chai.config.includeStack = true;

describe('parseRecived Tests', () => {
    it('Should parse header from Haraka', async () => {
        const res = parseReceived(`Received: from mail-oi1-f179.google.com (mail-oi1-f179.google.com [209.85.167.179])
	by zonemx.eu (Haraka/2.8.25) with ESMTPS id B3C0198B-A390-42E9-9DDC-C57D8D207298.1
	envelope-from <andris.reinman@gmail.com>
	(cipher=TLS_AES_256_GCM_SHA384);
	Fri, 06 Nov 2020 12:20:14 +0000`);

        expect(res).to.deep.equal({
            from: {
                value: 'mail-oi1-f179.google.com',
                comment: 'mail-oi1-f179.google.com [209.85.167.179]'
            },
            by: { value: 'zonemx.eu', comment: 'Haraka/2.8.25' },
            with: { value: 'ESMTPS' },
            id: { value: 'B3C0198B-A390-42E9-9DDC-C57D8D207298.1' },
            tls: { value: '', comment: 'cipher=TLS_AES_256_GCM_SHA384' },
            'envelope-from': { value: '<andris.reinman@gmail.com>' },
            timestamp: 'Fri, 06 Nov 2020 12:20:14 +0000',
            full: 'Received: from mail-oi1-f179.google.com (mail-oi1-f179.google.com [209.85.167.179]) by zonemx.eu (Haraka/2.8.25) with ESMTPS id B3C0198B-A390-42E9-9DDC-C57D8D207298.1 envelope-from <andris.reinman@gmail.com> (cipher=TLS_AES_256_GCM_SHA384); Fri, 06 Nov 2020 12:20:14 +0000'
        });
    });

    it('Should keep the transport security of a hop with an unusable key', async () => {
        const res = parseReceived('Received: __proto__ (version=TLS1_3 cipher=X) by mx.example.com; Mon, 1 Jan 2024 00:00:00 +0000');

        expect(res.tls).to.deep.equal({ value: '', comment: 'version=TLS1_3 cipher=X' });
        // the key itself is not assigned, it would replace the prototype of the parsed hop
        expect(Object.getPrototypeOf(res)).to.equal(Object.prototype);
        expect(Object.keys(res)).to.not.contain('__proto__');
    });

    it('Should not read an apostrophe as a quote', async () => {
        const res = parseReceived(
            "Received: from a.example (a.example [192.0.2.1]) by mx.example with ESMTP id 1 for <o'brien@example.com>; Mon, 21 Sep 2026 10:00:00 +0000"
        );
        expect(res.for).to.deep.equal({ value: "<o'brien@example.com>" });
        expect(res.timestamp).to.equal('Mon, 21 Sep 2026 10:00:00 +0000');
    });

    it('Should keep a quoted local-part as it is', async () => {
        const res = parseReceived(
            'Received: from a.example (a.example [192.0.2.1]) by mx.example with ESMTP id 1 for <"x;y"@example.com>; Mon, 21 Sep 2026 10:00:00 +0000'
        );
        expect(res.for).to.deep.equal({ value: '<"x;y"@example.com>' });
        expect(res.timestamp).to.equal('Mon, 21 Sep 2026 10:00:00 +0000');
    });

    it('Should keep every comment of the from clause', async () => {
        const res = parseReceived(
            'Received: from x([203.0.113.5]) (unknown [198.51.100.7]) by mx.example (Postfix) with ESMTP id 1; Mon, 21 Sep 2026 10:00:00 +0000'
        );
        expect(res.from).to.deep.equal({ value: 'x', comment: '[203.0.113.5] unknown [198.51.100.7]' });
        expect(res.by).to.deep.equal({ value: 'mx.example', comment: 'Postfix' });
    });

    describe('Client address of real MTA formats (RFC 5321 section 4.4 TCP-info)', () => {
        for (const entry of mtaFormats) {
            it(`Should find ${entry.ip || 'no address'} and HELO ${entry.helo || 'none'} in ${entry.mta}`, async () => {
                const res = parseReceived(entry.header);
                expect(res.from.value).to.equal(entry.from);
                expect(getClientAddress(res)).to.equal(entry.ip);
                expect(getClientHelo(res)).to.equal(entry.helo);
            });
        }

        it('Should read the current value of a parsed header that was changed', async () => {
            const res = parseReceived('Received: from a.example (a.example [192.0.2.1]) by mx.example.net with ESMTP id 1; Mon, 21 Sep 2026 10:00:00 +0000');
            expect(getClientAddress(res)).to.equal('192.0.2.1');
            expect(getClientHelo(res)).to.equal('a.example');
            const other = parseReceived('Received: from b.example (b.example [192.0.2.2]) by mx.example.net with ESMTP id 1; Mon, 21 Sep 2026 10:00:00 +0000');
            res.full = other.full;
            res.from = other.from;
            expect(getClientAddress(res)).to.equal('192.0.2.2');
            expect(getClientHelo(res)).to.equal('b.example');
        });

        const clientAddress = from =>
            getClientAddress(parseReceived(`Received: from ${from} by mx.example.net with ESMTP id 1; Mon, 21 Sep 2026 10:00:00 +0000`));

        it('Should never use an address literal given as the HELO value', async () => {
            expect(clientAddress('x (helo=[203.0.113.5])')).to.be.false;
            expect(clientAddress('x (port=1 ehlo=[203.0.113.5])')).to.be.false;
            expect(clientAddress('x ([192.0.2.1] helo=[203.0.113.5])')).to.equal('192.0.2.1');
        });

        it('Should skip an address literal that is not an IP address', async () => {
            expect(clientAddress('x (rdns.example [192.0.2.1] [unknown])')).to.equal('192.0.2.1');
            expect(clientAddress('x ([999.0.0.1])')).to.be.false;
            expect(getClientAddress(undefined)).to.be.false;
            expect(getClientAddress({ from: { value: 'x', comment: '[192.0.2.1]' } })).to.be.false;
        });

        it('Should not use an address from a HELO that contains a TCP-info comment and a by keyword', async () => {
            // the client sent "HELO x (a [6.6.6.6]) by", which Postfix copies as it is
            expect(clientAddress('x (a [6.6.6.6]) by (unknown [192.0.2.1])')).to.be.false;
            // the client sent "HELO x (y [6.6.6.6]", the comment is never closed
            expect(clientAddress('x (y [6.6.6.6] (unknown [192.0.2.1])')).to.be.false;
            expect(
                getClientAddress(
                    parseReceived(
                        'Received: from x (y [6.6.6.6] (unknown [192.0.2.1]) by mx.example.com (Postfix) with ESMTP id ABC for <u@[6.6.6.7]>; Thu, 1 Jan 2026 00:00:00 +0000'
                    )
                )
            ).to.be.false;
        });

        it('Should not use an address from a header that can not be split unambiguously', async () => {
            // a quoted string or a backslash in the from clause
            expect(clientAddress('x "y" (unknown [192.0.2.1])')).to.be.false;
            expect(clientAddress('x\\ (unknown [192.0.2.1])')).to.be.false;
            expect(clientAddress('x (unknown\\ [192.0.2.1])')).to.be.false;
            // an unclosed quoted string after the by keyword
            expect(getClientAddress(parseReceived('Received: from x (unknown [192.0.2.1]) by mx " by y; Mon, 21 Sep 2026 10:00:00 +0000'))).to.be.false;
            // by not followed by a host name
            expect(getClientAddress(parseReceived('Received: from x (unknown [192.0.2.1]) by (mx); Mon, 21 Sep 2026 10:00:00 +0000'))).to.be.false;
            // no by keyword at all
            expect(getClientAddress(parseReceived('Received: from x (unknown [192.0.2.1]); Mon, 21 Sep 2026 10:00:00 +0000'))).to.be.false;
            // the client sent "HELO (a [6.6.6.6]) by mx ;", which ends the from clause early
            expect(
                getClientAddress(
                    parseReceived('Received: from (a [6.6.6.6]) by mx ; (unknown [192.0.2.1]) by mx.example (Postfix); Mon, 21 Sep 2026 10:00:00 +0000')
                )
            ).to.be.false;
            // the client sent "HELO x ; (", which hides the rest of the header in a comment
            expect(getClientAddress(parseReceived('Received: from x ; ( (unknown [192.0.2.1]) by mx.example (Postfix); Mon, 21 Sep 2026 10:00:00 +0000'))).to.be
                .false;
            // the same address twice is not ambiguous
            expect(clientAddress('[192.0.2.1] (unknown [192.0.2.1]) ([192.0.2.1])')).to.equal('192.0.2.1');
        });

        it('Should not use an address from the HELO in the Exim layout without reverse DNS', async () => {
            // Exim, a client at 192.0.2.66 sent "HELO (unknown [6.6.6.6])x"
            expect(clientAddress('[192.0.2.66] (helo=(unknown [6.6.6.6])x)')).to.be.false;
            // Exim, a client at 192.0.2.66 sent "HELO x) (unknown [6.6.6.6]", which reads the
            // same as Postfix with the HELO "[192.0.2.66] (helo=x)" from 6.6.6.6
            expect(clientAddress('[192.0.2.66] (helo=x) (unknown [6.6.6.6])')).to.be.false;
            // "HELO )mail([6.6.6.6]" adds a word to the from clause
            expect(clientAddress('[192.0.2.66] (helo=)mail([6.6.6.6])')).to.be.false;
            // the same address in a comment is not ambiguous
            expect(clientAddress('[192.0.2.66] (helo=x) ([192.0.2.66])')).to.equal('192.0.2.66');
            // no "helo=" comment, Postfix with an address literal HELO
            expect(clientAddress('[203.0.113.5] (unknown [198.51.100.7])')).to.equal('198.51.100.7');
        });
    });
});
