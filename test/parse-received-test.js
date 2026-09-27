/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

let { parseReceived, getClientAddress } = require('../lib/parse-received');
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
            it(`Should find ${entry.ip || 'no address'} in ${entry.mta}`, async () => {
                const res = parseReceived(entry.header);
                expect(res.from.value).to.equal(entry.from);
                expect(getClientAddress(res.from)).to.equal(entry.ip);
            });
        }

        it('Should never use an address literal given as the HELO value', async () => {
            expect(getClientAddress({ value: 'x', comment: 'helo=[203.0.113.5]' })).to.be.false;
            expect(getClientAddress({ value: 'x', comment: 'port=1 ehlo=[203.0.113.5]' })).to.be.false;
            expect(getClientAddress({ value: 'x', comment: '[192.0.2.1] helo=[203.0.113.5]' })).to.equal('192.0.2.1');
        });

        it('Should skip an address literal that is not an IP address', async () => {
            expect(getClientAddress({ value: 'x', comment: 'rdns.example [192.0.2.1] [unknown]' })).to.equal('192.0.2.1');
            expect(getClientAddress({ value: 'x', comment: '[999.0.0.1]' })).to.be.false;
            expect(getClientAddress(undefined)).to.be.false;
        });
    });
});
