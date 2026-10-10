/* eslint no-unused-expressions:0 */
'use strict';

const { Readable } = require('node:stream');
const chai = require('chai');
const expect = chai.expect;

const { authenticate, dkim2Sign, dkim2Verify, dkim2Hash, Dkim2SignStream } = require('../../lib/mailauth');
const { resolver, message, originatorOptions, signMessage } = require('../helpers/dkim2');

chai.config.includeStack = true;

const baseOptions = () => ({
    resolver: resolver(),
    ip: '192.0.2.1',
    helo: 'mail.example.com',
    sender: 'sender@example.com',
    mta: 'mx.example.net',
    disableArc: true,
    disableBimi: true,
    disableDmarc: true
});

describe('DKIM2 in authenticate()', () => {
    it('exports the DKIM2 functions', () => {
        expect(dkim2Sign).to.be.a('function');
        expect(dkim2Verify).to.be.a('function');
        expect(Dkim2SignStream).to.be.a('function');
        expect(dkim2Hash).to.be.a('function');
    });

    it('does not verify DKIM2 unless asked to', async () => {
        let signed = await signMessage(message(), originatorOptions());
        let result = await authenticate(signed, baseOptions());
        expect(result.dkim2).to.equal(false);
        expect(result.headers).to.not.include('dkim2=');
    });

    it('verifies DKIM2 with the envelope and adds the result to Authentication-Results', async () => {
        let signed = await signMessage(message(), originatorOptions());
        let result = await authenticate(Readable.from([signed]), Object.assign(baseOptions(), { dkim2: true, rcptTo: ['rcpt@example.net'] }));
        expect(result.dkim2.status.result).to.equal('pass');
        expect(result.headers).to.include('dkim2=pass (i=1 example.com pass) header.d=example.com');
        // DKIM1 still ran on the same input
        expect(result.dkim.results).to.be.an('array');
    });

    it('warns when authenticate() has the MAIL FROM but not the RCPT TO', async () => {
        let signed = await signMessage(message(), originatorOptions());
        let result = await authenticate(signed, Object.assign(baseOptions(), { dkim2: true }));
        expect(result.dkim2.status.result).to.equal('pass');
        expect(result.dkim2.status.warnings).to.deep.equal(['rcpt-to-not-checked']);
        expect(result.headers).to.not.include('not-checked');
    });

    it('reports a chain of custody mismatch with the SMTP envelope', async () => {
        let signed = await signMessage(message(), originatorOptions());
        let result = await authenticate(signed, Object.assign(baseOptions(), { dkim2: true, sender: 'other@example.com' }));
        expect(result.dkim2.status.result).to.equal('permerror');
        expect(result.headers).to.include('dkim2=permerror');
        expect(result.headers).to.include('header.i=1');
    });

    it('passes the DKIM2 options through', async () => {
        let signed = await signMessage(message(), originatorOptions({ signTime: new Date('2026-01-01T00:00:00Z') }));
        let result = await authenticate(signed, Object.assign(baseOptions(), { dkim2: true, dkim2Options: { curTime: new Date('2026-01-02T00:00:00Z') } }));
        expect(result.dkim2.status.result).to.equal('pass');

        let expired = await authenticate(signed, Object.assign(baseOptions(), { dkim2: true }));
        expect(expired.dkim2.status.comment).to.equal('DKIM2-Signature i=1 signature expired');
    });

    it('reports dkim2=none for a message without DKIM2', async () => {
        let result = await authenticate(message(), Object.assign(baseOptions(), { dkim2: true }));
        expect(result.dkim2.status.result).to.equal('none');
        expect(result.headers).to.include('dkim2=none');
    });
});
