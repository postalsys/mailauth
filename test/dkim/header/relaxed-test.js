/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { relaxedHeaders } = require('../../../lib/dkim/header/relaxed');

chai.config.includeStack = true;

describe('DKIM Relaxed Header Canonicalization Tests', () => {
    describe('Header normalization', () => {
        it('Should lowercase header names', () => {
            const signingHeaderLines = {
                keys: 'From: Subject',
                headers: [
                    { line: Buffer.from('FROM: user@example.com', 'binary') },
                    { line: Buffer.from('SUBJECT: Test Email', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('from:');
            expect(canonicalized).to.include('subject:');
            expect(canonicalized).not.to.include('FROM:');
            expect(canonicalized).not.to.include('SUBJECT:');
        });

        it('Should trim whitespace around colon', () => {
            const signingHeaderLines = {
                keys: 'Subject',
                headers: [
                    { line: Buffer.from('Subject  :   Test Email', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('subject:Test Email');
        });

        it('Should collapse multiple spaces to single space', () => {
            const signingHeaderLines = {
                keys: 'Subject',
                headers: [
                    { line: Buffer.from('Subject: Multiple    Spaces    Here', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('subject:Multiple Spaces Here');
        });

        it('Should unfold folded headers', () => {
            const signingHeaderLines = {
                keys: 'Subject',
                headers: [
                    { line: Buffer.from('Subject: This is a very long subject\r\n that was folded', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            // The first header should be unfolded and collapsed
            expect(canonicalized).to.include('subject:');
            expect(canonicalized).to.include('This is a very long subject');
        });

        it('Should trim trailing whitespace', () => {
            const signingHeaderLines = {
                keys: 'Subject',
                headers: [
                    { line: Buffer.from('Subject: Test Email   ', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            // Check it doesn't end with spaces before CRLF
            expect(canonicalized).to.match(/subject:Test Email\r\n/);
        });

        it('Should handle tabs as whitespace', () => {
            const signingHeaderLines = {
                keys: 'Subject',
                headers: [
                    { line: Buffer.from('Subject:\tTest\t\tEmail', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('subject:Test Email');
        });

        it('Should handle mixed case header names', () => {
            const signingHeaderLines = {
                keys: 'Content-Type',
                headers: [
                    { line: Buffer.from('Content-TYPE: text/plain', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('content-type:text/plain');
        });
    });

    describe('Signature header generation', () => {
        it('Should generate DKIM-Signature header', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            expect(result.signatureHeaderLine).to.include('DKIM-Signature:');
            expect(result.signatureHeaderLine).to.include('d=example.com');
            expect(result.signatureHeaderLine).to.include('s=selector1');
            expect(result.signatureHeaderLine).to.include('a=rsa-sha256');
        });

        it('Should generate ARC-Message-Signature header', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = relaxedHeaders('ARC', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'arc-selector',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'archash==',
                instance: 1
            });

            expect(result.signatureHeaderLine).to.include('ARC-Message-Signature:');
            expect(result.signatureHeaderLine).to.include('i=1');
        });

        it('Should generate ARC-Seal header', () => {
            const signingHeaderLines = {
                keys: 'ARC-Authentication-Results',
                headers: [
                    { line: Buffer.from('ARC-Authentication-Results: i=1; none', 'binary') }
                ]
            };

            const result = relaxedHeaders('AS', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'arc-selector',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'sealhash==',
                instance: 1
            });

            expect(result.signatureHeaderLine).to.include('ARC-Seal:');
        });

        it('Should use provided signatureHeaderLine if given', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const customHeader = 'DKIM-Signature: v=1; a=rsa-sha256; d=custom.com; s=sel; b=';

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signatureHeaderLine: customHeader
            });

            expect(result.signatureHeaderLine).to.equal(customHeader);
        });
    });

    describe('Optional tags', () => {
        it('Should include l= tag when bodyHashedBytes is set', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash==',
                bodyHashedBytes: 2000
            });

            expect(result.signatureHeaderLine).to.include('l=2000');
            expect(result.dkimHeaderOpts.l).to.equal(2000);
        });

        it('Should include t= tag when signTime is provided', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const signTime = new Date('2024-06-15T10:30:00Z');

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash==',
                signTime: signTime
            });

            expect(result.signatureHeaderLine).to.include('t=');
            expect(result.dkimHeaderOpts.t).to.equal(Math.floor(signTime.getTime() / 1000));
        });

        it('Should include x= tag when expires is provided', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const expires = new Date('2024-06-20T10:30:00Z');

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash==',
                expires: expires
            });

            expect(result.signatureHeaderLine).to.include('x=');
            expect(result.dkimHeaderOpts.x).to.equal(Math.floor(expires.getTime() / 1000));
        });

        it('Should include i= for ARC instance', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = relaxedHeaders('ARC', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'arc-selector',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'archash==',
                instance: 3
            });

            expect(result.dkimHeaderOpts.i).to.equal(3);
        });
    });

    describe('Edge cases', () => {
        it('Should handle whitespace-only header value', () => {
            const signingHeaderLines = {
                keys: 'X-Empty',
                headers: [
                    { line: Buffer.from('X-Empty:    ', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('x-empty:');
        });

        it('Should handle special characters in header value', () => {
            const signingHeaderLines = {
                keys: 'Subject',
                headers: [
                    { line: Buffer.from('Subject: Test <test@example.com> "quoted" (comment)', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('Test <test@example.com> "quoted" (comment)');
        });

        it('Should handle IDN domains in signing domain', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'xn--e1afmkfd.xn--p1ai',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            expect(result.signatureHeaderLine).to.include('d=xn--e1afmkfd.xn--p1ai');
        });

        it('Should handle multiple headers correctly', () => {
            const signingHeaderLines = {
                keys: 'From: To: Subject: Date',
                headers: [
                    { line: Buffer.from('From: sender@example.com', 'binary') },
                    { line: Buffer.from('To: recipient@example.com', 'binary') },
                    { line: Buffer.from('Subject: Important Message', 'binary') },
                    { line: Buffer.from('Date: Mon, 15 Jan 2024 12:00:00 +0000', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('from:sender@example.com\r\n');
            expect(canonicalized).to.include('to:recipient@example.com\r\n');
            expect(canonicalized).to.include('subject:Important Message\r\n');
            expect(canonicalized).to.include('date:Mon, 15 Jan 2024 12:00:00 +0000\r\n');
        });

        it('Should handle LF line endings', () => {
            const signingHeaderLines = {
                keys: 'Subject',
                headers: [
                    { line: Buffer.from('Subject: Line1\n Line2', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('subject:Line1 Line2');
        });
    });

    describe('Return values', () => {
        it('Should return canonicalizedHeader as Buffer', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            expect(Buffer.isBuffer(result.canonicalizedHeader)).to.be.true;
        });

        it('Should return dkimHeaderOpts with all options', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            expect(result.dkimHeaderOpts).to.be.an('object');
            expect(result.dkimHeaderOpts.a).to.equal('rsa-sha256');
            expect(result.dkimHeaderOpts.c).to.equal('relaxed/relaxed');
            expect(result.dkimHeaderOpts.d).to.equal('example.com');
            expect(result.dkimHeaderOpts.s).to.equal('selector1');
        });

        it('Should return false for dkimHeaderOpts when signatureHeaderLine provided', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = relaxedHeaders('DKIM', signingHeaderLines, {
                signatureHeaderLine: 'DKIM-Signature: prebuilt'
            });

            expect(result.dkimHeaderOpts).to.be.false;
        });
    });
});
