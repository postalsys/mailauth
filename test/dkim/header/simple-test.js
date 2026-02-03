/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { simpleHeaders } = require('../../../lib/dkim/header/simple');

chai.config.includeStack = true;

describe('DKIM Simple Header Canonicalization Tests', () => {
    describe('Header formatting', () => {
        it('Should preserve original header case', () => {
            const signingHeaderLines = {
                keys: 'From: Subject',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') },
                    { line: Buffer.from('Subject: Test Email', 'binary') }
                ]
            };

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('From: user@example.com');
            expect(canonicalized).to.include('Subject: Test Email');
        });

        it('Should preserve whitespace in headers', () => {
            const signingHeaderLines = {
                keys: 'Subject',
                headers: [
                    { line: Buffer.from('Subject:   Multiple   Spaces', 'binary') }
                ]
            };

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('Subject:   Multiple   Spaces');
        });

        it('Should add CRLF after each header', () => {
            const signingHeaderLines = {
                keys: 'From: Subject',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') },
                    { line: Buffer.from('Subject: Test', 'binary') }
                ]
            };

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('From: user@example.com\r\n');
            expect(canonicalized).to.include('Subject: Test\r\n');
        });

        it('Should preserve folded headers', () => {
            const signingHeaderLines = {
                keys: 'Subject',
                headers: [
                    { line: Buffer.from('Subject: This is a very long subject line\r\n that has been folded', 'binary') }
                ]
            };

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('Subject: This is a very long subject line\r\n that has been folded');
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

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash=='
            });

            expect(result.signatureHeaderLine).to.include('DKIM-Signature:');
            expect(result.signatureHeaderLine).to.include('d=example.com');
            expect(result.signatureHeaderLine).to.include('s=selector1');
            expect(result.signatureHeaderLine).to.include('a=rsa-sha256');
            expect(result.signatureHeaderLine).to.include('bh=base64bodyhash==');
        });

        it('Should generate ARC-Message-Signature header', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = simpleHeaders('ARC', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'arc-selector',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
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

            const result = simpleHeaders('AS', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'arc-selector',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
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

            const result = simpleHeaders('DKIM', signingHeaderLines, {
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

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash==',
                bodyHashedBytes: 1000
            });

            expect(result.signatureHeaderLine).to.include('l=1000');
            expect(result.dkimHeaderOpts.l).to.equal(1000);
        });

        it('Should include t= tag when signTime is provided', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const signTime = new Date('2024-01-15T12:00:00Z');

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
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

            const expires = new Date('2024-01-20T12:00:00Z');

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
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

            const result = simpleHeaders('ARC', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'arc-selector',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'archash==',
                instance: 2
            });

            expect(result.dkimHeaderOpts.i).to.equal(2);
        });
    });

    describe('Signature placeholder', () => {
        it('Should remove b= value from canonicalized header', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash==',
                signature: 'thesignaturevalue'
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            // The b= should be present but its value should be empty for signing
            expect(canonicalized).to.match(/b=$/m);
            expect(canonicalized).not.to.include('thesignaturevalue');
        });

        it('Should use placeholder signature when none provided', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash=='
            });

            // Should have generated header with placeholder
            expect(result.signatureHeaderLine).to.include('b=');
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

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash=='
            });

            expect(Buffer.isBuffer(result.canonicalizedHeader)).to.be.true;
        });

        it('Should return dkimHeaderOpts with all set options', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash=='
            });

            expect(result.dkimHeaderOpts).to.be.an('object');
            expect(result.dkimHeaderOpts.a).to.equal('rsa-sha256');
            expect(result.dkimHeaderOpts.c).to.equal('simple/simple');
            expect(result.dkimHeaderOpts.d).to.equal('example.com');
            expect(result.dkimHeaderOpts.s).to.equal('selector1');
            expect(result.dkimHeaderOpts.bh).to.equal('base64bodyhash==');
        });

        it('Should return false for dkimHeaderOpts when signatureHeaderLine provided', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            const result = simpleHeaders('DKIM', signingHeaderLines, {
                signatureHeaderLine: 'DKIM-Signature: prebuilt'
            });

            expect(result.dkimHeaderOpts).to.be.false;
        });
    });
});
