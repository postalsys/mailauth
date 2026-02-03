/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { generateCanonicalizedHeader } = require('../../../lib/dkim/header/index');

chai.config.includeStack = true;

describe('DKIM Header Canonicalization Dispatcher Tests', () => {
    describe('Canonicalization selection', () => {
        it('Should use simple canonicalization when c=simple/simple', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('FROM: user@example.com', 'binary') }
                ]
            };

            const result = generateCanonicalizedHeader('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/simple',
                bodyHash: 'base64bodyhash=='
            });

            // Simple preserves case
            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('FROM:');
        });

        it('Should use relaxed canonicalization when c=relaxed/relaxed', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('FROM: user@example.com', 'binary') }
                ]
            };

            const result = generateCanonicalizedHeader('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            // Relaxed lowercases
            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('from:');
            expect(canonicalized).not.to.include('FROM:');
        });

        it('Should use simple canonicalization when c=simple/relaxed', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('FROM: user@example.com', 'binary') }
                ]
            };

            const result = generateCanonicalizedHeader('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'simple/relaxed',
                bodyHash: 'base64bodyhash=='
            });

            // Header uses first part (simple)
            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('FROM:');
        });

        it('Should use relaxed canonicalization when c=relaxed/simple', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('FROM: user@example.com', 'binary') }
                ]
            };

            const result = generateCanonicalizedHeader('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'relaxed/simple',
                bodyHash: 'base64bodyhash=='
            });

            // Header uses first part (relaxed)
            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('from:');
        });

        it('Should default to simple canonicalization when not specified', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('FROM: user@example.com', 'binary') }
                ]
            };

            const result = generateCanonicalizedHeader('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                bodyHash: 'base64bodyhash=='
            });

            // Default is simple
            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('FROM:');
        });
    });

    describe('Error handling', () => {
        it('Should throw for unknown canonicalization type', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            try {
                generateCanonicalizedHeader('DKIM', signingHeaderLines, {
                    signingDomain: 'example.com',
                    selector: 'selector1',
                    algorithm: 'rsa-sha256',
                    canonicalization: 'unknown/simple',
                    bodyHash: 'base64bodyhash=='
                });
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.message).to.equal('Unknown header canonicalization');
                expect(err.canonicalization).to.equal('unknown');
            }
        });

        it('Should throw for invalid canonicalization value', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('From: user@example.com', 'binary') }
                ]
            };

            try {
                generateCanonicalizedHeader('DKIM', signingHeaderLines, {
                    signingDomain: 'example.com',
                    selector: 'selector1',
                    algorithm: 'rsa-sha256',
                    canonicalization: 'invalid',
                    bodyHash: 'base64bodyhash=='
                });
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.message).to.equal('Unknown header canonicalization');
                expect(err.canonicalization).to.equal('invalid');
            }
        });
    });

    describe('Case handling', () => {
        it('Should handle uppercase canonicalization value', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('FROM: user@example.com', 'binary') }
                ]
            };

            const result = generateCanonicalizedHeader('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'RELAXED/simple',
                bodyHash: 'base64bodyhash=='
            });

            // Should recognize relaxed even when uppercase
            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('from:');
        });

        it('Should handle mixed case canonicalization value', () => {
            const signingHeaderLines = {
                keys: 'From',
                headers: [
                    { line: Buffer.from('FROM: user@example.com', 'binary') }
                ]
            };

            const result = generateCanonicalizedHeader('DKIM', signingHeaderLines, {
                signingDomain: 'example.com',
                selector: 'selector1',
                algorithm: 'rsa-sha256',
                canonicalization: 'ReLaXeD/simple',
                bodyHash: 'base64bodyhash=='
            });

            const canonicalized = result.canonicalizedHeader.toString('binary');
            expect(canonicalized).to.include('from:');
        });
    });
});
