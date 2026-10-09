/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const zlib = require('node:zlib');
const chai = require('chai');
const expect = chai.expect;

const { validateVMC } = require('../../lib/bimi');

chai.config.includeStack = true;

const LOGO =
    '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 10 10"><title>Example</title><rect width="10" height="10" fill="red"/></svg>';

const decodeIndicator = header => Buffer.from(header.slice('BIMI-Indicator: '.length).replace(/\s+/g, ''), 'base64').toString();

describe('BIMI validateVMC Tests', () => {
    describe('Indicator validation without an evidence document', () => {
        it('Should not build headers from a downloaded file that is not SVG', async () => {
            const result = await validateVMC({
                location: 'https://example.com/logo.svg',
                locationPath: Buffer.from('<html><script>alert(1)</script></html>'),
                status: { header: {} }
            });

            expect(result.headers).to.not.exist;
            expect(result.location.success).to.be.false;
            expect(result.location.logoFile).to.not.exist;
            expect(result.location.error.code).to.equal('SVG_VALIDATION_FAILED');
            expect(result.location.error.details.code).to.equal('INVALID_SVG_FILE');
        });

        it('Should not build headers from an SVG file that fails validation', async () => {
            const result = await validateVMC({
                location: 'https://example.com/logo.svg',
                locationPath: Buffer.from(
                    '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><title>t</title><script>alert(1)</script></svg>'
                ),
                status: { header: {} }
            });

            expect(result.headers).to.not.exist;
            expect(result.location.success).to.be.false;
            expect(result.location.error.code).to.equal('SVG_VALIDATION_FAILED');
            expect(result.location.error.details.code).to.equal('LOGO_INVALID_ELEMENT');
        });

        it('Should build headers from a valid SVG file', async () => {
            const result = await validateVMC({
                location: 'https://example.com/logo.svg',
                locationPath: Buffer.from(LOGO),
                status: { header: {} }
            });

            expect(result.location.success).to.be.true;
            expect(result.location.logoFile).to.equal(Buffer.from(LOGO).toString('base64'));
            expect(result.headers.location).to.equal('BIMI-Location: v=BIMI1; l=https://example.com/logo.svg');
            expect(decodeIndicator(result.headers.indicator)).to.equal(LOGO);
        });

        it('Should uncompress an SVGZ file before validating and encoding it', async () => {
            const result = await validateVMC({
                location: 'https://example.com/logo.svgz',
                locationPath: zlib.gzipSync(Buffer.from(LOGO)),
                status: { header: {} }
            });

            expect(result.location.success).to.be.true;
            expect(decodeIndicator(result.headers.indicator)).to.equal(LOGO);
        });

        it('Should validate the content of an SVGZ file', async () => {
            const result = await validateVMC({
                location: 'https://example.com/logo.svgz',
                locationPath: zlib.gzipSync(Buffer.from('<html><script>alert(1)</script></html>')),
                status: { header: {} }
            });

            expect(result.headers).to.not.exist;
            expect(result.location.success).to.be.false;
            expect(result.location.error.code).to.equal('SVG_VALIDATION_FAILED');
        });

        it('Should reject a broken SVGZ file', async () => {
            const result = await validateVMC({
                location: 'https://example.com/logo.svgz',
                locationPath: zlib.gzipSync(Buffer.from(LOGO)).subarray(0, 20),
                status: { header: {} }
            });

            expect(result.headers).to.not.exist;
            expect(result.location.success).to.be.false;
            expect(result.location.error.details.code).to.equal('INVALID_SVGZ_FILE');
        });
    });

    describe('SVG Tiny PS profile rules', () => {
        const noVersion = '<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps"><title>Example</title><rect width="10" height="10" fill="red"/></svg>';

        it('Should report a lax logo in warnings', async () => {
            const result = await validateVMC({ location: 'https://example.com/logo.svg', locationPath: Buffer.from(noVersion), status: { header: {} } });
            expect(result.location.success).to.be.true;
            expect(result.headers).to.exist;
            expect(result.warnings).to.deep.equal(['svg-version']);
        });

        it('Should reject a lax logo in strict mode', async () => {
            const result = await validateVMC(
                { location: 'https://example.com/logo.svg', locationPath: Buffer.from(noVersion), status: { header: {} } },
                { strict: true }
            );
            expect(result.location.success).to.be.false;
            expect(result.location.error.code).to.equal('SVG_VALIDATION_FAILED');
            expect(result.location.error.details.code).to.equal('INVALID_SVG_VERSION');
            expect(result.headers).to.not.exist;
            expect(result.warnings).to.not.exist;
        });

        it('Should not report warnings for a valid logo', async () => {
            const result = await validateVMC(
                { location: 'https://example.com/logo.svg', locationPath: Buffer.from(LOGO), status: { header: {} } },
                { strict: true }
            );
            expect(result.location.success).to.be.true;
            expect(result.warnings).to.not.exist;
        });
    });
});
