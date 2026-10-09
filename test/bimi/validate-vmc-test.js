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

    describe('Authentication-Results after validation', () => {
        const passStatus = authority => ({
            result: 'pass',
            header: { selector: 'default', d: 'example.com' },
            policy: authority ? { authority: 'none', 'authority-uri': authority } : undefined
        });

        it('Should fail the result when the indicator and the evidence document fail', async () => {
            const result = await validateVMC({
                location: 'https://example.com/logo.svg',
                locationPath: Buffer.from('<svg/>'),
                authority: 'https://example.com/vmc.pem',
                authorityPath: Buffer.from('not a certificate'),
                status: passStatus('https://example.com/vmc.pem')
            });
            expect(result.authority.success).to.be.false;
            expect(result.headers).to.not.exist;
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('invalid SVG indicator');
            expect(result.status.policy.authority).to.equal('fail');
            expect(result.info).to.equal(
                'bimi=fail (invalid SVG indicator) policy.authority=fail policy.authority-uri="https://example.com/vmc.pem" header.selector=default header.d=example.com'
            );
        });

        it('Should fail the result when only the evidence document fails', async () => {
            const result = await validateVMC({
                location: 'https://example.com/logo.svg',
                locationPath: Buffer.from(LOGO),
                authority: 'https://example.com/vmc.pem',
                authorityPath: Buffer.from('not a certificate'),
                status: passStatus('https://example.com/vmc.pem')
            });
            expect(result.location.success).to.be.true;
            expect(result.headers).to.not.exist;
            expect(result.info).to.equal(
                'bimi=fail (evidence document validation failed) policy.authority=fail policy.authority-uri="https://example.com/vmc.pem" header.selector=default header.d=example.com'
            );
        });

        it('Should fail the result when the indicator can not be retrieved', async () => {
            const result = await validateVMC({
                location: 'https://127.0.0.1/logo.svg',
                status: passStatus()
            });
            expect(result.location.success).to.be.false;
            expect(result.info).to.equal('bimi=fail (failed to retrieve indicator) header.selector=default header.d=example.com');
        });

        it('Should keep the pass result for a valid indicator without evidence', async () => {
            const bimiData = { location: 'https://example.com/logo.svg', locationPath: Buffer.from(LOGO), status: passStatus() };
            const result = await validateVMC(bimiData);
            expect(result.status.result).to.equal('pass');
            expect(result.status.policy).to.not.exist;
            expect(result.info).to.equal('bimi=pass header.selector=default header.d=example.com');
            expect(result.headers.location).to.equal('BIMI-Location: v=BIMI1; l=https://example.com/logo.svg');
        });

        it('Should format the entry in strict mode', async () => {
            const result = await validateVMC(
                { location: 'https://example.com/logo.svg', locationPath: Buffer.from('<svg/>'), status: passStatus() },
                { strict: true }
            );
            expect(result.status.result).to.equal('fail');
            expect(result.info).to.match(/^bimi=fail \(invalid SVG indicator\)/);
        });

        it('Should not add a status for data that did not pass discovery', async () => {
            const result = await validateVMC({ location: 'https://example.com/logo.svg', locationPath: Buffer.from(LOGO), status: { header: {} } });
            expect(result.status).to.not.exist;
            expect(result.info).to.not.exist;
        });

        it('Should not build headers from a location that is not a valid URL', async () => {
            const result = await validateVMC({
                location: 'https://example.com/logo.svg\r\nX-Injected: 1',
                locationPath: Buffer.from(LOGO),
                status: { header: {} }
            });
            expect(result.location.success).to.be.true;
            expect(result.headers).to.not.exist;
        });
    });
});
