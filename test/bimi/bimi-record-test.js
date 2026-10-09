/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { bimi, validateVMC } = require('../../lib/bimi');

chai.config.includeStack = true;

// draft-brand-indicators-for-message-identification-14, Assertion Record and BIMI header fields

const LOGO =
    '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 10 10"><title>Example</title><rect width="10" height="10" fill="red"/></svg>';

const dmarc = {
    status: { result: 'pass', header: { from: 'example.com', d: 'example.com' } },
    domain: 'example.com',
    policy: 'reject',
    record: { p: 'reject' },
    orgRecord: false
};

const notFound = () => {
    throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
};

// records is a map of DNS names to TXT record strings
const lookup = (records, extra) =>
    bimi(
        Object.assign(
            {
                dmarc,
                headers: { parsed: [{ key: 'from', line: 'From: a@example.com' }] },
                resolver: async name => {
                    if (Object.prototype.hasOwnProperty.call(records, name)) {
                        return [[records[name]]];
                    }
                    notFound();
                }
            },
            extra || {}
        )
    );

const lookupRecord = (record, extra) => lookup({ 'default._bimi.example.com': record }, extra);

describe('BIMI Assertion Record Tests', () => {
    describe('4.3 avp= Avatar Preference', () => {
        for (let value of ['personal', 'brand']) {
            it(`Should read avp=${value}`, async () => {
                const result = await lookupRecord(`v=BIMI1; l=https://example.com/logo.svg; avp=${value}`);
                expect(result.status.result).to.equal('pass');
                expect(result.preference).to.equal(value);

                result.locationPath = Buffer.from(LOGO);
                const vmcResult = await validateVMC(result);
                expect(vmcResult.headers.preference).to.equal(`BIMI-Logo-Preference: avp=${value}`);
            });
        }

        for (let value of ['Personal', 'self', '']) {
            it(`Should ignore avp=${value}`, async () => {
                const result = await lookupRecord(`v=BIMI1; l=https://example.com/logo.svg; avp=${value}`);
                expect(result.status.result).to.equal('pass');
                expect(result.preference).to.not.exist;

                result.locationPath = Buffer.from(LOGO);
                const vmcResult = await validateVMC(result);
                expect(vmcResult.headers.indicator).to.exist;
                expect(vmcResult.headers.preference).to.not.exist;
            });
        }

        it('Should ignore the undefined p= tag', async () => {
            const result = await lookupRecord('v=BIMI1; l=https://example.com/logo.svg; p=\x00anything goes');
            expect(result.status.result).to.equal('pass');
            expect(result.preference).to.not.exist;

            result.locationPath = Buffer.from(LOGO);
            const vmcResult = await validateVMC(result);
            expect(vmcResult.headers.preference).to.not.exist;
        });

        it('Should not build a header from an invalid preference value', async () => {
            const vmcResult = await validateVMC({
                location: 'https://example.com/logo.svg',
                locationPath: Buffer.from(LOGO),
                preference: 'brand\r\nX-Injected: 1',
                status: { header: {} }
            });
            expect(vmcResult.headers.indicator).to.exist;
            expect(vmcResult.headers.preference).to.not.exist;
        });
    });
});
