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

    describe('4.3 Assertion Record syntax', () => {
        const cases = {
            'v=bimi1; l=https://example.com/logo.svg': { strict: ['none'], lax: ['pass', ['record-version-case']] },
            'v=BIMI1; L=https://example.com/logo.svg': {
                strict: ['fail', 'missing location value in dns record'],
                lax: ['pass', ['record-tag-case']]
            },
            'v=BIMI1; l=https://example.com/a.svg; l=https://example.net/b.svg': {
                strict: ['fail', 'invalid syntax in dns record'],
                lax: ['pass', ['record-syntax']]
            },
            'v=BIMI1; l=https://example.com/logo.svg; bogus': {
                strict: ['fail', 'invalid syntax in dns record'],
                lax: ['pass', ['record-syntax']]
            },
            'v=BIMI1; l=https://example.com/logo.png': {
                strict: ['fail', 'unsupported image format in location value'],
                lax: ['pass', ['location-format']]
            },
            'v=BIMI1; l=https://example.com/a.svg,https://example.com/b.svg': {
                strict: ['fail', 'invalid location value in dns record'],
                lax: ['pass', ['uri-comma']]
            },
            'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/a,b.pem': {
                strict: ['fail', 'invalid authority value in dns record'],
                lax: ['pass', ['uri-comma']]
            }
        };

        for (let [record, { strict, lax }] of Object.entries(cases)) {
            it(`Should handle ${JSON.stringify(record)}`, async () => {
                let result = await lookupRecord(record, { strict: true });
                expect(result.status.result).to.equal(strict[0]);
                expect(result.status.comment).to.equal(strict[1]);
                expect(result.warnings).to.not.exist;

                result = await lookupRecord(record);
                expect(result.status.result).to.equal(lax[0]);
                expect(result.warnings).to.deep.equal(lax[1]);
            });
        }

        it('Should accept a valid record in strict mode without warnings', async () => {
            for (let strict of [false, true]) {
                const result = await lookupRecord('v=BIMI1; l=https://example.com/logo.svgz; a=https://example.com/vmc.pem; avp=brand;', { strict });
                expect(result.status.result).to.equal('pass');
                expect(result.location).to.equal('https://example.com/logo.svgz');
                expect(result.warnings).to.not.exist;
            }
        });

        it('Should use a v=BIMI1 record next to a v=bimi1 record in strict mode', async () => {
            const result = await bimi({
                dmarc,
                strict: true,
                headers: { parsed: [{ key: 'from', line: 'From: a@example.com' }] },
                resolver: async name => {
                    if (name === 'default._bimi.example.com') {
                        return [['v=bimi1; l=https://example.com/a.svg'], ['v=BIMI1; l=https://example.com/b.svg']];
                    }
                    notFound();
                }
            });
            expect(result.status.result).to.equal('pass');
            expect(result.location).to.equal('https://example.com/b.svg');
        });
    });

    describe('5.1 BIMI-Selector header', () => {
        const records = {
            'default._bimi.example.com': 'v=BIMI1; l=https://example.com/default.svg',
            'brand._bimi.example.com': 'v=BIMI1; l=https://example.com/brand.svg',
            'brand_x._bimi.example.com': 'v=BIMI1; l=https://example.com/brand_x.svg'
        };

        const withSelector = (line, strict) =>
            lookup(records, {
                strict,
                headers: {
                    parsed: [
                        { key: 'from', line: 'From: a@example.com' },
                        { key: 'bimi-selector', line }
                    ]
                }
            });

        for (let line of [
            'BIMI-Selector: s=brand',
            'BIMI-Selector: v=BIMI2; s=brand',
            'BIMI-Selector: v=BIMI1',
            'BIMI-Selector: v=BIMI1; s=',
            'BIMI-Selector: v=BIMI1; s=bad selector',
            'BIMI-Selector: v=BIMI1; s=-brand',
            'BIMI-Selector: v=BIMI1; s=brand..x',
            // a DNS label is at most 63 octets
            `BIMI-Selector: v=BIMI1; s=${'a'.repeat(64)}`,
            `BIMI-Selector: v=BIMI1; s=brand_${'a'.repeat(58)}`
        ]) {
            it(`Should ignore ${JSON.stringify(line)} and use the default selector`, async () => {
                for (let strict of [false, true]) {
                    const result = await withSelector(line, strict);
                    expect(result.status.result).to.equal('pass');
                    expect(result.status.header).to.deep.equal({ selector: 'default', d: 'example.com' });
                    expect(result.info).to.equal('bimi=pass header.selector=default header.d=example.com');
                }
            });
        }

        it('Should use a valid selector', async () => {
            for (let strict of [false, true]) {
                const result = await withSelector('BIMI-Selector: v=BIMI1; s=brand;', strict);
                expect(result.status.header).to.deep.equal({ selector: 'brand', d: 'example.com' });
                expect(result.location).to.equal('https://example.com/brand.svg');
                expect(result.warnings).to.not.exist;
            }
        });

        const laxCases = {
            'BIMI-Selector: v=bimi1; s=brand': ['brand', 'selector-version-case'],
            'BIMI-Selector: s=brand; v=BIMI1': ['brand', 'selector-syntax'],
            'BIMI-Selector: v=BIMI1; s=other; s=brand': ['brand', 'selector-syntax'],
            'BIMI-Selector: v=BIMI1; s=brand_x': ['brand_x', 'selector-syntax']
        };

        for (let [line, [selector, warning]] of Object.entries(laxCases)) {
            it(`Should use ${JSON.stringify(line)} only without strict`, async () => {
                let result = await withSelector(line, true);
                expect(result.status.header.selector).to.equal('default');
                expect(result.warnings).to.not.exist;

                result = await withSelector(line, false);
                expect(result.status.header.selector).to.equal(selector);
                expect(result.warnings).to.deep.equal([warning]);
            });
        }
    });
});
