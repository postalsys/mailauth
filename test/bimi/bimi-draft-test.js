/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const { bimi } = require('../../lib/bimi');
const verifyDmarc = require('../../lib/dmarc/verify');
const { authenticate } = require('../../lib/mailauth');
const { zoneResolver } = require('../helpers/dns-zone');

chai.config.includeStack = true;

// draft-brand-indicators-for-message-identification-14

const LOGO = 'https://brand.example/logo.svg';

// Runs DMARC (aligned SPF) and then BIMI for an author domain, the way authenticate() does
const run = async (from, zone, extra) => {
    const resolver = zoneResolver(zone);
    const authorDomain = from.split('@').pop();
    const dmarc = await verifyDmarc({ headerFrom: from, spfDomains: [authorDomain], resolver });
    const result = await bimi(Object.assign({ dmarc, resolver }, extra));
    return { dmarc, result, resolver };
};

const bimiQueries = resolver => resolver.calls.filter(call => call.name.includes('._bimi.')).map(call => call.name);

describe('BIMI draft-14 requirements', () => {
    describe('7.1 DMARC policy requirements', () => {
        it('Should skip when the Organizational Domain has p=none', async () => {
            const { dmarc, result, resolver } = await run('a@news.bank.example', {
                '_dmarc.news.bank.example': { TXT: [['v=DMARC1; p=reject']] },
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=none']] },
                'default._bimi.news.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`]] }
            });
            expect(dmarc.status.result).to.equal('pass');
            expect(dmarc.policy).to.equal('reject');
            expect(result.status.result).to.equal('skipped');
            expect(result.status.comment).to.equal('too lax DMARC policy');
            expect(bimiQueries(resolver)).to.have.lengthOf(0);
        });

        it('Should skip when a record has sp=none, even for the Organizational Domain itself', async () => {
            const { dmarc, result } = await run('a@bank.example', {
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject; sp=none']] },
                'default._bimi.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`]] }
            });
            expect(dmarc.policy).to.equal('reject');
            expect(result.status.result).to.equal('skipped');
            expect(result.status.comment).to.equal('too lax DMARC subdomain policy');
        });

        it('Should skip quarantine applied to a percentage of messages', async () => {
            const { result } = await run('a@bank.example', {
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=quarantine; pct=50']] },
                'default._bimi.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`]] }
            });
            expect(result.status.result).to.equal('skipped');
        });

        it('Should pass with enforcing policies at both domains', async () => {
            const { result } = await run('a@news.bank.example', {
                '_dmarc.news.bank.example': { TXT: [['v=DMARC1; p=reject']] },
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=quarantine; pct=100; sp=reject']] },
                'default._bimi.news.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`]] }
            });
            expect(result.status.result).to.equal('pass');
            expect(result.location).to.equal(LOGO);
        });

        it('Should look up the Organizational Domain record for a DMARC result built elsewhere', async () => {
            const resolver = zoneResolver({
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=none']] },
                'default._bimi.news.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`]] }
            });
            const dmarc = {
                status: { result: 'pass', header: { from: 'news.bank.example', d: 'news.bank.example' } },
                domain: 'bank.example',
                policy: 'reject',
                rr: 'v=DMARC1; p=reject'
            };
            const result = await bimi({ dmarc, resolver });
            expect(result.status.result).to.equal('skipped');
            expect(result.status.comment).to.equal('too lax DMARC policy');
        });

        it('Should give temperror when the Organizational Domain is not known', async () => {
            const resolver = zoneResolver({
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] },
                'default._bimi.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`]] }
            });
            const failing = async (name, type) => {
                if (name === '_dmarc.example') {
                    const err = new Error('SERVFAIL');
                    err.code = 'ESERVFAIL';
                    throw err;
                }
                return resolver(name, type);
            };
            const dmarc = await verifyDmarc({ headerFrom: 'a@bank.example', spfDomains: ['bank.example'], resolver: failing });
            expect(dmarc.status.result).to.equal('pass');
            const result = await bimi({ dmarc, resolver: failing });
            expect(result.status.result).to.equal('temperror');
        });
    });

    describe('7.1 step 1: one From address', () => {
        const zone = {
            '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] },
            'default._bimi.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`]] }
        };

        it('Should skip several addresses of the same domain that DMARC evaluated', async () => {
            const resolver = zoneResolver(zone);
            const dmarc = await verifyDmarc({ headerFrom: ['a@bank.example', 'b@bank.example'], spfDomains: ['bank.example'], resolver });
            expect(dmarc.status.result).to.equal('pass');
            const result = await bimi({ dmarc, resolver });
            expect(result.status.result).to.equal('skipped');
            expect(result.status.comment).to.equal('multiple From addresses');
        });

        it('Should skip based on the From header fields', async () => {
            const resolver = zoneResolver(zone);
            const dmarc = await verifyDmarc({ headerFrom: 'a@bank.example', spfDomains: ['bank.example'], resolver });
            for (let parsed of [
                [{ key: 'from', line: 'From: a@bank.example, b@bank.example' }],
                [
                    { key: 'from', line: 'From: a@bank.example' },
                    { key: 'from', line: 'From: a@bank.example' }
                ],
                [{ key: 'from', line: 'From: Bank: a@bank.example, b@bank.example;' }]
            ]) {
                const result = await bimi({ dmarc, headers: { parsed }, resolver });
                expect(result.status.result).to.equal('skipped');
            }
            const result = await bimi({ dmarc, headers: { parsed: [{ key: 'from', line: 'From: Bank <a@bank.example>' }] }, resolver });
            expect(result.status.result).to.equal('pass');
        });

        it('Should skip through authenticate()', async () => {
            const res = await authenticate(Buffer.from('From: a@bank.example, b@bank.example\r\nSubject: t\r\n\r\nbody\r\n'), {
                ip: '192.0.2.1',
                helo: 'mx.bank.example',
                sender: 'bounce@bank.example',
                mta: 'mx.test',
                resolver: zoneResolver(Object.assign({ 'bank.example': { TXT: [['v=spf1 ip4:192.0.2.1 -all']] } }, zone)),
                disableArc: true
            });
            expect(res.dmarc.status.result).to.equal('pass');
            expect(res.bimi.status.result).to.equal('skipped');
        });
    });

    describe('7.2 Assertion Record Discovery', () => {
        it('Should fall back to the same custom selector at the Organizational Domain', async () => {
            const { result, resolver } = await run(
                'a@news.bank.example',
                {
                    '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] },
                    'brand._bimi.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`]] },
                    'default._bimi.bank.example': { TXT: [['v=BIMI1; l=https://brand.example/other.svg']] }
                },
                { headers: { parsed: [{ key: 'bimi-selector', line: 'BIMI-Selector: v=BIMI1; s=brand' }] } }
            );
            expect(bimiQueries(resolver)).to.deep.equal(['brand._bimi.news.bank.example', 'brand._bimi.bank.example']);
            expect(result.status.result).to.equal('pass');
            expect(result.status.header).to.deep.equal({ selector: 'brand', d: 'bank.example' });
            expect(result.location).to.equal(LOGO);
        });

        it('Should not fall back to the default selector', async () => {
            const { result, resolver } = await run(
                'a@bank.example',
                {
                    '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] },
                    'default._bimi.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`]] }
                },
                { headers: { parsed: [{ key: 'bimi-selector', line: 'BIMI-Selector: v=BIMI1; s=brand' }] } }
            );
            expect(bimiQueries(resolver)).to.deep.equal(['brand._bimi.bank.example']);
            expect(result.status.result).to.equal('none');
        });

        it('Should discard TXT records that are not BIMI records', async () => {
            const { result } = await run('a@bank.example', {
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] },
                'default._bimi.bank.example': { TXT: [['google-site-verification=abc'], [`v=BIMI1; l=${LOGO}`]] }
            });
            expect(result.status.result).to.equal('pass');
            expect(result.rr).to.equal(`v=BIMI1; l=${LOGO}`);
        });

        it('Should move on to the Organizational Domain when only other TXT records are found', async () => {
            const { result } = await run('a@news.bank.example', {
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] },
                'default._bimi.news.bank.example': { TXT: [['some-verification=abc']] },
                'default._bimi.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`]] }
            });
            expect(result.status.result).to.equal('pass');
            expect(result.status.header.d).to.equal('bank.example');
        });

        it('Should fail on several BIMI records', async () => {
            const { result } = await run('a@bank.example', {
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] },
                'default._bimi.bank.example': { TXT: [[`v=BIMI1; l=${LOGO}`], ['v=BIMI1; l=https://brand.example/other.svg']] }
            });
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('multiple BIMI records for default._bimi.bank.example');
        });

        it('Should report a DNS failure as temperror', async () => {
            const zone = zoneResolver({ '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] } });
            const resolver = async (name, type) => {
                if (name === 'default._bimi.bank.example') {
                    const err = new Error('SERVFAIL');
                    err.code = 'ESERVFAIL';
                    throw err;
                }
                return zone(name, type);
            };
            const dmarc = await verifyDmarc({ headerFrom: 'a@bank.example', spfDomains: ['bank.example'], resolver });
            const result = await bimi({ dmarc, resolver });
            expect(result.status.result).to.equal('temperror');
            expect(result.info).to.equal('bimi=temperror (failed to resolve default._bimi.bank.example)');
        });
    });

    describe('Assertion Record', () => {
        const withRecord = record => ({
            '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] },
            'default._bimi.bank.example': { TXT: [[record]] }
        });

        it('Should report a Declination to Publish as declined', async () => {
            for (let record of ['v=BIMI1; l=; a=', 'v=BIMI1; l=;', 'v=BIMI1; l= ; a= ; lps=']) {
                const { result } = await run('a@bank.example', withRecord(record));
                expect(result.status.result, record).to.equal('declined');
                expect(result.info, record).to.equal('bimi=declined header.selector=default header.d=bank.example');
                expect(result, record).to.not.have.property('location');
            }
        });

        it('Should fail a record without a location, even with an authority', async () => {
            for (let record of ['v=BIMI1; a=https://brand.example/vmc.pem', 'v=BIMI1; l=; a=https://brand.example/vmc.pem', 'v=BIMI1;', 'v=BIMI1; l=0']) {
                const { result } = await run('a@bank.example', withRecord(record));
                expect(result.status.result, record).to.equal('fail');
            }
        });

        it('Should keep parentheses and quotes in URIs', async () => {
            const { result } = await run('a@bank.example', withRecord("v=BIMI1; l=https://brand.example/logo(1).svg; a=https://brand.example/it's.pem"));
            expect(result.status.result).to.equal('pass');
            expect(result.location).to.equal('https://brand.example/logo(1).svg');
            expect(result.authority).to.equal("https://brand.example/it's.pem");
        });
    });
});
