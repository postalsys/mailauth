/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const verifyDmarc = require('../../lib/dmarc/verify');
const { evaluateDmarc } = verifyDmarc;
const { dmarc } = require('../../lib/dmarc');
const getDmarcRecord = require('../../lib/dmarc/get-dmarc-record');
const { authenticate } = require('../../lib/mailauth');
const { zoneResolver } = require('../helpers/dns-zone');

chai.config.includeStack = true;

const servfail = name => {
    const err = new Error(`SERVFAIL ${name}`);
    err.code = 'ESERVFAIL';
    return err;
};

// zoneResolver with SERVFAIL for the listed names
const failingResolver = (zone, failing) => {
    const resolver = zoneResolver(zone);
    const wrapped = async (name, type) => {
        if (failing.includes(name)) {
            wrapped.calls.push({ name, type });
            throw servfail(name);
        }
        let result = await resolver(name, type);
        wrapped.calls.push({ name, type });
        return result;
    };
    wrapped.calls = [];
    return wrapped;
};

describe('DMARC compliance fixes', () => {
    describe('C1: Author Domain is the domain of the addr-spec', () => {
        const zone = { '_dmarc.victim.example': { TXT: [['v=DMARC1; p=reject']] } };

        it('Should not be fooled by an "@" in a quoted local-part', async () => {
            const result = await verifyDmarc({ headerFrom: '"ceo@x"@victim.example', spfDomains: ['attacker.test'], resolver: zoneResolver(zone) });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('reject');
            expect(result.status.header.from).to.equal('victim.example');
        });

        it('Should use the mailbox domain of an obs-route address', async () => {
            const result = await verifyDmarc({ headerFrom: '@relay.test:ceo@victim.example', spfDomains: ['attacker.test'], resolver: zoneResolver(zone) });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('reject');
            expect(result.status.header.from).to.equal('victim.example');
            expect(result.info).to.include('header.from=victim.example');
        });

        it('Should apply the policy through authenticate()', async () => {
            const resolver = zoneResolver(Object.assign({ 'attacker.test': { TXT: [['v=spf1 ip4:203.0.113.5 -all']] } }, zone));
            for (let from of ['"ceo@x"@victim.example', '<@relay.test:ceo@victim.example>', 'CEO <"ceo@x"@victim.example>']) {
                const res = await authenticate(Buffer.from(`From: ${from}\r\nTo: r@example.org\r\nSubject: t\r\n\r\nbody\r\n`), {
                    ip: '203.0.113.5',
                    helo: 'mail.attacker.test',
                    sender: 'bounce@attacker.test',
                    mta: 'mx.test',
                    resolver,
                    disableArc: true,
                    disableBimi: true
                });
                expect(res.spf.status.result, from).to.equal('pass');
                expect(res.dmarc.status.result, from).to.equal('fail');
                expect(res.dmarc.policy, from).to.equal('reject');
                expect(res.headers, from).to.include('dmarc=fail (p=REJECT) policy.dmarc=reject header.from=victim.example header.d=victim.example');
            }
        });
    });

    describe('H6: several From mailboxes', () => {
        const zone = { '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] } };

        it('Should evaluate mailboxes that share one domain', async () => {
            const result = await verifyDmarc({
                headerFrom: ['a@example.com', 'B@Example.COM'],
                dkimDomains: [{ domain: 'example.com' }],
                resolver: zoneResolver(zone)
            });
            expect(result.status.result).to.equal('pass');
        });

        it('Should report why evaluation is not possible, keeping the false response', async () => {
            let evaluation = await evaluateDmarc({ headerFrom: ['a@example.com', 'b@example.net'], resolver: zoneResolver(zone) });
            expect(evaluation.response).to.be.false;
            expect(evaluation.reason).to.equal('multiple-author-domains');
            expect(evaluation.authorDomains).to.deep.equal(['example.com', 'example.net']);

            evaluation = await evaluateDmarc({ headerFrom: [], resolver: zoneResolver(zone) });
            expect(evaluation.response).to.be.false;
            expect(evaluation.reason).to.equal('no-author-domain');

            expect(await dmarc({ headerFrom: ['a@example.com', 'b@example.net'], resolver: zoneResolver(zone) })).to.be.false;
        });

        it('Should evaluate through authenticate()', async () => {
            const res = await authenticate(Buffer.from('From: a@example.com, b@example.com\r\nSubject: t\r\n\r\nbody\r\n'), {
                ip: '192.0.2.1',
                helo: 'mx.example.com',
                sender: 'bounce@example.com',
                mta: 'mx.test',
                resolver: zoneResolver(zone),
                disableArc: true,
                disableBimi: true
            });
            expect(res.dmarc.status.result).to.equal('fail');
            expect(res.headers).to.include('dmarc=fail');
        });
    });

    describe('I3: From without a domain', () => {
        it('Should not query "_dmarc." for an empty domain', async () => {
            for (let headerFrom of ['u@', 'u@.', '@']) {
                const resolver = zoneResolver({});
                const evaluation = await evaluateDmarc({ headerFrom, resolver });
                expect(evaluation.response, headerFrom).to.be.false;
                expect(evaluation.reason, headerFrom).to.equal('no-author-domain');
                expect(resolver.calls, headerFrom).to.have.lengthOf(0);
            }
        });
    });

    describe('F4: failed Tree Walk of the author domain', () => {
        const zone = { '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] } };

        it('Should fail an identifier that has no parent in common with the author domain', async () => {
            const result = await verifyDmarc({ headerFrom: 'u@example.com', spfDomains: ['other.net'], resolver: failingResolver(zone, ['_dmarc.com']) });
            expect(result.status.result).to.equal('fail');
            expect(result).to.not.have.property('error');
        });

        it('Should still give temperror for an identifier that could align', async () => {
            // _dmarc.com could make "com" the Organizational Domain of both
            for (let identifier of ['sub.example.com', 'other.com']) {
                const result = await verifyDmarc({ headerFrom: 'u@example.com', spfDomains: [identifier], resolver: failingResolver(zone, ['_dmarc.com']) });
                expect(result.status.result, identifier).to.equal('temperror');
                expect(result.error, identifier).to.equal('SERVFAIL _dmarc.com');
            }
        });
    });

    describe('F5: limit of Tree Walks for alignment', () => {
        it('Should give temperror, not fail, when an identifier is past the limit', async () => {
            let zone = { '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] } };
            let dkimDomains = [];
            for (let i = 0; i < 10; i++) {
                zone[`_dmarc.s${i}.example.com`] = { TXT: [['v=DMARC1; p=none; psd=n']] };
                dkimDomains.push({ domain: `s${i}.example.com` });
            }
            dkimDomains.push({ domain: 'good.example.com' });

            const result = await verifyDmarc({ headerFrom: 'u@example.com', dkimDomains, resolver: zoneResolver(zone) });
            expect(result.status.result).to.equal('temperror');
            expect(result.error).to.match(/limit of 10 Tree Walks/);
            expect(result.status).to.not.have.property('policy');
        });

        it('Should still pass when an identifier within the limit aligns', async () => {
            let zone = { '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] } };
            let dkimDomains = [{ domain: 'good.example.com' }];
            for (let i = 0; i < 12; i++) {
                zone[`_dmarc.s${i}.example.com`] = { TXT: [['v=DMARC1; p=none; psd=n']] };
                dkimDomains.push({ domain: `s${i}.example.com` });
            }

            const result = await verifyDmarc({ headerFrom: 'u@example.com', dkimDomains, resolver: zoneResolver(zone) });
            expect(result.status.result).to.equal('pass');
        });
    });

    describe('F6: Authentication-Results properties', () => {
        const zone = { '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; sp=quarantine; t=y']] } };

        it('Should add policy.dmarc with the evaluated policy and keep header.d by default', async () => {
            const result = await verifyDmarc({ headerFrom: 'u@sub.example.com', resolver: zoneResolver(zone) });
            expect(result.status.result).to.equal('fail');
            expect(result.status.policy).to.deep.equal({ dmarc: 'none' });
            expect(result.info).to.equal('dmarc=fail (p=REJECT sp=QUARANTINE) policy.dmarc=none header.from=sub.example.com header.d=example.com');
            expect(result.policyDomain).to.equal('example.com');
        });

        it('Should leave out header.d in strict mode', async () => {
            const result = await dmarc({ headerFrom: 'u@sub.example.com', resolver: zoneResolver(zone), strict: true });
            expect(result.status.header).to.deep.equal({ from: 'sub.example.com' });
            expect(result.info).to.equal('dmarc=fail (p=REJECT sp=QUARANTINE) policy.dmarc=none header.from=sub.example.com');
            expect(result.policyDomain).to.equal('example.com');
        });

        it('Should not add policy.dmarc without a record', async () => {
            const result = await verifyDmarc({ headerFrom: 'u@example.net', resolver: zoneResolver(zone) });
            expect(result.info).to.equal('dmarc=none header.from=example.net');
            expect(result).to.not.have.property('policyDomain');
        });

        it('Should not expose the internal properties for BIMI in JSON', async () => {
            const result = await verifyDmarc({ headerFrom: 'u@example.com', resolver: zoneResolver(zone) });
            expect(result.orgRecord).to.be.an('object');
            expect(result.record).to.be.an('object');
            expect(result.authorMailboxes).to.equal(1);
            const json = JSON.parse(JSON.stringify(result));
            expect(json).to.not.have.property('orgRecord');
            expect(json).to.not.have.property('record');
            expect(json).to.not.have.property('authorMailboxes');
        });
    });

    describe('F7: duplicate tags and tag name case', () => {
        it('Should let the last duplicate win by default and warn', async () => {
            const zone = { '_dmarc.example.com': { TXT: [['v=DMARC1; p=none; p=reject']] } };
            const result = await verifyDmarc({ headerFrom: 'u@example.com', resolver: zoneResolver(zone) });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('reject');
            expect(result.warnings).to.deep.equal(['duplicate-tag']);
            expect(result.info).to.not.include('duplicate');
        });

        it('Should treat a record with a duplicate tag as invalid in strict mode', async () => {
            const zone = { '_dmarc.example.com': { TXT: [['v=DMARC1; p=none; p=reject']] } };
            const result = await verifyDmarc({ headerFrom: 'u@example.com', resolver: zoneResolver(zone), strict: true });
            expect(result.status.result).to.equal('none');
            expect(result).to.not.have.property('warnings');
        });

        it('Should continue the Tree Walk past an invalid record in strict mode', async () => {
            const zone = {
                '_dmarc.sub.example.com': { TXT: [['v=DMARC1; p=none; p=none']] },
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
            };
            const result = await verifyDmarc({ headerFrom: 'u@sub.example.com', resolver: zoneResolver(zone), strict: true });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('reject');
            expect(result.policyDomain).to.equal('example.com');
        });

        it('Should case-fold tag names by default and warn', async () => {
            const zone = { '_dmarc.example.com': { TXT: [['V=DMARC1; P=reject']] } };
            const result = await verifyDmarc({ headerFrom: 'u@example.com', resolver: zoneResolver(zone) });
            expect(result.policy).to.equal('reject');
            expect(result.warnings).to.deep.equal(['tag-case']);
        });

        it('Should treat an upper case tag name as unknown in strict mode', async () => {
            // "V" is accepted by the DMARC version ABNF, "P" is not the "p" tag
            let zone = { '_dmarc.example.com': { TXT: [['V=DMARC1; P=reject; rua=mailto:dmarc@example.com']] } };
            let result = await verifyDmarc({ headerFrom: 'u@example.com', resolver: zoneResolver(zone), strict: true });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('none');

            zone = { '_dmarc.example.com': { TXT: [['v=DMARC1; p=none; P=reject']] } };
            result = await verifyDmarc({ headerFrom: 'u@example.com', resolver: zoneResolver(zone), strict: true });
            expect(result.policy).to.equal('none');
        });

        it('Should not warn for records that strict mode reads the same way', async () => {
            const zone = { '_dmarc.example.com': { TXT: [['V=DMARC1; p=reject; Foo=bar; x']] } };
            const result = await verifyDmarc({ headerFrom: 'u@example.com', resolver: zoneResolver(zone) });
            expect(result).to.not.have.property('warnings');
        });

        it('Should apply strict parsing in getDmarcRecord()', async () => {
            const zone = { '_dmarc.example.com': { TXT: [['v=DMARC1; p=none; p=reject']] } };
            expect((await getDmarcRecord('example.com', zoneResolver(zone))).p).to.equal('reject');
            expect(await getDmarcRecord('example.com', zoneResolver(zone), { strict: true })).to.be.false;
        });
    });

    describe('I4: resolver hardening', () => {
        it('Should accept TXT records as plain strings from a custom resolver', async () => {
            const resolver = async name => {
                if (name === '_dmarc.example.com') {
                    return ['v=DMARC1; p=reject'];
                }
                const err = new Error('NXDOMAIN');
                err.code = 'ENOTFOUND';
                throw err;
            };
            const result = await verifyDmarc({ headerFrom: 'u@example.com', resolver });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('reject');
        });
    });
});
