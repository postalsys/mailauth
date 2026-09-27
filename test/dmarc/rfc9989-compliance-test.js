/* eslint no-unused-expressions:0 */
'use strict';

// RFC 9989 (DMARCbis) compliance harness.
//
// This file is an executable specification of the target DMARC behaviour from
// RFC 9989 (https://www.rfc-editor.org/rfc/rfc9989.txt). The suite numbering follows
// the gap analysis this harness was written from (items #1, #3-#8, #10).
//
// Suites for features that are not implemented yet use `describe.skip(...)` so the
// default `npm test` run stays green (they report as pending). To develop a feature
// test-first, change its `describe.skip` to `describe`, implement until green, and
// leave it active as a regression guard.
//
// Note that a few cases inside the skipped suites already pass today, but only as a
// side effect of organizational-record inheritance rather than of the feature under
// test. They are marked inline and must be re-verified when the feature lands.
//
// Expected outcomes are taken verbatim from the RFC's normative text and the worked
// examples in Appendix B.4.

const chai = require('chai');
const expect = chai.expect;

const verifyDmarc = require('../../lib/dmarc/verify');
const { zoneResolver } = require('../helpers/dns-zone');

chai.config.includeStack = true;

describe('RFC 9989 DMARC compliance', () => {
    // ---------------------------------------------------------------------------
    // Behaviour that is already correct today. These run normally and pin current
    // results so future work (tree walk, etc.) cannot silently regress them.
    // ---------------------------------------------------------------------------
    describe('Currently compliant (regression guards)', () => {
        it('passes on identical strict alignment (adkim=s)', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; adkim=s']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.policy).to.equal('reject');
        });

        it('passes on relaxed organizational-domain alignment via the org record', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('pass');
        });

        it('returns none when no DMARC record exists', async () => {
            const resolver = zoneResolver({});
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('none');
        });

        it('discards the record set when multiple DMARC records are published (§4.10 step 2)', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject'], ['v=DMARC1; p=none']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('none');
        });

        it('discards a multi-record set at the author domain and continues the walk (§4.10 steps 2 and 6, §4.10.1)', async () => {
            // RFC 7489 6.6.3 ended policy discovery here. RFC 9989 discards the records and,
            // as no valid record was found by the first query, performs a Tree Walk.
            const resolver = zoneResolver({
                '_dmarc.mail.example.com': { TXT: [['v=DMARC1; p=reject'], ['v=DMARC1; p=quarantine']] },
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=none; sp=quarantine']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('fail');
            expect(result.status.header.d).to.equal('example.com');
            expect(result.policy).to.equal('quarantine');
        });

        it('continues to the org domain when the author domain publishes only non-DMARC TXT records (§4.10)', async () => {
            const resolver = zoneResolver({
                '_dmarc.mail.example.com': { TXT: [['some other txt record'], ['and another one']] },
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=quarantine']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.policy).to.equal('quarantine');
        });

        it('joins split (chunked) TXT records', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=re', 'ject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.policy).to.equal('reject');
        });

        it('does not let pct change the pass/fail outcome (#6: pct is historic in RFC 9989 §A.6)', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; pct=0']] }
            });

            const aligned = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(aligned.status.result).to.equal('pass');

            // pct=0 historically meant "apply the policy to no messages". It must not turn a
            // failing evaluation into a passing one, which is the only way this assertion can bite.
            const unaligned = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'other.example' }],
                spfDomains: [{ domain: 'other.example' }],
                resolver
            });
            expect(unaligned.status.result).to.equal('fail');
        });

        // RFC 9989 Appendix B.4.1, the query sequence is asserted in the #1 suite below
        it('B.4.1: org domain and alignment for a simple hierarchy', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] },
                '_dmarc.signing.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                spfDomains: [{ domain: 'example.com' }],
                dkimDomains: [{ domain: 'signing.example.com' }],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.domain).to.equal('example.com');
        });

        // RFC 9989 Appendix B.4.2: deep name, records only at example.com. The bounded
        // query sequence is asserted in the #1 suite below.
        it('B.4.2: org domain for a deep author name resolves to example.com', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] },
                '_dmarc.signing.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@a.b.c.d.e.f.g.h.i.j.k.example.com',
                spfDomains: [{ domain: 'example.com' }],
                dkimDomains: [{ domain: 'signing.example.com' }],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.domain).to.equal('example.com');
        });
    });

    // ---------------------------------------------------------------------------
    // #1 DNS Tree Walk: policy discovery and organizational domain
    // RFC 9989 §4.10, §4.10.1, §4.10.2. Replaces the Public Suffix List.
    // ---------------------------------------------------------------------------
    describe('#1 DNS Tree Walk: policy discovery and organizational domain [§4.10, §4.10.2]', () => {
        it('uses a record published at an intermediate label marked psd=n as the org domain', async () => {
            // Author a.b.example.com: walk finds _dmarc.b.example.com with psd=n and stops there.
            // b.example.com is the Organizational Domain, so its policy (reject) applies, not example.com's.
            const resolver = zoneResolver({
                '_dmarc.b.example.com': { TXT: [['v=DMARC1; p=reject; psd=n']] },
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=none']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@a.b.example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver
            });
            expect(result.domain).to.equal('b.example.com');
            expect(result.policy).to.equal('reject');
        });

        it('walks every label and caps a >8-label author at 8 queries in the exact RFC sequence (§4.10)', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=none']] }
            });
            await verifyDmarc({
                headerFrom: 'user@a.b.c.d.e.f.g.h.i.j.k.example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver
            });
            const dmarcQueries = resolver.calls.filter(c => c.type === 'TXT' && c.name.startsWith('_dmarc.')).map(c => c.name);
            expect(dmarcQueries).to.deep.equal([
                '_dmarc.a.b.c.d.e.f.g.h.i.j.k.example.com',
                '_dmarc.g.h.i.j.k.example.com',
                '_dmarc.h.i.j.k.example.com',
                '_dmarc.i.j.k.example.com',
                '_dmarc.j.k.example.com',
                '_dmarc.k.example.com',
                '_dmarc.example.com',
                '_dmarc.com'
            ]);
        });

        const dmarcQueries = resolver => resolver.calls.filter(c => c.type === 'TXT').map(c => c.name);

        it('B.4.1: queries the author walk and each differing identifier walk once', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] },
                '_dmarc.signing.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                spfDomains: [{ domain: 'example.com' }],
                dkimDomains: [{ domain: 'signing.example.com' }],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.alignment.spf.result).to.equal('example.com');
            expect(result.alignment.dkim.result).to.equal('signing.example.com');
            expect(dmarcQueries(resolver)).to.deep.equal(['_dmarc.example.com', '_dmarc.com', '_dmarc.signing.example.com']);
        });

        it('B.4.2: an identifier walk reuses the names the author walk already queried', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] },
                '_dmarc.signing.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@a.b.c.d.e.f.g.h.i.j.k.example.com',
                spfDomains: [{ domain: 'example.com' }],
                dkimDomains: [{ domain: 'signing.example.com' }],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.status.header.d).to.equal('example.com');
            expect(result.alignment.spf.result).to.equal('example.com');
            expect(result.alignment.dkim.result).to.equal('signing.example.com');
            expect(dmarcQueries(resolver)).to.have.lengthOf(9);
            expect(dmarcQueries(resolver).slice(-1)).to.deep.equal(['_dmarc.signing.example.com']);
        });

        it('shortens an author of exactly eight labels by one label and one of nine labels to seven (§4.10 step 4)', async () => {
            let resolver = zoneResolver({});
            await verifyDmarc({ headerFrom: 'user@a.b.c.d.e.f.example.com', resolver });
            expect(dmarcQueries(resolver).slice(0, 2)).to.deep.equal(['_dmarc.a.b.c.d.e.f.example.com', '_dmarc.b.c.d.e.f.example.com']);
            expect(dmarcQueries(resolver)).to.have.lengthOf(8);

            resolver = zoneResolver({});
            await verifyDmarc({ headerFrom: 'user@x.a.b.c.d.e.f.example.com', resolver });
            expect(dmarcQueries(resolver).slice(0, 2)).to.deep.equal(['_dmarc.x.a.b.c.d.e.f.example.com', '_dmarc.b.c.d.e.f.example.com']);
            expect(dmarcQueries(resolver)).to.have.lengthOf(8);
        });

        it('makes the author domain its own org domain when no record is published above it (§4.10.2 rule 3)', async () => {
            // the Public Suffix List would say example.com, and d=example.com would align
            const resolver = zoneResolver({
                '_dmarc.mail.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [{ domain: 'bounce.example.com' }],
                resolver
            });
            expect(result.status.result).to.equal('fail');
            expect(result.domain).to.equal('mail.example.com');
            expect(result.policy).to.equal('reject');
        });

        it('takes the policy of the record with the fewest labels, not an intermediate one (§4.10.1)', async () => {
            const resolver = zoneResolver({
                '_dmarc.b.example.com': { TXT: [['v=DMARC1; p=none']] },
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({ headerFrom: 'user@a.b.example.com', resolver });
            expect(result.domain).to.equal('example.com');
            expect(result.status.header.d).to.equal('example.com');
            expect(result.policy).to.equal('reject');
        });

        it('inherits a policy from a name the Public Suffix List lists as a suffix', async () => {
            const resolver = zoneResolver({
                '_dmarc.blogspot.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@alice.blogspot.com',
                dkimDomains: [{ domain: 'bob.blogspot.com' }],
                resolver
            });
            expect(result.domain).to.equal('blogspot.com');
            expect(result.status.header.d).to.equal('blogspot.com');
            expect(result.policy).to.equal('reject');
            // both names share the Organizational Domain blogspot.com
            expect(result.status.result).to.equal('pass');
        });

        it('lets psd=n on the author record keep a parent from becoming its org domain', async () => {
            const resolver = zoneResolver({
                '_dmarc.mail.example.com': { TXT: [['v=DMARC1; p=reject; psd=n']] },
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [{ domain: 'example.com' }],
                resolver
            });
            expect(result.domain).to.equal('mail.example.com');
            expect(result.status.result).to.equal('fail');
            // the walk stops at the psd tag
            expect(dmarcQueries(resolver)).to.deep.equal(['_dmarc.mail.example.com']);
        });

        it('discards a multi-record set above the author domain and keeps walking', async () => {
            const resolver = zoneResolver({
                '_dmarc.b.example.com': { TXT: [['v=DMARC1; p=reject; psd=n'], ['v=DMARC1; p=none']] },
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=quarantine']] }
            });
            const result = await verifyDmarc({ headerFrom: 'user@a.b.example.com', resolver });
            expect(result.domain).to.equal('example.com');
            expect(result.policy).to.equal('quarantine');
        });

        it('does not walk identifiers outside the author org domain', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                spfDomains: [{ domain: 'bounces.esp.example.net' }],
                dkimDomains: [{ domain: 'esp.example.net' }, { domain: 'example.org' }],
                resolver
            });
            expect(result.status.result).to.equal('fail');
            expect(dmarcQueries(resolver)).to.deep.equal(['_dmarc.example.com', '_dmarc.com']);
        });

        it('caps relaxed alignment walks per message and checks SPF before DKIM', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const dkimDomains = [];
            for (let i = 0; i < 20; i++) {
                dkimDomains.push({ domain: `s${i}.example.com` });
            }
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                spfDomains: [{ domain: 'bounces.example.com' }],
                dkimDomains,
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.alignment.spf.result).to.equal('bounces.example.com');
            // SPF plus nine signing domains, one query each on top of the author walk
            expect(dmarcQueries(resolver)).to.have.lengthOf(2 + 10);
            expect(dmarcQueries(resolver)).to.include('_dmarc.bounces.example.com');
            expect(dmarcQueries(resolver)).to.not.include('_dmarc.s9.example.com');
        });

        it('does not query names that can not exist, and treats EBADNAME as no record', async () => {
            let resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            let result = await verifyDmarc({ headerFrom: `user@${'a'.repeat(64)}.example.com`, resolver });
            expect(result.policy).to.equal('reject');
            expect(dmarcQueries(resolver)).to.deep.equal(['_dmarc.example.com', '_dmarc.com']);

            result = await verifyDmarc({ headerFrom: 'user@[192.0.2.1]', resolver: zoneResolver({}) });
            expect(result.status.result).to.equal('none');

            const badName = async name => {
                if (name === '_dmarc.example.com') {
                    return [['v=DMARC1; p=quarantine']];
                }
                const err = new Error('bad name');
                err.code = name === '_dmarc.com' ? 'ENOTFOUND' : 'EBADNAME';
                throw err;
            };
            result = await verifyDmarc({ headerFrom: 'user@mail.example.com', resolver: badName });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('quarantine');
        });

        it('ignores a trailing root dot on the author domain and identifiers', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com.',
                dkimDomains: [{ domain: 'example.com.' }],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.domain).to.equal('example.com');
        });

        describe('DNS failures', () => {
            // a resolver that fails for the listed names and serves the zone otherwise
            const failingResolver = (zone, failing) => {
                const resolver = zoneResolver(zone);
                return async (name, type) => {
                    if (failing.includes(name)) {
                        const err = new Error(`SERVFAIL: ${name}`);
                        err.code = 'ESERVFAIL';
                        throw err;
                    }
                    return resolver(name, type);
                };
            };

            it('returns temperror when the policy can not be discovered', async () => {
                const resolver = failingResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] } }, ['_dmarc.example.com']);
                const result = await verifyDmarc({ headerFrom: 'user@mail.example.com', dkimDomains: [{ domain: 'example.com' }], resolver });
                expect(result.status.result).to.equal('temperror');
                expect(result.domain).to.equal('mail.example.com');
                expect(result).to.not.have.property('policy');
            });

            it('keeps the author record when the walk above it fails and an identical identifier aligns', async () => {
                const resolver = failingResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] } }, ['_dmarc.com']);
                const result = await verifyDmarc({ headerFrom: 'user@example.com', dkimDomains: [{ domain: 'example.com' }], resolver });
                expect(result.status.result).to.equal('pass');
                expect(result.policy).to.equal('reject');
                expect(result.domain).to.equal('example.com');
            });

            it('returns temperror with the policy when the walk above the author fails and only a differing identifier could align', async () => {
                const resolver = failingResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] } }, ['_dmarc.com']);
                const result = await verifyDmarc({ headerFrom: 'user@example.com', dkimDomains: [{ domain: 'mail.example.com' }], resolver });
                expect(result.status.result).to.equal('temperror');
                expect(result.error).to.equal('SERVFAIL: _dmarc.com');
                expect(result.policy).to.equal('reject');
                expect(result.p).to.equal('reject');
                expect(result.rr).to.equal('v=DMARC1; p=reject');
            });

            it('returns temperror when an identifier walk fails and nothing else aligns', async () => {
                const resolver = failingResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] } }, ['_dmarc.mail.example.com']);
                const result = await verifyDmarc({ headerFrom: 'user@example.com', dkimDomains: [{ domain: 'mail.example.com' }], resolver });
                expect(result.status.result).to.equal('temperror');
                expect(result.policy).to.equal('reject');
            });

            it('passes when an identifier walk fails but another identifier aligns', async () => {
                const resolver = failingResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] } }, ['_dmarc.mail.example.com']);
                const result = await verifyDmarc({
                    headerFrom: 'user@example.com',
                    spfDomains: [{ domain: 'bounces.example.com' }],
                    dkimDomains: [{ domain: 'mail.example.com' }],
                    resolver
                });
                expect(result.status.result).to.equal('pass');
                expect(result.alignment.spf.result).to.equal('bounces.example.com');
            });

            it('does not turn a strict alignment failure into a temperror', async () => {
                const resolver = failingResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; adkim=s']] } }, ['_dmarc.mail.example.com']);
                const result = await verifyDmarc({ headerFrom: 'user@example.com', dkimDomains: [{ domain: 'mail.example.com', underSized: 10 }], resolver });
                expect(result.status.result).to.equal('fail');
                expect(result.alignment.dkim.underSized).to.be.undefined;
            });
        });
    });

    // ---------------------------------------------------------------------------
    // #3 np: Domain Owner Assessment Policy for non-existent subdomains
    // RFC 9989 §4.7 (np), §4.10.1, §3.2.13, Appendix A.4 (domain existence test).
    // ---------------------------------------------------------------------------
    describe('#3 np + domain-existence test [§4.7 np, §4.10.1, §3.2.13, §A.4]', () => {
        it('applies np for a non-existent (NXDOMAIN) author subdomain', async () => {
            // sub.example.com does not exist (NXDOMAIN). np must be applied, not sp/p.
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; sp=none; np=quarantine']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@sub.example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver
            });
            expect(result.policy).to.equal('quarantine');
        });

        it('applies sp (not np) for an existing author subdomain', async () => {
            // sub.example.com exists (has an A record), so the existing-subdomain policy (sp) applies.
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; sp=none; np=quarantine']] },
                'sub.example.com': { A: ['192.0.2.10'] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@sub.example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver
            });
            expect(result.policy).to.equal('none');
        });

        it('treats a name with any RR (NODATA on TXT) as existing for the existence test', async () => {
            // mail.example.com has an MX but no TXT: it exists, so np must not be applied.
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; sp=none; np=quarantine']] },
                'mail.example.com': { MX: [{ priority: 1, exchange: 'mx.example.com' }] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver
            });
            expect(result.policy).to.equal('none');
        });

        const npZone = extra => ({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; sp=none; np=quarantine']] }, ...extra });

        it('treats a subdomain with a dangling CNAME as existing and applies sp', async () => {
            // the A query for shop.example.com follows its CNAME to a missing target and gets that
            // NXDOMAIN (RFC 6604 3), but the CNAME is an RR, so the name exists (RFC 9989 A.4)
            const resolver = zoneResolver(npZone({ 'shop.example.com': { CNAME: ['gone.example.net'] } }));
            const result = await verifyDmarc({ headerFrom: 'user@shop.example.com', resolver });
            expect(result.policy).to.equal('none');
        });

        it('does not apply np to the org domain itself and skips the existence query', async () => {
            const resolver = zoneResolver(npZone());
            const result = await verifyDmarc({ headerFrom: 'user@example.com', resolver });
            expect(result.policy).to.equal('reject');
            expect(result.np).to.equal('quarantine');
            expect(resolver.calls.filter(c => c.type !== 'TXT')).to.have.lengthOf(0);
        });

        it('does not query for existence when the record has no np', async () => {
            const resolver = zoneResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; sp=none']] } });
            const result = await verifyDmarc({ headerFrom: 'user@sub.example.com', resolver });
            expect(result.policy).to.equal('none');
            expect(resolver.calls.filter(c => c.type !== 'TXT')).to.have.lengthOf(0);
        });

        it('falls back to p for a non-existent subdomain without sp', async () => {
            const resolver = zoneResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=quarantine; np=reject']] }, 'sub.example.com': { A: ['192.0.2.1'] } });
            const result = await verifyDmarc({ headerFrom: 'user@sub.example.com', resolver });
            expect(result.policy).to.equal('quarantine');
        });

        it('applies a PSD np to a non-existent registration below it (.gov style)', async () => {
            const resolver = zoneResolver({ '_dmarc.gov.example': { TXT: [['v=DMARC1; p=reject; sp=none; np=reject; psd=y']] } });
            const result = await verifyDmarc({ headerFrom: 'user@fake-agency.gov.example', resolver });
            expect(result.status.header.d).to.equal('gov.example');
            expect(result.policy).to.equal('reject');
        });

        it('treats a name that can not exist as non-existent without querying it', async () => {
            const resolver = zoneResolver(npZone());
            const result = await verifyDmarc({ headerFrom: `user@${'a'.repeat(64)}.example.com`, resolver });
            expect(result.policy).to.equal('quarantine');
            expect(resolver.calls.filter(c => c.type !== 'TXT')).to.have.lengthOf(0);
        });

        const existenceServfail = (failingType = 'A') => {
            const zone = zoneResolver(npZone());
            return async (name, type) => {
                if (type === failingType) {
                    const err = new Error('SERVFAIL');
                    err.code = 'ESERVFAIL';
                    throw err;
                }
                return zone(name, type);
            };
        };

        it('passes an aligned message when the existence query fails', async () => {
            // the policy only matters for a message that does not pass (RFC 9989 5.3.5)
            const result = await verifyDmarc({ headerFrom: 'user@sub.example.com', dkimDomains: [{ domain: 'example.com' }], resolver: existenceServfail() });
            expect(result.status.result).to.equal('pass');
            expect(result).to.not.have.property('error');
            // sp=none or np=quarantine, whichever is weaker, and no policy.dmarc since it is not known
            expect(result.policy).to.equal('none');
            expect(result.status).to.not.have.property('policy');
            expect(result.info).to.not.include('policy.dmarc');
        });

        it('returns temperror for a failing message when the existence query fails', async () => {
            const result = await verifyDmarc({ headerFrom: 'user@sub.example.com', dkimDomains: [{ domain: 'other.example' }], resolver: existenceServfail() });
            expect(result.status.result).to.equal('temperror');
            expect(result.error).to.equal('SERVFAIL');
        });

        it('returns temperror for a failing message when the CNAME query after an NXDOMAIN fails', async () => {
            // the A query found nothing, so the name's own CNAME decides, and without an answer the
            // policy is not known
            const result = await verifyDmarc({
                headerFrom: 'user@sub.example.com',
                dkimDomains: [{ domain: 'other.example' }],
                resolver: existenceServfail('CNAME')
            });
            expect(result.status.result).to.equal('temperror');
            expect(result.error).to.equal('SERVFAIL');
        });

        it('ignores a failed existence query when np and sp are the same policy', async () => {
            const zone = zoneResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=none; sp=reject; np=reject']] } });
            const resolver = async (name, type) => {
                if (type === 'A') {
                    const err = new Error('SERVFAIL');
                    err.code = 'ESERVFAIL';
                    throw err;
                }
                return zone(name, type);
            };
            const result = await verifyDmarc({ headerFrom: 'user@sub.example.com', dkimDomains: [{ domain: 'other.example' }], resolver });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('reject');
            expect(result.info).to.include('policy.dmarc=reject');
        });
    });

    // ---------------------------------------------------------------------------
    // #4 psd: Public Suffix Domain discovery
    // RFC 9989 §4.7 (psd), §4.10.2, §5.2. Worked example: Appendix B.4.3.
    // ---------------------------------------------------------------------------
    describe('#4 psd / PSD discovery [§4.7 psd, §4.10.2, §5.2; example B.4.3]', () => {
        it('B.4.3: psd=y stops the walk and the org domain is one label below the PSD', async () => {
            // Author giant.bank.example. Walk: _dmarc.giant.bank.example (record) then
            // _dmarc.bank.example (psd=y -> stop). Org domain = giant.bank.example.
            // DKIM mail.mega.bank.example -> org mega.bank.example -> NOT aligned.
            // SPF mail.giant.bank.example -> org giant.bank.example -> aligned -> DMARC pass.
            const resolver = zoneResolver({
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject; psd=y; rua=mailto:psd@bank.example']] },
                '_dmarc.giant.bank.example': { TXT: [['v=DMARC1; p=quarantine']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@giant.bank.example',
                spfDomains: [{ domain: 'mail.giant.bank.example' }],
                dkimDomains: [{ domain: 'mail.mega.bank.example' }],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.domain).to.equal('giant.bank.example');
            // the aligned identifier itself is reported, not its Organizational Domain
            expect(result.alignment.spf.result).to.equal('mail.giant.bank.example');
            expect(result.alignment.dkim.result).to.not.be.ok;
            // every walk stops at the psd=y record, so "_dmarc.example" is never queried. The DKIM
            // domain is not below giant.bank.example, so its Organizational Domain can not be
            // giant.bank.example either and the walk the example makes for it is skipped.
            expect(resolver.calls.filter(c => c.type === 'TXT').map(c => c.name)).to.deep.equal([
                '_dmarc.giant.bank.example',
                '_dmarc.bank.example',
                '_dmarc.mail.giant.bank.example'
            ]);
        });

        it('PSD policy is not used when the org domain publishes its own record (§4.10.1 note)', async () => {
            // foo.example has its own record; the psd=y record above it must not override it.
            const resolver = zoneResolver({
                '_dmarc.example': { TXT: [['v=DMARC1; p=reject; psd=y; rua=mailto:psd@example']] },
                '_dmarc.foo.example': { TXT: [['v=DMARC1; p=none']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@foo.example',
                dkimDomains: [],
                spfDomains: [],
                resolver
            });
            expect(result.domain).to.equal('foo.example');
            expect(result.policy).to.equal('none');
        });

        it('applies the PSD policy, with sp, when the org domain publishes no record (§4.10.1)', async () => {
            const resolver = zoneResolver({
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject; sp=quarantine; psd=y']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@mail.giant.bank.example',
                dkimDomains: [{ domain: 'giant.bank.example' }],
                resolver
            });
            expect(result.domain).to.equal('giant.bank.example');
            expect(result.status.header.d).to.equal('bank.example');
            expect(result.policy).to.equal('quarantine');
            expect(result.status.result).to.equal('pass');
        });

        it('does not align two registrants below the same PSD', async () => {
            const resolver = zoneResolver({
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject; psd=y']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@giant.bank.example',
                spfDomains: [{ domain: 'bank.example' }],
                dkimDomains: [{ domain: 'mega.bank.example' }],
                resolver
            });
            expect(result.domain).to.equal('giant.bank.example');
            expect(result.policy).to.equal('reject');
            expect(result.status.result).to.equal('fail');
        });

        it('treats a PSD sending as itself as its own org domain (§4.10.2 rule 2 skips the start)', async () => {
            const resolver = zoneResolver({
                '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject; sp=none; psd=y']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@bank.example',
                spfDomains: [{ domain: 'mail.bank.example' }],
                resolver
            });
            expect(result.domain).to.equal('bank.example');
            expect(result.policy).to.equal('reject');
            // the walk from mail.bank.example stops at the psd=y record, one label below it
            expect(result.status.result).to.equal('fail');
        });
    });

    // ---------------------------------------------------------------------------
    // #5 t: DMARC policy test mode
    // RFC 9989 §4.7 (t), Appendix A.6. t=y downgrades the applied policy one level:
    // `policy` is the downgraded one, `p` and `sp` stay as published, and `testMode` is set.
    // ---------------------------------------------------------------------------
    describe('#5 t: policy test mode [§4.7 t, §A.6]', () => {
        it('t=y downgrades reject to quarantine for a failing message', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; t=y']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('quarantine');
        });

        it('t=y downgrades quarantine to none for a failing message', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=quarantine; t=y']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('none');
        });

        it('t=y keeps the published p and sp and reports testMode', async () => {
            const resolver = zoneResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; sp=quarantine; t=Y']] } });
            const result = await verifyDmarc({ headerFrom: 'user@sub.example.com', resolver });
            expect(result.policy).to.equal('none');
            expect(result.p).to.equal('reject');
            expect(result.sp).to.equal('quarantine');
            expect(result.testMode).to.be.true;
        });

        it('t=n and an invalid t value apply the policy as published', async () => {
            for (let t of ['n', 'yes']) {
                const resolver = zoneResolver({ '_dmarc.example.com': { TXT: [[`v=DMARC1; p=reject; t=${t}`]] } });
                const result = await verifyDmarc({ headerFrom: 'user@example.com', resolver });
                expect(result.policy).to.equal('reject');
                expect(result.testMode).to.be.false;
            }
        });
    });

    // ---------------------------------------------------------------------------
    // #6 pct is historic in RFC 9989 (§9.3, §A.6).
    // pct does not affect pass/fail (asserted in the active block above) and is not
    // reported in the result either.
    // ---------------------------------------------------------------------------
    describe('#6 pct is historic, not surfaced in the result [§9.3, §A.6]', () => {
        it('does not expose a pct property on the result', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; pct=50']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result).to.not.have.property('pct');
        });
    });

    // ---------------------------------------------------------------------------
    // #7 Records with no valid policy
    // RFC 9989 §4.10.1, §4.7.
    // ---------------------------------------------------------------------------
    describe('#7 invalid/absent p ⇒ p=none when rua present, else no processing [§4.10.1, §4.7]', () => {
        it('treats a record with no p but a valid rua as p=none and continues processing', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; rua=mailto:dmarc@example.com']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.policy).to.equal('none');
        });

        it('applies no DMARC processing for a record with no p and no rua', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; adkim=s']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('none');
        });

        it('treats an invalid p with a valid rua as p=none, keeping other tags', async () => {
            const resolver = zoneResolver({ '_dmarc.example.com': { TXT: [['v=DMARC1; p=block; adkim=s; rua=mailto:dmarc@example.com!10m']] } });
            const result = await verifyDmarc({ headerFrom: 'user@example.com', dkimDomains: [{ domain: 'mail.example.com' }], resolver });
            expect(result.status.result).to.equal('fail');
            expect(result.policy).to.equal('none');
            expect(result.p).to.equal('none');
            expect(result.alignment.dkim.strict).to.be.true;
        });

        it('treats a valid p with an invalid sp or np as p=none when rua is valid', async () => {
            for (let tag of ['sp=bounce', 'np=']) {
                const resolver = zoneResolver({ '_dmarc.example.com': { TXT: [[`v=DMARC1; p=reject; ${tag}; rua=mailto:dmarc@example.com`]] } });
                const result = await verifyDmarc({ headerFrom: 'user@sub.example.com', resolver });
                expect(result.policy).to.equal('none');
                expect(result.sp).to.equal('none');
            }
        });

        it('accepts any syntactically valid URI in rua, including an empty mailto: (RFC 3986)', async () => {
            for (let rua of ['rua=mailto:', 'rua=mailto:dmarc@example.com!10m', 'rua=bogus, https://report.example/dmarc', 'rua=mailto:d%2Cmarc@example.com']) {
                const resolver = zoneResolver({ '_dmarc.example.com': { TXT: [[`v=DMARC1; p=reject; sp=nope; ${rua}`]] } });
                const result = await verifyDmarc({ headerFrom: 'user@example.com', resolver });
                expect(result.status.result, rua).to.equal('fail');
                expect(result.policy, rua).to.equal('none');
            }
        });

        it('applies no DMARC processing when rua has no syntactically valid URI', async () => {
            for (let rua of ['rua=dmarc@example.com', 'rua=', 'rua=nothing', 'rua=<mailto:dmarc@example.com>', 'rua=mailto:a b@example.com']) {
                const resolver = zoneResolver({ '_dmarc.example.com': { TXT: [[`v=DMARC1; p=reject; sp=nope; ${rua}`]] } });
                const result = await verifyDmarc({ headerFrom: 'user@example.com', resolver });
                expect(result.status.result).to.equal('none');
                expect(result).to.not.have.property('policy');
            }
        });

        it('does not continue the walk past an author record without a valid policy', async () => {
            const resolver = zoneResolver({
                '_dmarc.mail.example.com': { TXT: [['v=DMARC1; adkim=s']] },
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({ headerFrom: 'user@mail.example.com', resolver });
            expect(result.status.result).to.equal('none');
        });
    });

    // ---------------------------------------------------------------------------
    // #8 Version tag is case sensitive
    // RFC 9989 §4.7: the v tag value is case sensitive and must be exactly "DMARC1".
    // ---------------------------------------------------------------------------
    describe('#8 version tag is case-sensitive [§4.7 v]', () => {
        it('ignores a record whose version is not exactly DMARC1 (e.g. v=dmarc1)', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=dmarc1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('none');
        });

        it('ignores a record whose version value has trailing garbage (v=DMARC1x)', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1x; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('none');
        });

        it('accepts WSP around "=" in the version tag (v = DMARC1)', async () => {
            // The ABNF allows *WSP around "=", so this record is valid and the domain
            // is protected. Discarding it would silently fail open to dmarc=none.
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v = DMARC1; p=reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.policy).to.equal('reject');
        });
    });

    // ---------------------------------------------------------------------------
    // #10 Tag value case handling
    // RFC 9989 §4.7. Tag values that are ABNF literals are case insensitive (RFC 5234 §2.3),
    // and *WSP is allowed around "=". Implemented, so this suite is an active guard.
    // ---------------------------------------------------------------------------
    describe('#10 tag value case handling [§4.7]', () => {
        it('recognizes a policy value regardless of case (p=Reject)', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=Reject']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('pass');
            expect(result.policy).to.equal('reject');
        });

        it('enforces strict alignment when adkim is upper-case (adkim=S)', async () => {
            // adkim=S must be treated as strict, so an org-only match fails.
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject; adkim=S']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('fail');
            expect(result.alignment.dkim.strict).to.be.true;
        });

        it('allows whitespace around "=" in a tag (*WSP in the ABNF)', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p = reject; adkim = s']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('fail');
            expect(result.alignment.dkim.strict).to.be.true;
            expect(result.policy).to.equal('reject');
        });

        it('preserves the case of tag values that are not ABNF literals', async () => {
            const resolver = zoneResolver({
                '_dmarc.example.com': { TXT: [['v=DMARC1; p=none; rua=mailto:DMARC-Reports@Example.COM']] }
            });
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.rr).to.contain('mailto:DMARC-Reports@Example.COM');
        });
    });
});
