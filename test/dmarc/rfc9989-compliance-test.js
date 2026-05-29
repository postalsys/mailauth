/* eslint no-unused-expressions:0 */
'use strict';

// RFC 9989 (DMARCbis) compliance harness.
//
// This file is an executable specification of the target DMARC behaviour from
// RFC 9989 (https://www.rfc-editor.org/rfc/rfc9989.txt). See RFC9989-DMARC-REVIEW.md
// at the repo root for the gap analysis the suites below map to (items #1, #3-#8, #10).
//
// Suites for features that are NOT yet implemented use `describe.skip(...)` so the
// default `npm test` run stays green (they report as pending). To develop a feature
// test-first, change its `describe.skip` to `describe`, implement until green, and
// leave it active as a regression guard.
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
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver
            });
            expect(result.status.result).to.equal('pass');
        });

        // RFC 9989 Appendix B.4.1 — outcome matches today (PSL agrees with the Tree Walk
        // for simple names); kept active so the eventual Tree Walk keeps these correct.
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

        // RFC 9989 Appendix B.4.2 — deep name, records only at example.com. Outcome
        // matches today; the bounded query *sequence* is asserted in the #1 suite below.
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
    // #1 DNS Tree Walk — policy discovery & organizational domain
    // RFC 9989 §4.10, §4.10.1, §4.10.2. Replaces the Public Suffix List.
    // ---------------------------------------------------------------------------
    describe.skip('#1 DNS Tree Walk — policy discovery & organizational domain [§4.10–§4.10.2]', () => {
        it('uses a record published at an intermediate label marked psd=n as the org domain', async () => {
            // Author a.b.example.com: walk finds _dmarc.b.example.com with psd=n and stops there.
            // b.example.com is the Organizational Domain, so its policy (reject) applies — not example.com's.
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
    });

    // ---------------------------------------------------------------------------
    // #3 np — Domain Owner Assessment Policy for non-existent subdomains
    // RFC 9989 §4.7 (np), §4.10.1, §3.2.13, Appendix A.4 (domain existence test).
    // ---------------------------------------------------------------------------
    describe.skip('#3 np + domain-existence test [§4.7 np, §4.10.1, §3.2.13, §A.4]', () => {
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
    });

    // ---------------------------------------------------------------------------
    // #4 psd — Public Suffix Domain discovery
    // RFC 9989 §4.7 (psd), §4.10.2, §5.2. Worked example: Appendix B.4.3.
    // ---------------------------------------------------------------------------
    describe.skip('#4 psd / PSD discovery [§4.7 psd, §4.10.2, §5.2; example B.4.3]', () => {
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
            expect(result.alignment.spf.result).to.equal('giant.bank.example');
            expect(result.alignment.dkim.result).to.not.be.ok;
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
    });

    // ---------------------------------------------------------------------------
    // #5 t — DMARC policy test mode
    // RFC 9989 §4.7 (t), Appendix A.6. t=y downgrades the applied policy one level.
    // TODO: confirm the output contract for the downgrade (effective `policy` vs declared
    // `p`, or a dedicated `testMode` flag) when implementing.
    // ---------------------------------------------------------------------------
    describe.skip('#5 t — policy test mode [§4.7 t, §A.6]', () => {
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
    });

    // ---------------------------------------------------------------------------
    // #6 pct is historic in RFC 9989 (§9.3, §A.6).
    // pct already does not affect pass/fail (asserted in the active block above).
    // The spec below proposes also dropping pct from the result object. This is a
    // BREAKING output change for consumers that read result.pct, so it is left for
    // the implementer to decide; enable only if that change is adopted.
    // ---------------------------------------------------------------------------
    describe.skip('#6 pct is historic — not surfaced in the result [§9.3, §A.6]', () => {
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
    describe.skip('#7 invalid/absent p ⇒ p=none when rua present, else no processing [§4.10.1, §4.7]', () => {
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
    });

    // ---------------------------------------------------------------------------
    // #8 Version tag is case sensitive
    // RFC 9989 §4.7: the v tag value is case sensitive and must be exactly "DMARC1".
    // ---------------------------------------------------------------------------
    describe.skip('#8 version tag is case-sensitive [§4.7 v]', () => {
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
    });

    // ---------------------------------------------------------------------------
    // #10 Tag value case handling
    // RFC 9989 §4.7. Tag values should be compared case-insensitively.
    // ---------------------------------------------------------------------------
    describe.skip('#10 tag value case handling [§4.7]', () => {
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
        });
    });
});
