'use strict';

const dns = require('node:dns').promises;
const { formatAuthHeaderRow, formatDomain } = require('../tools');
const { createRecordLookup, discoverPolicy, getOrgDomain, getPolicyTags, domainExists } = require('./get-dmarc-record');
const { getAuthorDomain } = require('./author-domain');

// Every Tree Walk is capped at eight queries, but the number of walks is not (RFC 9989 4.10.2),
// so a message can only make this many identifiers walk for relaxed alignment. An identifier
// past the limit is not known to align or not, so it is treated like one whose walk failed.
const MAX_ALIGNMENT_WALKS = 10;

// t=y asks for the policy one level below the published one (RFC 9989 4.7 "t")
const TEST_MODE_POLICY = { reject: 'quarantine', quarantine: 'none', none: 'none' };

const POLICY_STRENGTH = { none: 0, quarantine: 1, reject: 2 };

// Two domains can only have the same Organizational Domain if they have a common parent. With
// no common label at all no Tree Walk result could make them align.
const shareParent = (a, b) => a.split('.').pop() === b.split('.').pop();

const setHidden = (obj, key, value) => Object.defineProperty(obj, key, { value, enumerable: false, configurable: true, writable: true });

const evaluateDmarc = async opts => {
    let { headerFrom, fromFields, fromSyntax, spfDomains, dkimDomains, resolver, arcResult, strict } = opts;

    strict = !!strict;
    resolver = resolver || dns.resolve;

    // RFC 9989 5.3.1: several mailboxes are fine if they share one domain, but with zero or more
    // than one Author Domain DMARC validation is not possible. The response stays false, as it
    // always was for these messages, and "reason" says why.
    // a From header field that only the lenient parsing accepts is invalid in strict mode
    const author = getAuthorDomain(headerFrom, fromFields, { fromSyntax, strict });
    if (!author.authorDomain) {
        return { response: false, reason: author.reason, authorDomains: author.domains };
    }

    // "domain" is reported in header.from. "authorDomain" is the name to query and compare,
    // where "example.com." and "example.com" are the same domain.
    const { domain, authorDomain } = author;

    // what the default mode accepted that strict mode would not
    const warnings = new Set();
    if (fromSyntax === 'lax') {
        warnings.add('from-syntax');
    }

    let formatResponse = response => {
        if (warnings.size) {
            response.warnings = Array.from(warnings);
        }

        response.info = formatAuthHeaderRow('dmarc', response.status, { strict });

        if (typeof response.status.comment === 'boolean') {
            delete response.status.comment;
        }

        // for BIMI (draft-brand-indicators-for-message-identification 7.1), not part of the result
        setHidden(response, 'authorMailboxes', author.mailboxes);

        return response;
    };

    let status = {
        result: 'neutral',
        comment: false,
        // ptype properties
        header: {
            // RFC 9989 9.1: header.from is the domain of the RFC5322.From address,
            // not the organizational domain the policy may have been inherited from
            from: domain
        }
    };

    // the strict parsing rejects what the default parsing would note, so it adds no warnings
    const lookup = createRecordLookup(resolver, { strict, warnings });

    let policyDiscovery;
    try {
        policyDiscovery = await discoverPolicy(authorDomain, lookup);
    } catch (err) {
        // temperror?
        status.result = 'temperror';
        return { response: formatResponse({ status, domain: authorDomain, error: err.message }) };
    }

    let { record: dmarcRecord, recordDomain, orgDomain, orgRecord } = policyDiscovery;

    if (!dmarcRecord) {
        // nothing to do here
        // none
        status.result = 'none';
        return { response: formatResponse({ status, domain: orgDomain }) };
    }

    const policyTags = getPolicyTags(dmarcRecord);
    if (!policyTags) {
        // no valid policy and nowhere to report to, the record gets no DMARC processing (RFC 9989 4.10.1)
        status.result = 'none';
        return { response: formatResponse({ status, domain: orgDomain || authorDomain }) };
    }

    if (!strict) {
        // The domain the applied policy record was published at, the DMARC Policy Domain. This
        // property is not registered for dmarc (RFC 9989 9.1), so strict mode leaves it out and
        // the domain is only reported in "policyDomain".
        status.header.d = recordDomain;
    }

    let policy = policyTags.p;
    // set when the existence query that decides between "sp" and "np" failed
    let existenceError = null;
    if (recordDomain !== authorDomain) {
        // A record inherited by a subdomain applies "np" if the subdomain does not exist and "sp"
        // if it does, both falling back to "p" (RFC 9989 4.10.1). Existence only matters with "np".
        policy = policyTags.sp || policyTags.p;
        if (policyTags.np) {
            try {
                if (!(await domainExists(authorDomain, resolver))) {
                    policy = policyTags.np;
                }
            } catch (err) {
                if (policyTags.np !== policy) {
                    // The policy is one of the two, but which one is not known. This only matters
                    // for a message that does not pass. Until then the weaker one is assumed, so
                    // that nothing (such as BIMI) treats the domain as more enforcing than it is.
                    existenceError = err;
                    if (POLICY_STRENGTH[policyTags.np] < POLICY_STRENGTH[policy]) {
                        policy = policyTags.np;
                    }
                }
            }
        }
    }

    const testMode = dmarcRecord.t === 'y';
    if (testMode) {
        policy = TEST_MODE_POLICY[policy];
    }

    status.comment = []
        .concat(`p=${policyTags.p.toUpperCase()}`)
        .concat(policyTags.sp ? `sp=${policyTags.sp.toUpperCase()}` : [])
        .concat(arcResult?.status?.result ? `arc=${arcResult?.status?.result}` : [])
        .join(' ');

    const adkimStrict = dmarcRecord.adkim === 's';
    const aspfStrict = dmarcRecord.aspf === 's';

    // Relaxed alignment compares Organizational Domains found by Tree Walks (RFC 9989 4.10.2).
    // An identifier's Organizational Domain is always the identifier itself or one of its
    // parents, so only identifiers at or below the author's Organizational Domain need a walk.
    let orgDomains = new Map();
    // throws when a Tree Walk the answer depends on failed, or was not made because of the limit
    const alignsRelaxed = async entryDomain => {
        if (entryDomain === authorDomain) {
            return true;
        }
        if (!orgDomain) {
            // The author's own Tree Walk failed, so there is nothing to compare against,
            // unless the two domains have no parent in common and can never align
            if (!shareParent(entryDomain, authorDomain)) {
                return false;
            }
            throw policyDiscovery.error;
        }
        if (entryDomain !== orgDomain && !entryDomain.endsWith(`.${orgDomain}`)) {
            return false;
        }
        if (!orgDomains.has(entryDomain)) {
            if (orgDomains.size >= MAX_ALIGNMENT_WALKS) {
                let err = new Error(`Alignment of ${entryDomain} not checked, limit of ${MAX_ALIGNMENT_WALKS} Tree Walks per message reached`);
                err.code = 'EWALKLIMIT';
                throw err;
            }
            orgDomains.set(entryDomain, getOrgDomain(entryDomain, lookup));
        }
        return (await orgDomains.get(entryDomain)) === orgDomain;
    };

    // Returns every entry that aligns, most preferred first, and the first walk error seen.
    // Signatures with an l= tag come last, so that a signature covering the whole body is
    // reported when several align.
    const findAligned = async (entries, strictAlignment) => {
        let list = []
            .concat(entries || [])
            .map(entry => (typeof entry === 'string' ? { domain: entry } : entry))
            .filter(entry => entry && typeof entry.domain === 'string')
            .sort((a, b) => (a.underSized || 0) - (b.underSized || 0));

        let aligned = [];
        let error = null;
        for (let entry of list) {
            let entryDomain = formatDomain(entry.domain);
            if (!authorDomain || !entryDomain) {
                // a bare root label normalizes to an empty string, which must not align with anything
                continue;
            }
            try {
                if (strictAlignment ? entryDomain === authorDomain : await alignsRelaxed(entryDomain)) {
                    aligned.push(entry);
                }
            } catch (err) {
                error = error || err;
            }
        }

        return { aligned, error };
    };

    // SPF first, so a flood of DKIM signatures can not use up the walks it needs
    const spf = await findAligned(spfDomains, aspfStrict);
    // every signature is checked, so that each one's own alignment can be reported
    const dkim = await findAligned(dkimDomains, adkimStrict);
    const spfAlignment = spf.aligned[0];
    const dkimAlignment = dkim.aligned[0];
    const walkError = spf.error || dkim.error;

    // "underSized" warns that a passing DKIM signature covers only part of the body (l= tag).
    // It describes the signature rather than the alignment mode, so it is still reported when
    // strict alignment rejected a signature that aligns at the org level. A walk that fails
    // for this warning alone does not affect the result.
    const underSized = adkimStrict && !dkimAlignment ? (await findAligned(dkimDomains, false)).aligned[0]?.underSized : dkimAlignment?.underSized;

    let response = {
        status,
        domain: orgDomain || authorDomain,
        // the DMARC Policy Domain (RFC 9989 3.2.5), where the applied record was published.
        // This is the domain RFC 9990 aggregate reports list as the published policy's domain.
        policyDomain: recordDomain,
        policy,
        p: policyTags.p,
        sp: policyTags.sp || policyTags.p,
        np: policyTags.np,
        testMode,
        rr: dmarcRecord.rr,

        alignment: {
            spf: { result: spfAlignment?.domain, strict: aspfStrict },
            dkim: { result: dkimAlignment?.domain, strict: adkimStrict, underSized }
        }
    };

    if (dkimAlignment || spfAlignment) {
        // pass
        status.result = 'pass';
    } else if (walkError || existenceError) {
        // an identifier might have aligned if its Tree Walk had not failed, or the
        // policy to apply is not known because the author domain's existence is not
        status.result = 'temperror';
        response.error = (walkError || existenceError).message;
    } else {
        // fail
        status.result = 'fail';
    }

    if (status.result !== 'temperror' && !existenceError) {
        // RFC 9989 9.1: the evaluated policy after the policy options have been processed
        status.policy = { dmarc: policy };
    }

    // for BIMI (draft-brand-indicators-for-message-identification 7.1), not part of the result:
    // the applied record and the record holding the Organizational Domain's policy (null if unknown)
    setHidden(response, 'record', dmarcRecord);
    setHidden(response, 'orgRecord', orgRecord);

    return { response: formatResponse(response), dkimAligned: new Set(dkim.aligned.map(entry => formatDomain(entry.domain))) };
};

const verifyDmarc = async opts => (await evaluateDmarc(opts)).response;

module.exports = verifyDmarc;
// also returns the signing domains that aligned, for the per signature flags of authenticate()
module.exports.evaluateDmarc = evaluateDmarc;
