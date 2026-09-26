'use strict';

const punycode = require('punycode.js');
const { formatAuthHeaderRow, formatDomain } = require('../tools');
const { createRecordLookup, discoverPolicy, getOrgDomain } = require('./get-dmarc-record');

// Every Tree Walk is capped at eight queries, but the number of walks is not (RFC 9989 4.10.2),
// so a message can only make this many identifiers walk for relaxed alignment. The rest do not align.
const MAX_ALIGNMENT_WALKS = 10;

const evaluateDmarc = async opts => {
    let { headerFrom, spfDomains, dkimDomains, resolver, arcResult } = opts;

    if (Array.isArray(headerFrom)) {
        if (headerFrom.length === 1) {
            headerFrom = headerFrom[0];
        } else {
            // invalid number of FROM addresses found
            return { response: false };
        }
    }

    let atPos = headerFrom.indexOf('@');
    let domain = atPos >= 0 ? headerFrom.substr(atPos + 1) : headerFrom;

    domain = domain.toLowerCase().trim();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        // ignore punycode conversion errors
    }

    // the name to query and compare, "example.com." and "example.com" are the same domain
    const authorDomain = formatDomain(domain);

    let formatResponse = response => {
        response.info = formatAuthHeaderRow('dmarc', response.status);

        if (typeof response.status.comment === 'boolean') {
            delete response.status.comment;
        }

        return response;
    };

    let status = {
        result: 'neutral',
        comment: false,
        // ptype properties
        header: {
            // RFC 8601 2.7.2: header.from is the domain of the RFC5322.From address,
            // not the organizational domain the policy may have been inherited from
            from: domain
        }
    };

    const lookup = createRecordLookup(resolver);

    let policyDiscovery;
    try {
        policyDiscovery = await discoverPolicy(authorDomain, lookup);
    } catch (err) {
        // temperror?
        status.result = 'temperror';
        return { response: formatResponse({ status, domain: authorDomain, error: err.message }) };
    }

    let { record: dmarcRecord, recordDomain, orgDomain } = policyDiscovery;

    if (!dmarcRecord) {
        // nothing to do here
        // none
        status.result = 'none';
        return { response: formatResponse({ status, domain: orgDomain }) };
    }

    // the domain the applied policy record was published at
    status.header.d = recordDomain;

    status.comment = []
        .concat(dmarcRecord.p ? `p=${dmarcRecord.p.toUpperCase()}` : [])
        .concat(dmarcRecord.sp ? `sp=${dmarcRecord.sp.toUpperCase()}` : [])
        .concat(arcResult?.status?.result ? `arc=${arcResult?.status?.result}` : [])
        .join(' ');

    // use "sp" if the record was inherited by a subdomain and "sp" is set, otherwise use "p"
    const policy = recordDomain !== authorDomain && dmarcRecord.sp ? dmarcRecord.sp : dmarcRecord.p;

    const adkimStrict = dmarcRecord.adkim === 's';
    const aspfStrict = dmarcRecord.aspf === 's';

    // Relaxed alignment compares Organizational Domains found by Tree Walks (RFC 9989 4.10.2).
    // An identifier's Organizational Domain is always the identifier itself or one of its
    // parents, so only identifiers at or below the author's Organizational Domain need a walk.
    let orgDomains = new Map();
    // throws when a Tree Walk the answer depends on failed
    const alignsRelaxed = async entryDomain => {
        if (entryDomain === authorDomain) {
            return true;
        }
        if (!orgDomain) {
            // the author's own Tree Walk failed, so there is nothing to compare against
            throw policyDiscovery.error;
        }
        if (entryDomain !== orgDomain && !entryDomain.endsWith(`.${orgDomain}`)) {
            return false;
        }
        if (!orgDomains.has(entryDomain)) {
            if (orgDomains.size >= MAX_ALIGNMENT_WALKS) {
                return false;
            }
            orgDomains.set(entryDomain, getOrgDomain(entryDomain, lookup));
        }
        return (await orgDomains.get(entryDomain)) === orgDomain;
    };

    // Returns every entry that aligns, most preferred first, and the first walk error seen.
    // Signatures with an l= tag come last, so that a signature covering the whole body is
    // reported when several align.
    const findAligned = async (entries, strict) => {
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
                if (strict ? entryDomain === authorDomain : await alignsRelaxed(entryDomain)) {
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
        policy,
        p: dmarcRecord.p,
        sp: dmarcRecord.sp || dmarcRecord.p,
        pct: dmarcRecord.pct,
        rr: dmarcRecord.rr,

        alignment: {
            spf: { result: spfAlignment?.domain, strict: aspfStrict },
            dkim: { result: dkimAlignment?.domain, strict: adkimStrict, underSized }
        }
    };

    if (dkimAlignment || spfAlignment) {
        // pass
        status.result = 'pass';
    } else if (walkError) {
        // an identifier might have aligned if its Tree Walk had not failed
        status.result = 'temperror';
        response.error = walkError.message;
    } else {
        // fail
        status.result = 'fail';
    }

    return { response: formatResponse(response), dkimAligned: new Set(dkim.aligned.map(entry => formatDomain(entry.domain))) };
};

const verifyDmarc = async opts => (await evaluateDmarc(opts)).response;

module.exports = verifyDmarc;
// also returns the signing domains that aligned, for the per signature flags of authenticate()
module.exports.evaluateDmarc = evaluateDmarc;
