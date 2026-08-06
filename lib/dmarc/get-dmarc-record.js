'use strict';

const dns = require('node:dns').promises;
const tldkit = require('tldkit');
const { TLDTS_OPTS } = require('../tools');

// Tags whose values are ABNF literals in RFC 7489 6.4 / RFC 9989 4.7 and are therefore
// case insensitive (RFC 5234 2.3). Values of other tags keep their case: "v" is defined
// with explicit hex literals and is case sensitive, "rua"/"ruf" are URIs.
const CASE_INSENSITIVE_TAGS = new Set(['p', 'sp', 'np', 'adkim', 'aspf', 'fo', 'rf', 't', 'psd']);

// Returns every DMARC record published for a domain. The caller distinguishes an empty set,
// which continues policy discovery at the organizational domain, from a multi record set,
// which terminates it (RFC 7489 6.6.3 step 5).
const resolveTxt = async (domain, resolver) => {
    try {
        let txt = await resolver(`_dmarc.${domain}`, 'TXT');
        return (txt || []).map(row => row.join('').trim()).filter(row => /^v=DMARC1\b/i.test(row));
    } catch (err) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
            return [];
        }
        throw err;
    }
};

const getDmarcRecord = async (domain, resolver) => {
    resolver = resolver || dns.resolve;

    let records = await resolveTxt(domain, resolver);
    let isOrgRecord = false;

    if (!records.length) {
        let orgDomain = tldkit.getDomain(domain, TLDTS_OPTS);
        // No registrable domain, so there is nothing to inherit a policy from.
        // Without this the fallback would query `_dmarc.null`.
        if (orgDomain && orgDomain !== domain) {
            // try org domain as well
            records = await resolveTxt(orgDomain, resolver);
            isOrgRecord = true;
        }
    }

    if (records.length !== 1) {
        // no record, or a multi record set that terminates policy discovery
        return false;
    }

    let txt = records[0];

    let parsed = Object.fromEntries(
        txt
            .split(';')
            .map(e => e.trim())
            .filter(e => e)
            .map(e => {
                let splitPos = e.indexOf('=');
                if (splitPos < 0) {
                    return [e.toLowerCase().trim(), false];
                } else if (splitPos === 0) {
                    return [false, e];
                }
                // whitespace is allowed around "=" (*WSP in the ABNF), so the value must be trimmed
                let key = e.substr(0, splitPos).toLowerCase().trim();
                let val = e.substr(splitPos + 1).trim();
                if (['pct', 'ri'].includes(key)) {
                    val = parseInt(val, 10) || 0;
                } else if (CASE_INSENSITIVE_TAGS.has(key)) {
                    val = val.toLowerCase();
                }
                return [key, val];
            })
    );

    parsed.rr = txt;
    parsed.isOrgRecord = isOrgRecord;

    return parsed;
};

module.exports = getDmarcRecord;
