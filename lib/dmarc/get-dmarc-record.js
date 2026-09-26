'use strict';

const dns = require('node:dns').promises;
const net = require('node:net');
const { formatDomain } = require('../tools');

// Tags whose values are ABNF literals in RFC 7489 6.4 / RFC 9989 4.7 and are therefore
// case insensitive (RFC 5234 2.3). Values of other tags keep their case: "v" is defined
// with explicit hex literals and is case sensitive, "rua"/"ruf" are URIs.
const CASE_INSENSITIVE_TAGS = new Set(['p', 'sp', 'np', 'adkim', 'aspf', 'fo', 'rf', 't', 'psd']);

// The version tag must be the first tag and its value "DMARC1" must match precisely
// (RFC 9989 4.7 "v"), while the ABNF allows *WSP around "=" and a case insensitive
// tag name, hence [vV] instead of an /i flag that would also relax the value
const DMARC_VERSION_RE = /^[vV][ \t]*=[ \t]*DMARC1[ \t]*(?:;|$)/;

// Resolver errors that mean the name has no record, as opposed to a transient failure.
// EBADNAME is a name that can not exist in the DNS at all.
const NO_RECORD_CODES = new Set(['ENOTFOUND', 'ENODATA', 'EBADNAME']);

// A Tree Walk shortens an author domain of eight or more labels straight to seven (RFC 9989 4.10 step 4)
const WALK_MAX_LABELS = 7;

// A domain literal or an IP address is not a DNS name and can not publish a DMARC record
const isAddress = domain => domain.startsWith('[') || net.isIP(domain) !== 0;

// Whether a name can exist in the DNS: no empty labels, labels of at most 63 octets and a
// name of at most 253 octets (RFC 1035 2.3.4). Anything else would only produce a resolver
// error that looks like a transient failure.
const isValidName = name => name.length <= 253 && name.split('.').every(label => label.length && label.length <= 63);

const POLICY_VALUES = new Set(['none', 'quarantine', 'reject']);

// "rua" lists at least one syntactically valid URI (RFC 9989 4.8 dmarc-urilist), a scheme
// followed by something. An obsolete "!size" suffix does not change that.
const hasReportingUri = record => typeof record.rua === 'string' && record.rua.split(',').some(uri => /^[a-z][a-z0-9+.-]*:[^\s,]+$/i.test(uri.trim()));

// Returns the policy tags a record is applied with (RFC 9989 4.10.1). A record without a
// valid "p", or with an invalid "sp" or "np", acts as p=none when it asks for aggregate
// reports, and gets no DMARC processing at all (null) otherwise.
const getPolicyTags = record => {
    const isValid = value => value === undefined || POLICY_VALUES.has(value);
    if (POLICY_VALUES.has(record.p) && isValid(record.sp) && isValid(record.np)) {
        return { p: record.p, sp: record.sp, np: record.np };
    }
    return hasReportingUri(record) ? { p: 'none' } : null;
};

// Domain existence test (RFC 9989 A.4): any RR makes a name exist, only NXDOMAIN means it
// does not. A query for A tells the two apart, NODATA is an existing name without A records.
const domainExists = async (domain, resolver) => {
    if (!isValidName(domain)) {
        return false;
    }
    try {
        await (resolver || dns.resolve)(domain, 'A');
        return true;
    } catch (err) {
        if (err.code === 'ENODATA') {
            return true;
        }
        if (err.code === 'ENOTFOUND' || err.code === 'EBADNAME') {
            return false;
        }
        throw err;
    }
};

const parseDmarcRecord = txt => {
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

    return parsed;
};

// Returns the DMARC Policy Record published at "_dmarc.<name>", or false. A set of several
// records counts as no record, it is discarded (RFC 9989 4.10 steps 2 and 6).
const fetchRecord = async (name, resolver) => {
    if (!isValidName(`_dmarc.${name}`)) {
        return false;
    }

    let records;
    try {
        let txt = await resolver(`_dmarc.${name}`, 'TXT');
        records = (txt || []).map(row => row.join('').trim()).filter(row => DMARC_VERSION_RE.test(row));
    } catch (err) {
        if (NO_RECORD_CODES.has(err.code)) {
            return false;
        }
        throw err;
    }

    return records.length === 1 ? parseDmarcRecord(records[0]) : false;
};

// Tree Walks for one message share most of their names, so each name is queried only once
const createRecordLookup = resolver => {
    resolver = resolver || dns.resolve;
    let cache = new Map();
    return name => {
        if (!cache.has(name)) {
            cache.set(name, fetchRecord(name, resolver));
        }
        return cache.get(name);
    };
};

// DNS Tree Walk (RFC 9989 4.10). Returns the records found, longest name first. The walk
// stops at a record with a psd=y or psd=n tag, or when no labels are left, so it makes
// at most eight queries. A DNS error ends the walk and is returned next to the records
// found before it, because a record found at the start domain is usable without the rest.
const treeWalk = async (domain, lookup) => {
    let found = [];
    let labels = domain.split('.');

    while (labels.length) {
        let name = labels.join('.');
        let record;
        try {
            record = await lookup(name);
        } catch (err) {
            return { found, error: err };
        }

        if (record) {
            found.push({ domain: name, record });
            if (record.psd === 'y' || record.psd === 'n') {
                break;
            }
        }

        labels = labels.length > WALK_MAX_LABELS ? labels.slice(-WALK_MAX_LABELS) : labels.slice(1);
    }

    return { found };
};

// Organizational Domain selection for a completed Tree Walk (RFC 9989 4.10.2)
const selectOrgDomain = (domain, found) => {
    for (let { domain: recordDomain, record } of found) {
        if (record.psd === 'n') {
            return recordDomain;
        }
        if (record.psd === 'y' && recordDomain !== domain) {
            // the domain one label below the PSD
            let labelCount = recordDomain.split('.').length + 1;
            return domain.split('.').slice(-labelCount).join('.');
        }
    }

    // the record with the fewest labels, or the start domain itself when nothing was found
    return found.length ? found[found.length - 1].domain : domain;
};

// Returns the Organizational Domain of a normalized domain name. Throws on DNS errors.
const getOrgDomain = async (domain, lookup) => {
    if (isAddress(domain)) {
        return domain;
    }
    let { found, error } = await treeWalk(domain, lookup);
    if (error) {
        throw error;
    }
    return selectOrgDomain(domain, found);
};

// DMARC Policy Discovery (RFC 9989 4.10.1) for a normalized author domain. Returns
// { record, recordDomain, orgDomain, error }, where "record" is false when no policy applies.
// When the Tree Walk fails after a record was found at the author domain, "orgDomain" is null
// and "error" says why. Throws on DNS errors that leave the policy unknown.
const discoverPolicy = async (domain, lookup) => {
    if (isAddress(domain)) {
        return { record: false, recordDomain: null, orgDomain: domain };
    }

    let { found, error } = await treeWalk(domain, lookup);

    if (found[0]?.domain === domain) {
        // the author domain's own record applies regardless of what is above it
        return { record: found[0].record, recordDomain: domain, orgDomain: error ? null : selectOrgDomain(domain, found), error };
    }

    if (error) {
        throw error;
    }

    let orgDomain = selectOrgDomain(domain, found);

    // otherwise the record of the Organizational Domain, and failing that the record of the PSD.
    // A walk only stops at a psd tag, so a psd=y record can only be the last one found.
    let last = found[found.length - 1];
    let entry = found.find(e => e.domain === orgDomain) || (last?.record.psd === 'y' ? last : null);

    return { record: entry ? entry.record : false, recordDomain: entry ? entry.domain : null, orgDomain };
};

// Fetches the DMARC Policy Record that applies to a domain. Returns the parsed record or false.
const getDmarcRecord = async (domain, resolver) => {
    domain = formatDomain(domain || '');

    let { record, recordDomain, orgDomain } = await discoverPolicy(domain, createRecordLookup(resolver));
    if (!record) {
        return false;
    }

    return Object.assign(record, {
        // the record is inherited from the Organizational Domain or the PSD
        isOrgRecord: recordDomain !== domain,
        recordDomain,
        orgDomain
    });
};

module.exports = getDmarcRecord;
module.exports.createRecordLookup = createRecordLookup;
module.exports.discoverPolicy = discoverPolicy;
module.exports.getOrgDomain = getOrgDomain;
module.exports.getPolicyTags = getPolicyTags;
module.exports.domainExists = domainExists;
