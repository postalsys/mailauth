'use strict';

const { formatDomain, toALabel } = require('../tools');

// Characters that can not appear in a domain name taken from an address. Anything like this
// means the address was malformed and the text after the "@" is not a domain.
const INVALID_DOMAIN_CHARS = /[\s"<>(),;:\\@[\]]/;

// A domain literal (RFC 5322 3.4.1). It is kept as is, it can not publish a DMARC record.
const DOMAIN_LITERAL = /^\[[^[\]\\]*\]$/;

// Removes an obsolete source route (RFC 5322 4.4 obs-angle-addr), as in "@relay.example:ceo@bank.example",
// where the route ends with the first ":" that is not inside a domain literal
const stripRoute = address => {
    if (address.charAt(0) !== '@') {
        return address;
    }
    let inLiteral = false;
    for (let i = 1; i < address.length; i++) {
        let c = address.charAt(i);
        if (c === '[') {
            inLiteral = true;
        } else if (c === ']') {
            inLiteral = false;
        } else if (c === ':' && !inLiteral) {
            return address.slice(i + 1);
        }
    }
    return address;
};

// Returns the positions of the "@" signs that separate a local-part from a domain. An "@" inside
// a quoted string of the local-part (RFC 5322 3.2.4) or inside a domain literal does not count.
// With an unterminated quoted string the quotes are not honored, so that the "@" of an address
// such as '"ceo@bank.example' still counts and the domain the reader sees is not dropped.
const findSeparators = (address, honorQuotes) => {
    let positions = [];
    let inQuote = false;
    let escaped = false;
    let inLiteral = false;

    for (let i = 0; i < address.length; i++) {
        let c = address.charAt(i);
        if (inQuote) {
            if (escaped) {
                escaped = false;
            } else if (c === '\\') {
                escaped = true;
            } else if (c === '"') {
                inQuote = false;
            }
            continue;
        }
        if (inLiteral) {
            if (c === ']') {
                inLiteral = false;
            }
            continue;
        }
        if (c === '"' && honorQuotes && !positions.length) {
            inQuote = true;
        } else if (c === '[' && positions.length) {
            inLiteral = true;
        } else if (c === '@') {
            positions.push(i);
        }
    }

    if (inQuote) {
        return findSeparators(address, false);
    }

    return positions;
};

// Normalizes the domain part of an address. Returns { domain, authorDomain } or null when it is
// not a domain. "domain" is lower case and an A-label (RFC 9989 5.3.1), "authorDomain" also has
// the trailing root dot removed and is the name that is queried and compared.
const normalizeDomain = value => {
    let domain = (value || '').trim().toLowerCase();
    if (!domain) {
        return null;
    }

    if (!DOMAIN_LITERAL.test(domain)) {
        if (INVALID_DOMAIN_CHARS.test(domain)) {
            return null;
        }
        domain = toALabel(domain);
    }

    let authorDomain = formatDomain(domain);
    if (!authorDomain) {
        // "user@." has no domain name, only the root
        return null;
    }

    return { domain, authorDomain };
};

// Returns the normalized domains found in one address. A valid addr-spec has one domain, the text
// after the "@" that ends the local-part. An address with more than one "@" outside a quoted string
// is malformed and every candidate is returned, so that it counts as more than one Author Domain.
const getAddressDomains = address => {
    if (typeof address !== 'string') {
        return [];
    }

    address = address.trim();

    if (address.indexOf('@') < 0) {
        // not an address, but dmarc() has always accepted a bare domain name here
        let entry = normalizeDomain(address);
        return entry ? [entry] : [];
    }

    address = stripRoute(address);

    let positions = findSeparators(address, true);
    let domains = [];
    for (let i = 0; i < positions.length; i++) {
        let entry = normalizeDomain(address.slice(positions[i] + 1, i + 1 < positions.length ? positions[i + 1] : address.length));
        if (entry) {
            domains.push(entry);
        }
    }

    return domains;
};

// Extracts the Author Domain from the RFC5322.From addresses (RFC 9989 5.3.1). Several mailboxes
// are fine as long as they all use the same domain. Returns
//   { domain, authorDomain, mailboxes } when there is exactly one Author Domain, or
//   { reason, domains, mailboxes } when DMARC validation is not possible, where "reason" is
//   "no-author-domain", "multiple-author-domains", "invalid-author-domain" or
//   "multiple-from-fields".
// "fromFields" is the number of From header fields the addresses came from, if known. RFC 5322
// allows only one, and with several the DKIM signature can cover a different field than the one
// a mail client shows, so their addresses are not merged into one Author Domain.
const getAuthorDomain = (headerFrom, fromFields) => {
    let addresses = [].concat(headerFrom === undefined || headerFrom === null ? [] : headerFrom);

    let found = new Map();
    let invalid = false;
    for (let address of addresses) {
        let entries = getAddressDomains(address);
        if (!entries.length) {
            // a mailbox without a usable domain is not skipped, the domain a reader sees for it
            // is unknown, so the Author Domain can not be determined
            invalid = true;
        }
        for (let entry of entries) {
            if (!found.has(entry.authorDomain)) {
                found.set(entry.authorDomain, entry);
            }
        }
    }

    let mailboxes = addresses.length;

    if (fromFields > 1) {
        return { reason: 'multiple-from-fields', domains: Array.from(found.keys()), mailboxes };
    }

    if (invalid && found.size) {
        return { reason: 'invalid-author-domain', domains: Array.from(found.keys()), mailboxes };
    }

    if (found.size === 1) {
        let [entry] = found.values();
        return { domain: entry.domain, authorDomain: entry.authorDomain, mailboxes };
    }

    return {
        reason: found.size ? 'multiple-author-domains' : 'no-author-domain',
        domains: Array.from(found.keys()),
        mailboxes
    };
};

module.exports = { getAuthorDomain, getAddressDomains };
