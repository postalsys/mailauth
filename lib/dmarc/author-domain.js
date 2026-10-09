'use strict';

const { formatDomain, toALabel } = require('../tools');

// Characters that can not appear in a domain name taken from an address. Anything like this
// means the address was malformed and the text after the "@" is not a domain. Control characters
// (Cc, including DEL) and invisible format characters (Cf, such as U+200B or the soft hyphen) are
// not valid in a U-label (RFC 5890 2.3.2.1, RFC 5892), so such a domain has no A-label. U+200C and
// U+200D are left out, IDNA2008 allows them in some scripts (CONTEXTJ).
const INVALID_DOMAIN_CHARS = /[\s"<>(),;:\\@[\]\p{Cc}]|[^\P{Cf}\u200c\u200d]/u;

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
// "opts.fromSyntax" is the syntax of the From header field (see parseFromHeader). An "invalid"
// field, or a "lax" one with "opts.strict", gives no Author Domain, as the addresses may not be
// the ones a reader sees. For backward compatibility "opts" can also be a boolean that is true
// for a From header field that could not be parsed.
const getAuthorDomain = (headerFrom, fromFields, opts) => {
    let fromInvalid = opts;
    if (opts && typeof opts === 'object') {
        fromInvalid = opts.fromSyntax === 'invalid' || (!!opts.strict && opts.fromSyntax === 'lax');
    }

    let addresses = [].concat(headerFrom === undefined || headerFrom === null ? [] : headerFrom);

    let found = new Map();
    let invalid = false;
    // a mailbox has a domain part, but it is not a domain name
    let malformed = !!fromInvalid;
    for (let address of addresses) {
        let entries = getAddressDomains(address);
        if (!entries.length) {
            // a mailbox without a usable domain is not skipped, the domain a reader sees for it
            // is unknown, so the Author Domain can not be determined
            invalid = true;
            if (typeof address === 'string' && address.indexOf('@') >= 0 && address.slice(address.lastIndexOf('@') + 1).replace(/^\s*\.?\s*$/, '')) {
                malformed = true;
            }
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

    if (malformed || (invalid && found.size)) {
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

// RFC 5322 3.2.3 atext, with the UTF-8 of RFC 6532 3.2
const ATEXT = /[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~\u0080-￿]/;

// ASCII control characters other than whitespace. RFC 5322 4.1 only allows them (obs-NO-WS-CTL)
// in comments, quoted strings and domain literals
const ASCII_CTL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;

class FromSyntaxError extends Error {}

// Splits a From header field body into atoms, quoted strings, domain literals and single special
// characters. Whitespace and comments (CFWS) are dropped: where RFC 5322 allows CFWS, including
// between the atoms of an obs-domain (4.4), it has no meaning, and where it is not allowed, the
// tokens around it are not valid next to each other anyway.
const tokenizeFrom = value => {
    let tokens = [];
    let i = 0;

    // reads a quoted string, a comment or a domain literal that starts at "i"
    let readEnclosed = (close, nests) => {
        let start = i;
        let depth = 0;
        for (; i < value.length; i++) {
            let c = value.charAt(i);
            if (c === '\\' && close !== ']') {
                i++;
            } else if (nests && c === '(') {
                depth++;
            } else if (c === close && (!nests || !--depth)) {
                i++;
                return value.slice(start, i);
            } else if (close === ']' && i > start && (c === '[' || c === '\\')) {
                break;
            }
        }
        throw new FromSyntaxError('unterminated');
    };

    while (i < value.length) {
        let c = value.charAt(i);
        if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
            i++;
        } else if (c === '(') {
            readEnclosed(')', true);
        } else if (c === '"') {
            i++;
            tokens.push({ type: 'quoted', value: '"' + readEnclosed('"') });
        } else if (c === '[') {
            tokens.push({ type: 'literal', value: readEnclosed(']') });
        } else if (ATEXT.test(c)) {
            let start = i;
            while (i < value.length && ATEXT.test(value.charAt(i))) {
                i++;
            }
            tokens.push({ type: 'atom', value: value.slice(start, i) });
        } else if (ASCII_CTL.test(c)) {
            throw new FromSyntaxError('control character');
        } else {
            // one of the specials ) < > ] : ; @ \ , .
            tokens.push({ type: c });
            i++;
        }
    }

    return tokens;
};

// Parses the body of a From header field (RFC 5322 3.6.2 and 4.5.2, a mailbox-list or, by
// RFC 6854, an address-list) and returns the addr-spec of every mailbox, with CFWS removed and
// without a source route. "syntax" is "valid", "lax" for a field that only the lenient parsing
// accepts, or "invalid". An invalid field gives no reliable Author Domain (RFC 9989 4.4), so a
// domain that is not the one a reader sees can not be evaluated in its place.
//
// The lenient parsing accepts:
//   - a display name without an address, as in "Doe, John <john@example.com>"
//   - a group that is not closed with ";" at the end of the field
//   - a domain literal or a leading "." in a display name
//   - a domain with a trailing dot
//   - an addr-spec in place of a display name, as in "a@example.com <a@example.com>". Its address
//     is returned too when it differs from the angle-addr, so that a reader who sees it as the
//     author does not get the other domain evaluated
// Anything else that is not RFC 5322 syntax, such as text after an angle-addr or two addresses
// without a comma between them, makes the field invalid.
const parseFromHeader = value => {
    let addresses = [];
    let lax = false;
    let tokens;
    let pos = 0;

    let peek = () => tokens[pos]?.type;
    let expect = type => {
        if (peek() !== type) {
            throw new FromSyntaxError(`expected "${type}"`);
        }
        return tokens[pos++];
    };

    // domain = dot-atom / domain-literal / obs-domain
    let parseDomain = () => {
        if (peek() === 'literal') {
            return tokens[pos++].value;
        }
        let domain = expect('atom').value;
        while (peek() === '.') {
            pos++;
            if (peek() !== 'atom') {
                // a trailing dot, as in "user@example.com."
                lax = true;
                return domain + '.';
            }
            domain += '.' + tokens[pos++].value;
        }
        return domain;
    };

    // local-part = dot-atom / quoted-string / obs-local-part (word *("." word))
    let toLocalPart = words => {
        if (!words.length || words.length % 2 === 0) {
            throw new FromSyntaxError('invalid local-part');
        }
        for (let i = 0; i < words.length; i++) {
            // words and dots alternate, anything else between two words (such as a domain
            // literal) is not a local-part
            let valid = i % 2 === 0 ? words[i].type === 'atom' || words[i].type === 'quoted' : words[i].type === '.';
            if (!valid) {
                throw new FromSyntaxError('invalid local-part');
            }
        }
        return words.map(word => (word.type === '.' ? '.' : word.value)).join('');
    };

    let parseAddrSpec = () => {
        let words = [];
        while (['atom', 'quoted', '.'].includes(peek())) {
            words.push(tokens[pos++]);
        }
        let localPart = toLocalPart(words);
        expect('@');
        return `${localPart}@${parseDomain()}`;
    };

    // angle-addr, or obs-angle-addr with a source route that is dropped
    let parseAngleAddr = () => {
        expect('<');
        if (peek() === '@') {
            // obs-route = obs-domain-list ":"
            while (peek() === '@' || peek() === ',') {
                if (tokens[pos++].type === '@') {
                    parseDomain();
                }
            }
            expect(':');
        }
        let address = parseAddrSpec();
        expect('>');
        return address;
    };

    let parseMailbox = inGroup => {
        // display-name (phrase or obs-phrase), or the local-part of an addr-spec
        let words = [];
        while (['atom', 'quoted', '.', 'literal'].includes(peek())) {
            words.push(tokens[pos++]);
        }

        let next = peek();

        if (next === '@') {
            let localPart = toLocalPart(words);
            pos++;
            let address = `${localPart}@${parseDomain()}`;
            if (peek() !== '<') {
                addresses.push(address);
                return;
            }
            // an addr-spec used as a display name
            lax = true;
            let angleAddress = parseAngleAddr();
            if (address.toLowerCase() !== angleAddress.toLowerCase()) {
                addresses.push(address);
            }
            addresses.push(angleAddress);
            return;
        }

        if (words.some(word => word.type === 'literal') || words[0]?.type === '.') {
            lax = true;
        }

        if (next === '<') {
            addresses.push(parseAngleAddr());
            return;
        }

        if (next === ':' && !inGroup && words.length) {
            // group = display-name ":" [group-list] ";" [CFWS]
            pos++;
            for (;;) {
                while (peek() === ',') {
                    pos++;
                }
                if (peek() === ';') {
                    pos++;
                    return;
                }
                if (!peek()) {
                    lax = true;
                    return;
                }
                parseMailbox(true);
                if (peek() !== ',' && peek() !== ';' && peek()) {
                    throw new FromSyntaxError('unexpected text in group');
                }
            }
        }

        if (!words.length) {
            throw new FromSyntaxError('unexpected character');
        }

        // a display name without an address
        lax = true;
    };

    try {
        tokens = tokenizeFrom((value || '').toString());
        for (;;) {
            // obs-mbox-list allows empty list elements
            while (peek() === ',') {
                pos++;
            }
            if (!peek()) {
                break;
            }
            parseMailbox(false);
            if (peek() && peek() !== ',') {
                throw new FromSyntaxError('unexpected text after address');
            }
        }
    } catch (err) {
        if (!(err instanceof FromSyntaxError)) {
            throw err;
        }
        return { addresses, syntax: 'invalid' };
    }

    return { addresses, syntax: lax ? 'lax' : 'valid' };
};

module.exports = { getAuthorDomain, getAddressDomains, parseFromHeader };
