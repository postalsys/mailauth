// Authentic From header fields (draft-ietf-dkim-dkim2-spec-09 sections 7.1 item 3, 11, 12.4 and
// 14.8): the domain of the From address has to match the signing domain of the DKIM2-Signature
// that was added when the From was put into the message

import { Buffer } from 'node:buffer';
import { parseFromHeader, getAuthorDomain } from '../dmarc/author-domain.js';
import { relaxedMatch } from './domains.js';
import { KeyError } from './records.js';
import type { PolicyLookup } from './records.js';

/**
 * The outcome of comparing one From with a signing domain:
 *   - "direct": the From domain is the signing domain or one of its subdomains
 *   - "upward": the signing domain is a subdomain of the From domain, which makes the From
 *     Authentic unless the Domain Policy Record of `domain` has the "strict" flag (section 11.1)
 *   - "fail": the From can not be Authentic, `message` is the section 14.8 error string after
 *     "DKIM2-Signature i=<x>"
 */
type FromMatch = { status: 'direct' | 'upward'; domain: string; message?: undefined } | { status: 'fail'; message: string; domain?: undefined };

const notAuthentic: FromMatch = { status: 'fail', message: 'matching From is not authentic' };

/**
 * Finds the domain of the single address of a From header field
 *
 * @param {Buffer[]} fields The From header fields of a message, canonicalized
 * @returns {Object} { domain }, a lower case A-label, or { message } when the From can never be
 *          Authentic (section 11)
 */
const fromDomain = (fields: Buffer[]): { domain: string; message?: undefined } | { domain?: undefined; message: string } => {
    if (fields.length > 1) {
        // RFC 5322 allows one From header field, a reader may be shown any of them
        return { message: 'From has more than one address' };
    }
    if (!fields.length) {
        return { message: notAuthentic.message };
    }

    let line = fields[0].toString('utf8');
    let { addresses, syntax } = parseFromHeader(line.substring(line.indexOf(':') + 1));
    if (addresses.length > 1) {
        return { message: 'From has more than one address' };
    }
    if (syntax === 'invalid' || !addresses.length) {
        // a From that can not be parsed has no address a reader is known to see
        return { message: notAuthentic.message };
    }
    if (addresses[0].endsWith(']')) {
        return { message: 'From uses a domain literal' };
    }

    // the same address rules as the DMARC Author Domain, the domain as a lower case A-label
    // without a trailing dot (section 18)
    let author = getAuthorDomain(addresses, 1, { fromSyntax: syntax });
    if (!author.authorDomain) {
        return { message: notAuthentic.message };
    }
    return { domain: author.authorDomain };
};

/**
 * Compares a From header field with the signing domain of its relevant DKIM2-Signature
 * (section 7.1 item 3): first with the From domain as Parameter1, then the other way round
 *
 * @param {Buffer[]} fields The From header fields, canonicalized
 * @param {String} signingDomain d= of the relevant DKIM2-Signature
 * @returns {Object} See FromMatch
 */
const matchFrom = (fields: Buffer[], signingDomain: string): FromMatch => {
    let { domain, message } = fromDomain(fields);
    if (!domain) {
        return { status: 'fail', message: message! };
    }
    if (relaxedMatch(domain, signingDomain)) {
        return { status: 'direct', domain };
    }
    if (relaxedMatch(signingDomain, domain)) {
        return { status: 'upward', domain };
    }
    return notAuthentic;
};

/**
 * Section 11: whether a From is Authentic with the signing domain of its relevant
 * DKIM2-Signature. A subdomain makes it Authentic unless the From domain publishes a Domain Policy
 * Record with the "strict" flag (section 11.1), which is only looked up for that case
 *
 * @param {Buffer[]} fields The From header fields, canonicalized
 * @param {String} signingDomain d= of the relevant DKIM2-Signature
 * @param {Function} policyLookup Domain Policy Record lookup
 * @returns {Object|null} null when the From is Authentic, otherwise { result, message } with the
 *          section 14.8 error string after "DKIM2-Signature i=<x>"
 */
const checkAuthentic = async (
    fields: Buffer[],
    signingDomain: string,
    policyLookup: PolicyLookup
): Promise<{ result: 'fail' | 'permerror' | 'temperror'; message: string } | null> => {
    let match = matchFrom(fields, signingDomain);
    if (match.status === 'fail') {
        return { result: 'fail', message: match.message };
    }
    if (match.status === 'direct') {
        return null;
    }
    try {
        return (await policyLookup(match.domain)).strict ? { result: 'fail', message: `From ${match.domain} forbids subdomain signing` } : null;
    } catch (err) {
        if (!(err instanceof KeyError)) {
            throw err;
        }
        return { result: err.result, message: err.message };
    }
};

// Whether two lists of canonicalized header fields are the same
const sameFields = (left: Buffer[], right: Buffer[]): boolean => left.length === right.length && left.every((field, index) => field.equals(right[index]));

export { matchFrom, checkAuthentic, sameFields };
