// DNS records of DKIM2: TXT lookups, and the Domain Policy Record (draft-ietf-dkim-dkim2-spec-09
// section 3.8)

import { promises as dns } from 'node:dns';
import { parseTagList, toALabel, isValidDnsName } from '../tools.js';
import type { DNSResolver } from '../types.js';

// Whether the Domain Policy Record of a domain has the "strict" flag (section 3.8)
type PolicyLookup = (domain: string) => Promise<{ strict: boolean }>;

// DNS answers that mean there is no record. Anything else could be transient
const NO_RECORD_CODES = new Set(['ENOTFOUND', 'ENODATA']);

class KeyError extends Error {
    declare result: 'permerror' | 'temperror';
    declare rr?: string | undefined;

    /**
     * @param {String} result "permerror" or "temperror"
     * @param {String} message The end of the section 14.5 error string, after "public key <s1>",
     *        or the whole section 14.8 policy error after "DKIM2-Signature i=<x>"
     * @param {String} [rr] The key record
     */
    constructor(result: 'permerror' | 'temperror', message: string, rr?: string) {
        super(message);
        this.result = result;
        if (rr) {
            this.rr = rr;
        }
    }
}

const permerror = (reason: string, rr?: string): KeyError => new KeyError('permerror', reason, rr);

// the strings of a TXT record are joined with no whitespace between them
const joinRecord = (record: string | string[]): string => ([] as string[]).concat(record).join('');

// The v= value of a record that begins with a v= tag, or null. Tag names are case-sensitive
const leadingVersion = (rr: string): string | null => {
    let match = /^[ \t\r\n]*v[ \t\r\n]*=([^;]*)/.exec(rr);
    return match ? match[1].trim() : null;
};

/**
 * Fetches the TXT records of a name
 *
 * @param {String} name Domain name
 * @param {Function} resolver DNS resolver
 * @returns {String[]|null} Records, null when there are none
 * @throws {Error} For a lookup that may work later
 */
const fetchRecords = async (name: string, resolver: DNSResolver): Promise<string[] | null> => {
    let lookupName = toALabel(name);
    if (!isValidDnsName(lookupName)) {
        return null;
    }

    let list;
    try {
        list = await resolver(lookupName, 'TXT');
    } catch (err: any) {
        // section 14.5: a timeout is a TEMPERROR, an absent record is not
        if (NO_RECORD_CODES.has(err.code)) {
            return null;
        }
        throw new Error('DNS lookup failed');
    }

    return Array.isArray(list) && list.length ? list.map(joinRecord) : null;
};

/**
 * Fetches the Domain Policy Record of a domain (section 3.8): a tag-list at
 * "_domainkey.<domain>" that begins with v=DKIM1. Records that do not are ignored, no record
 * means subdomains are authorized, and the "strict" flag of f= says they are not
 *
 * @param {String} domain From domain, an A-label
 * @param {Function} resolver DNS resolver
 * @returns {Object} { strict }
 * @throws {KeyError} With the section 14.8 error string after "DKIM2-Signature i=<x>"
 */
const fetchPolicy = async (domain: string, resolver: DNSResolver): Promise<{ strict: boolean }> => {
    let records;
    try {
        records = await fetchRecords(`_domainkey.${domain}`, resolver);
    } catch {
        throw new KeyError('temperror', `policy for ${domain} unavailable`);
    }

    records = (records || []).filter(rr => leadingVersion(rr) === 'DKIM1');
    if (!records.length) {
        return { strict: false };
    }
    if (records.length > 1) {
        throw permerror(`multiple records for ${domain} policy`);
    }

    let rr = records[0];
    let entry = parseTagList(rr, { strict: true });
    if (entry.syntaxErrors.length) {
        // the draft does not say what a broken record means, so it is not read as authorizing
        throw permerror(`policy for ${domain} has a syntax error`, rr);
    }

    // a colon-separated list of case-sensitive flags, unknown flags are ignored
    let flags = String(entry.parsed.f?.value || '')
        .split(':')
        .map(flag => flag.trim());
    return { strict: flags.includes('strict') };
};

/**
 * Creates a Domain Policy Record lookup for one message, one DNS query per domain
 *
 * @param {Function} [resolver] DNS resolver, defaults to dns.promises.resolve
 * @returns {Function} async (domain) => { strict }, throws KeyError
 */
const createPolicyLookup = (resolver?: DNSResolver | undefined): PolicyLookup => {
    resolver = resolver || dns.resolve;
    let cache = new Map<string, ReturnType<PolicyLookup>>();
    return domain => {
        if (!cache.has(domain)) {
            let lookup = fetchPolicy(domain, resolver);
            lookup.catch(() => false);
            cache.set(domain, lookup);
        }
        return cache.get(domain)!;
    };
};

export { KeyError, permerror, leadingVersion, fetchRecords, createPolicyLookup };
export type { PolicyLookup };
