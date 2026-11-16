// DKIM2 signing algorithms, public key lookup and Domain Policy Records
// (draft-ietf-dkim-dkim2-spec-09 sections 3, 14.5 and 14.8, draft-ietf-dkim-dkim2-dns-02 section 3.4).
// The key records are DKIM1 key records, read with the DKIM2 rules: records with a v= other than
// DKIM1 are dropped, one record has to remain, the retired h=, n=, s= and t= tags are ignored, and
// only the rsa, ed25519 and mldsa44 key types are used.

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { promises as dns } from 'node:dns';
import { parseTagList, isBareRsaPublicKey } from '../tools.js';
import { isBase64 } from './fields.js';
import { ALGORITHM_KEY_TYPES, KEY_TYPES, rawPublicKey, isSupportedKeyType, signatureData } from './algorithms.js';
import { KeyError, permerror, leadingVersion, fetchRecords } from './records.js';
import type { DNSResolver } from '../types.js';

// A key record. `publicKey` is null for a key type that is not used, the lookup never returns
// such a key for a signature
interface DKIM2Key {
    publicKey: crypto.KeyObject | null;
    keyType: string;
    modulusLength?: number | undefined;
    rr: string;
}

type KeyLookup = (domain: string, selector: string, algorithm: string) => Promise<DKIM2Key>;

const MIN_RSA_KEY_SIZE = 1024;
// Verifiers MUST handle 1024 to 4096 bits and MAY handle more (section 3.2). Longer keys are not used
// in practice and only make verification slower
const MAX_RSA_KEY_SIZE = 8192;
// section 3.2: "The signing algorithm MUST use a public exponent of 65537"
const RSA_EXPONENT = 65537n;

// Section 3.2: why an RSA key can not be used, or null when it can
const rsaKeyProblem = (keyObject: crypto.KeyObject): string | null => {
    let details = keyObject.asymmetricKeyDetails!;
    if (details.modulusLength! < MIN_RSA_KEY_SIZE) {
        return 'is too short';
    }
    if (details.modulusLength! > MAX_RSA_KEY_SIZE) {
        return 'is too long';
    }
    if (details.publicExponent !== RSA_EXPONENT) {
        return 'has an unsupported exponent';
    }
    return null;
};

// Builds the public key of a key record, or throws the reason it can not be used
const createPublicKey = (keyType: string, rawKey: Buffer, rr: string): crypto.KeyObject => {
    let { nodeType, rawLength } = KEY_TYPES.get(keyType)!;
    // section 14.5: an Ed25519 key that is not exactly 32 octets, or an ML-DSA-44 key that is not
    // exactly 1312 octets, is malformed
    if (rawLength && rawKey.length !== rawLength) {
        throw permerror('is malformed', rr);
    }

    let publicKey: crypto.KeyObject;
    try {
        // the bare key (RFC 8463 section 4 for Ed25519), or for RSA an RSAPublicKey or the
        // SubjectPublicKeyInfo that is published in practice
        publicKey = rawLength
            ? rawPublicKey(keyType, rawKey)
            : crypto.createPublicKey({ key: rawKey, format: 'der', type: isBareRsaPublicKey(rawKey) ? 'pkcs1' : 'spki' });
    } catch {
        throw permerror('is malformed', rr);
    }

    if (publicKey.asymmetricKeyType !== nodeType) {
        throw permerror('is malformed', rr);
    }
    return publicKey;
};

/**
 * Fetches and parses the key record of a selector
 *
 * @param {String} name Key record name, "selector._domainkey.domain"
 * @param {Function} resolver DNS resolver
 * @returns {Object} { publicKey: KeyObject, keyType, modulusLength, rr }
 * @throws {KeyError}
 */
const fetchKey = async (name: string, resolver: DNSResolver): Promise<DKIM2Key> => {
    let records;
    try {
        records = await fetchRecords(name, resolver);
    } catch {
        throw new KeyError('temperror', 'could not be fetched');
    }

    // section 3.7: records that begin with a v= tag other than "DKIM1" are ignored, more than one
    // remaining record is an error
    records = (records || []).filter(rr => {
        let version = leadingVersion(rr);
        return version === null || version === 'DKIM1';
    });

    if (!records.length) {
        throw permerror('does not exist');
    }

    if (records.length > 1) {
        throw permerror('has multiple records');
    }

    let rr = records[0];

    let entry = parseTagList(rr, { strict: true });
    let tags = entry.parsed;
    if (entry.syntaxErrors.length) {
        throw permerror('has a syntax error', rr);
    }

    // v= is optional, but when present it is "DKIM1" and the first tag
    if (tags.v && (tags.v.value !== 'DKIM1' || entry.tags[0].name !== 'v')) {
        throw permerror('has a syntax error', rr);
    }

    if (!tags.p) {
        // p= is required
        throw permerror('has a syntax error', rr);
    }

    if (!tags.p.value) {
        // an empty p= means the key has been revoked
        throw permerror('has been revoked', rr);
    }

    if (!isBase64(tags.p.value)) {
        throw permerror('has a syntax error', rr);
    }

    // k= defaults to "rsa". Unknown key types are ignored, so they never match an algorithm. The
    // retired t= flags are ignored as well (section 14.5)
    let keyType = tags.k ? tags.k.value : 'rsa';
    if (!isSupportedKeyType(keyType)) {
        return { publicKey: null, keyType, rr };
    }

    let publicKey = createPublicKey(keyType, Buffer.from(tags.p.value, 'base64'), rr);

    let modulusLength: number | undefined;
    if (keyType === 'rsa') {
        modulusLength = publicKey.asymmetricKeyDetails!.modulusLength;
        let problem = rsaKeyProblem(publicKey);
        if (problem) {
            // section 14.5 says "too short" without the "is"
            throw permerror(problem === 'is too short' ? 'too short' : problem, rr);
        }
    }

    return { publicKey, keyType, modulusLength, rr };
};

/**
 * Creates a key lookup for one message, so that every signature naming the same key record
 * shares one DNS query
 *
 * @param {Function} [resolver] DNS resolver, defaults to dns.promises.resolve
 * @returns {Function} async (domain, selector, algorithm) => key info, throws KeyError
 */
const createKeyLookup = (resolver?: DNSResolver | undefined): KeyLookup => {
    resolver = resolver || dns.resolve;
    let cache = new Map<string, Promise<DKIM2Key>>();

    return async (domain, selector, algorithm) => {
        let name = `${selector}._domainkey.${domain}`;
        if (!cache.has(name)) {
            let lookup = fetchKey(name, resolver);
            lookup.catch(() => false);
            cache.set(name, lookup);
        }

        let key = await cache.get(name)!;
        if (key.keyType !== ALGORITHM_KEY_TYPES.get(algorithm)) {
            throw permerror('algorithm mismatch', key.rr);
        }
        return key;
    };
};

export { createKeyLookup, KeyError, ALGORITHM_KEY_TYPES, rsaKeyProblem, signatureData };
export type { DKIM2Key, KeyLookup };
