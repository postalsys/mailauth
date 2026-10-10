'use strict';

// DKIM2 public key lookup (draft-ietf-dkim-dkim2-dns-00 section 3.4 and
// draft-ietf-dkim-dkim2-spec-06 section 11.5). The records are DKIM1 key records, read with
// the DKIM2 rules: one TXT record per selector, the retired h=, n= and s= tags ignored, and
// only the rsa and ed25519 key types.

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const { parseTagList, toALabel, isValidDnsName, isBareRsaPublicKey } = require('../tools');
const { isBase64 } = require('./fields');

const MIN_RSA_KEY_SIZE = 1024;
// section 3.2: "The signing algorithm MUST use a public exponent of 65537"
const RSA_EXPONENT = 65537n;

// DNS answers that mean there is no record. Anything else could be transient
const NO_RECORD_CODES = new Set(['ENOTFOUND', 'ENODATA']);

// the key type of each signing algorithm (section 8.9: the k= value has to match the algorithm)
const ALGORITHM_KEY_TYPES = new Map([
    ['rsa-sha256', 'rsa'],
    ['ed25519-sha256', 'ed25519']
]);

// Section 3.2: why an RSA key can not be used, or null when it can
const rsaKeyProblem = keyObject => {
    let details = keyObject.asymmetricKeyDetails;
    if (details.modulusLength < MIN_RSA_KEY_SIZE) {
        return 'is too short';
    }
    if (details.publicExponent !== RSA_EXPONENT) {
        return 'has an unsupported exponent';
    }
    return null;
};

// Sections 3.2 and 3.3: the hash name and the data for crypto.sign() and crypto.verify(). RSA
// PKCS#1 v1.5 hashes the input itself, Ed25519 (PureEdDSA) signs the SHA-256 hash of it
const signatureData = (algorithm, input) => (algorithm === 'ed25519-sha256' ? [null, crypto.createHash('sha256').update(input).digest()] : ['sha256', input]);

// RFC 8410 SubjectPublicKeyInfo prefix for a raw 32 byte Ed25519 key
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

class KeyError extends Error {
    /**
     * @param {String} result "permerror" or "temperror"
     * @param {String} message The end of the section 11.5 error string, after "public key <selector>"
     * @param {String} [rr] The key record
     */
    constructor(result, message, rr) {
        super(message);
        this.result = result;
        if (rr) {
            this.rr = rr;
        }
    }
}

const permerror = (reason, rr) => new KeyError('permerror', reason, rr);

/**
 * Fetches and parses the key record of a selector
 *
 * @param {String} name Key record name, "selector._domainkey.domain"
 * @param {Function} resolver DNS resolver
 * @returns {Object} { publicKey: KeyObject, keyType, modulusLength, testing, rr }
 * @throws {KeyError}
 */
const fetchKey = async (name, resolver) => {
    let lookupName = toALabel(name);
    if (!isValidDnsName(lookupName)) {
        throw permerror('does not exist');
    }

    let list;
    try {
        list = await resolver(lookupName, 'TXT');
    } catch (err) {
        // section 11.5: a timeout is a TEMPERROR, an absent key a PERMERROR
        if (NO_RECORD_CODES.has(err.code)) {
            throw permerror('does not exist');
        }
        throw new KeyError('temperror', 'could not be fetched');
    }

    if (!Array.isArray(list) || !list.length) {
        throw permerror('does not exist');
    }

    if (list.length > 1) {
        // draft-ietf-dkim-dkim2-dns-00 section 3.4.2.2, an error per section 11.5
        throw permerror('has multiple records');
    }

    // the strings of a TXT record are joined with no whitespace between them
    let rr = [].concat(list[0]).join('');

    let entry = parseTagList(rr, { strict: true });
    let tags = entry.parsed;
    if (entry.syntaxErrors.length) {
        throw permerror('has a syntax error', rr);
    }

    // v= is optional, but when present it is "DKIM1" and the first tag. A record with any other
    // version is discarded
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

    // k= defaults to "rsa". Unknown key types are ignored, so they never match an algorithm
    let keyType = tags.k ? tags.k.value : 'rsa';
    if (!['rsa', 'ed25519'].includes(keyType)) {
        return { publicKey: null, keyType, rr };
    }

    let rawKey = Buffer.from(tags.p.value, 'base64');
    let publicKey;
    try {
        if (keyType === 'ed25519') {
            // RFC 8463 section 4: the bare 32 byte key
            if (rawKey.length !== 32) {
                throw new Error('Invalid Ed25519 key length');
            }
            publicKey = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawKey]), format: 'der', type: 'spki' });
        } else {
            // an RSAPublicKey, or the SubjectPublicKeyInfo that is published in practice
            publicKey = crypto.createPublicKey({ key: rawKey, format: 'der', type: isBareRsaPublicKey(rawKey) ? 'pkcs1' : 'spki' });
        }
    } catch (err) {
        throw permerror('has a syntax error', rr);
    }

    if (publicKey.asymmetricKeyType !== keyType) {
        throw permerror('has a syntax error', rr);
    }

    let modulusLength;
    if (keyType === 'rsa') {
        modulusLength = publicKey.asymmetricKeyDetails.modulusLength;
        let problem = rsaKeyProblem(publicKey);
        if (problem) {
            throw permerror(problem, rr);
        }
    }

    // t= flags. Only "y" means anything to DKIM2, "s" is about the DKIM1 i= tag
    let flags = String(tags.t?.value || '')
        .split(':')
        .map(flag => flag.trim());

    return { publicKey, keyType, modulusLength, testing: flags.includes('y'), rr };
};

/**
 * Creates a key lookup for one message, so that every signature naming the same key record
 * shares one DNS query
 *
 * @param {Function} [resolver] DNS resolver, defaults to dns.promises.resolve
 * @returns {Function} async (domain, selector, algorithm) => key info, throws KeyError
 */
const createKeyLookup = resolver => {
    resolver = resolver || dns.resolve;
    let cache = new Map();

    return async (domain, selector, algorithm) => {
        let name = `${selector}._domainkey.${domain}`;
        if (!cache.has(name)) {
            let lookup = fetchKey(name, resolver);
            lookup.catch(() => false);
            cache.set(name, lookup);
        }

        let key = await cache.get(name);
        if (key.keyType !== ALGORITHM_KEY_TYPES.get(algorithm)) {
            throw permerror('algorithm mismatch', key.rr);
        }
        return key;
    };
};

module.exports = { createKeyLookup, KeyError, ALGORITHM_KEY_TYPES, rsaKeyProblem, signatureData };
