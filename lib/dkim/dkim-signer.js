'use strict';

const {
    getSigningHeaderLines,
    formatSignatureHeaderLine,
    defaultDKIMFieldNames,
    defaultARCFieldNames,
    validateAlgorithm,
    getPrivateKey,
    getCurTime,
    toALabel,
    isSameOrSubdomain,
    addWarning,
    createError,
    splitAlgorithm
} = require('../../lib/tools');
const { DOMAIN_NAME, SELECTOR, LOCAL_PART, MAX_ARC_INSTANCE, ARC_HEADER_KEYS } = require('./syntax');
const { MessageParser } = require('./message-parser');
const { dkimBody } = require('./body');
const { generateCanonicalizedHeader } = require('./header');
const crypto = require('node:crypto');

// Characters that can never be in a tag value (RFC 6376 section 3.2): the semicolon ends the
// tag, and whitespace, CR and LF would change the header itself. Anything that is not
// printable ASCII once converted to an A-label is not a DNS name either
const UNSAFE_TAG_VALUE = /[^\x21-\x3a\x3c-\x7e]/;
// t= and x= are 1*12DIGIT (RFC 6376 section 3.5)
const MAX_TIMESTAMP = 999999999999;

// RFC 8617 section 4.1.2: header fields an ARC-Message-Signature never covers
const ARC_EXCLUDED_FIELDS = [...ARC_HEADER_KEYS, 'authentication-results'];

// RFC 8301 section 3.2: signers MUST use RSA keys of at least 1024 bits
const MIN_RSA_KEY_SIZE = 1024;

// Turns a header list option (a colon separated string or an array of names) into the
// colon separated string getSigningHeaderLines expects, or false if there is none
const normalizeHeaderList = headerList => {
    if (Array.isArray(headerList)) {
        headerList = headerList
            .map(entry => (entry || '').toString().trim())
            .filter(entry => entry)
            .join(':');
    }
    return typeof headerList === 'string' && headerList.trim() ? headerList : false;
};

class DkimSigner extends MessageParser {
    constructor(options) {
        super();

        let { canonicalization, algorithm, signTime, headerList, signatureData, arc, bodyHash, headers, getARChain, getArcInstance, expires, strict } =
            options || {};

        this.algorithm = algorithm || false;
        this.canonicalization = canonicalization || 'relaxed/relaxed';

        // follow RFC 6376 and RFC 8301 exactly instead of the lenient defaults
        this.strict = !!strict;

        this.errors = [];
        // what was signed although the strict mode would have refused it, as short codes
        this.warnings = [];

        this.expires = expires;
        this.signTime = signTime;

        this.headerList = normalizeHeaderList(headerList);

        this.signatureData = [].concat(signatureData || []).map(entry => {
            entry.type = 'DKIM';
            return entry;
        });

        this.signatureHeaders = [];

        this.arc = Object.assign({ chain: false }, arc);
        this.getARChain = getARChain;
        // decides the instance of an ARC set that has none set, from the message headers
        this.getArcInstance = getArcInstance;
        if (this.arc.signingDomain && this.arc.selector && this.arc.privateKey) {
            this.signatureData.push({
                type: 'ARC',
                signingDomain: this.arc.signingDomain, // d=
                selector: this.arc.selector, // s=
                privateKey: this.arc.privateKey,
                canonicalization: 'relaxed/relaxed',
                // rsa-sha256 or ed25519-sha256, follows the key type when not set
                algorithm: this.arc.algorithm || false
            });
        }

        this.bodyHashes = new Map();

        // precalculated hash and headers
        this.bodyHash = bodyHash || null;
        this.headers = headers;

        this.setupHashes();
    }

    warn(warning) {
        addWarning(this.warnings, warning);
    }

    // A rule the strict mode enforces: throws in the strict mode, notes the warning otherwise
    violation(message, code, warning) {
        if (this.strict) {
            throw createError(message, code);
        }
        this.warn(warning);
    }

    getCanonicalization(signatureData) {
        let canonicalization = signatureData?.canonicalization || this.canonicalization;
        let headerCanon = canonicalization.split('/').shift().toLowerCase().trim();
        let bodyCanon = (canonicalization.split('/')[1] || 'simple').toLowerCase().trim();
        return { canonicalization, headerCanon, bodyCanon };
    }

    getAlgorithm(signatureData) {
        // the shared algorithm option is for DKIM signatures, an ARC-Message-Signature has its own
        let algorithm = (signatureData?.algorithm || (signatureData?.type === 'ARC' ? '' : this.algorithm) || '').toLowerCase().trim();
        let { signAlgo, hashAlgo } = splitAlgorithm(algorithm);

        // the signing algorithm defaults to the key type
        return { algorithm, signAlgo: signAlgo || false, hashAlgo: hashAlgo || 'sha256' };
    }

    setupHashes() {
        for (let signatureData of this.signatureData) {
            if (!signatureData.privateKey) {
                continue;
            }

            signatureData.maxBodyLength =
                typeof signatureData.maxBodyLength === 'number' && signatureData.maxBodyLength >= 0 ? signatureData.maxBodyLength : '';

            let { hashAlgo } = this.getAlgorithm(signatureData);
            let { bodyCanon } = this.getCanonicalization(signatureData);

            let hashKey = `${bodyCanon}:${hashAlgo}:${signatureData.maxBodyLength}`;

            if (!this.bodyHashes.has(hashKey)) {
                this.bodyHashes.set(hashKey, {
                    bodyCanon,
                    hashAlgo,
                    hasher: null,
                    hash: this.bodyHash
                });
            }
        }
    }

    validateCanonicalization(canonicalization) {
        try {
            let [header, body] = canonicalization.split('/');

            if (!['relaxed', 'simple'].includes(header)) {
                let error = new Error('Unknown header canonicalization');
                error.canonicalization = header;
                throw error;
            }

            if (!['relaxed', 'simple'].includes(body)) {
                let error = new Error('Unknown body canonicalization');
                error.canonicalization = body;
                throw error;
            }
        } catch (err) {
            err.code = 'EINVALIDCANON';
            throw err;
        }
    }

    // Validates the d= and s= values (RFC 6376 section 3.5) and returns them as A-labels.
    // A value that would break out of its tag or out of the header is refused in every mode
    validateSigningIdentifiers(signatureData) {
        let checks = [
            ['signingDomain', 'd=', DOMAIN_NAME, 'EINVALIDDOMAIN'],
            ['selector', 's=', SELECTOR, 'EINVALIDSELECTOR']
        ];

        for (let [key, tag, format, code] of checks) {
            let value = typeof signatureData[key] === 'string' ? signatureData[key].trim() : '';
            let aLabel = toALabel(value);

            if (!value || UNSAFE_TAG_VALUE.test(aLabel)) {
                let err = new Error(value ? `Invalid ${tag} value ${JSON.stringify(signatureData[key])}` : `Missing ${tag} value`);
                err.code = code;
                throw err;
            }

            if (!format.test(aLabel)) {
                this.violation(`Invalid ${tag} value ${JSON.stringify(signatureData[key])}`, code, key === 'signingDomain' ? 'd-syntax' : 's-syntax');
            }
        }
    }

    // The i= value of a DKIM-Signature, from the `identity` option (RFC 6376 section 3.5)
    getIdentity(signatureData) {
        if (signatureData.type !== 'DKIM' || !signatureData.identity) {
            return false;
        }

        let identity = signatureData.identity.toString().trim();
        let atPos = identity.lastIndexOf('@');
        let domain = atPos >= 0 ? toALabel(identity.substring(atPos + 1)) : '';

        if (atPos < 0 || !domain || /[\s;\x00-\x1f\x7f]/.test(identity)) {
            let err = new Error(`Invalid identity ${JSON.stringify(signatureData.identity)}`);
            err.code = 'EINVALIDIDENTITY';
            throw err;
        }

        let localPart = identity.substring(0, atPos);
        if ((localPart && !LOCAL_PART.test(localPart)) || !DOMAIN_NAME.test(domain)) {
            // sig-i-tag = [ Local-part ] "@" domain-name
            this.violation(`Invalid identity ${JSON.stringify(signatureData.identity)}`, 'EINVALIDIDENTITY', 'identity-syntax');
        }

        if (!isSameOrSubdomain(domain, signatureData.signingDomain)) {
            // "The domain part of the address MUST be the same as, or a subdomain of, the value
            // of the d= tag", or every verifier ignores the signature
            this.violation(`Identity domain is not the same as or a subdomain of ${signatureData.signingDomain}`, 'EINVALIDIDENTITY', 'identity-domain');
        }

        return identity;
    }

    // The t= and x= values in seconds (RFC 6376 section 3.5), false for a tag that is left out
    getTimestamps() {
        let timestamp = Math.floor(getCurTime(this.signTime).getTime() / 1000);
        let expiration = this.expires ? Math.floor(getCurTime(this.expires).getTime() / 1000) : false;

        let validTimestamp = value => Number.isInteger(value) && value >= 0 && value <= MAX_TIMESTAMP;

        if (!validTimestamp(timestamp)) {
            // 1*12DIGIT can not hold a time before 1970 or after the year 33658
            this.violation('Signing time can not be represented in a t= tag', 'EINVALIDTIME', 'invalid-signtime');
            timestamp = false;
        }

        if (expiration !== false && !validTimestamp(expiration)) {
            this.violation('Expiration time can not be represented in an x= tag', 'EINVALIDTIME', 'invalid-expiration');
            expiration = false;
        }

        if (expiration !== false && timestamp !== false && expiration <= timestamp) {
            // "The value of the x= tag MUST be greater than the value of the t= tag"
            this.violation('Expiration time must be later than the signing time', 'EINVALIDTIME', 'invalid-expiration');
        }

        return { timestamp, expiration };
    }

    async messageHeaders(headers) {
        this.headers = headers;

        if (this.getARChain) {
            try {
                this.arc.chain = this.getARChain(headers);
                if (this.arc.chain?.length) {
                    this.arc.lastEntry = this.arc.chain[this.arc.chain.length - 1];
                }
            } catch (err) {
                this.arc.error = err;
            }
        }

        for (let hashKey of this.bodyHashes.keys()) {
            let [bodyCanon, hashAlgo, maxBodyLength] = hashKey.split(':');
            this.bodyHashes.get(hashKey).hasher = dkimBody(bodyCanon, hashAlgo, maxBodyLength ? Number(maxBodyLength) : false);
        }
    }

    async nextChunk(chunk) {
        for (let hashKey of this.bodyHashes.keys()) {
            if (this.bodyHashes.get(hashKey).hasher) {
                this.bodyHashes.get(hashKey).hasher.update(chunk);
            }
        }
    }

    async finalChunk() {
        if (!this.headers) {
            return;
        }

        for (let hashKey of this.bodyHashes.keys()) {
            if (this.bodyHashes.get(hashKey).hasher) {
                this.bodyHashes.get(hashKey).hash = this.bodyHashes.get(hashKey).hasher.digest('base64');
            }
        }

        return this.finalize();
    }

    // The header fields to sign for a signature: its own headerList, the shared one, or the
    // default list of its type. An ARC-Message-Signature never covers ARC header fields or
    // Authentication-Results (RFC 8617 section 4.1.2)
    getFieldNames(signatureData) {
        let fieldNames =
            normalizeHeaderList(signatureData.headerList) || this.headerList || (signatureData.type === 'ARC' ? defaultARCFieldNames : defaultDKIMFieldNames);

        if (signatureData.type === 'ARC') {
            fieldNames = fieldNames
                .split(':')
                .filter(name => !ARC_EXCLUDED_FIELDS.includes(name.trim().toLowerCase()))
                .join(':');
        }

        return fieldNames;
    }

    async finalize() {
        for (let signatureData of this.signatureData || []) {
            if (!signatureData.privateKey) {
                continue;
            }

            const pushError = (err, extra) => {
                this.errors.push(
                    Object.assign(
                        {
                            type: signatureData.type,
                            selector: signatureData.selector,
                            signingDomain: signatureData.signingDomain
                        },
                        extra || {},
                        { err }
                    )
                );
            };

            let signingHeaderLines = getSigningHeaderLines(this.headers.parsed, this.getFieldNames(signatureData));

            if (!signingHeaderLines.headers.some(header => header.key === 'from')) {
                // RFC 6376 section 5.4: the From header field MUST be signed, and section
                // 6.1.1 makes a signature that does not cover it a PERMFAIL for every
                // verifier. Without this an input with no header at all is signed with an
                // empty h= tag, which is not even valid sig-h-tag syntax
                let err = new Error('Can not sign a message that has no From header');
                err.code = 'ENOFROM';
                pushError(err);
                continue;
            }

            let identity, timestamps, instance;
            try {
                // throws on a value that is not safe to put into the header
                this.validateSigningIdentifiers(signatureData);
                identity = this.getIdentity(signatureData);
                timestamps = this.getTimestamps();

                if (signatureData.type === 'ARC') {
                    // createSeal decides where a set without an explicit instance goes
                    instance = this.arc.instance || (this.getArcInstance ? this.getArcInstance(this.headers) : 1);
                    if (!Number.isInteger(instance) || instance < 1 || instance > MAX_ARC_INSTANCE) {
                        // RFC 8617 section 4.2.1, an ARC chain holds at most 50 sets
                        let err = new Error(`ARC instance ${instance} is out of range (1-${MAX_ARC_INSTANCE})`);
                        err.code = 'EINVALIDINSTANCE';
                        throw err;
                    }
                }
            } catch (err) {
                pushError(err);
                continue;
            }

            let { algorithm, signAlgo, hashAlgo } = this.getAlgorithm(signatureData);
            let { canonicalization, bodyCanon } = this.getCanonicalization(signatureData);

            try {
                // throws if invalid
                this.validateCanonicalization(canonicalization);
            } catch (err) {
                this.errors.push({
                    algorithm,
                    canonicalization,
                    selector: signatureData.selector,
                    signingDomain: signatureData.signingDomain,
                    err
                });
                continue;
            }

            let privateKeyObj;

            try {
                privateKeyObj = getPrivateKey(signatureData.privateKey);
            } catch (err) {
                this.errors.push({
                    selector: signatureData.selector,
                    signingDomain: signatureData.signingDomain,
                    err
                });
                continue;
            }

            let hashKey = `${bodyCanon}:${hashAlgo}:${signatureData.maxBodyLength}`;

            try {
                let keyType = privateKeyObj.asymmetricKeyType;
                if (signAlgo && keyType !== signAlgo) {
                    // invalid key type
                    let err = new Error(`Invalid key type: "${keyType}" (expecting "${signAlgo}")`);
                    err.code = 'EINVALIDTYPE';
                    throw err;
                }

                if (!['rsa', 'ed25519'].includes(keyType)) {
                    let err = new Error(`Unsupported key type: "${keyType}"`);
                    err.code = 'EINVALIDTYPE';
                    throw err;
                }

                if (!signAlgo) {
                    signAlgo = keyType;
                }

                algorithm = `${signAlgo}-${hashAlgo}`;

                if (keyType === 'rsa' && privateKeyObj.asymmetricKeyDetails?.modulusLength < MIN_RSA_KEY_SIZE) {
                    // RFC 8301 section 3.2, verifiers MUST NOT accept such a signature
                    this.violation(
                        `RSA key too short (${privateKeyObj.asymmetricKeyDetails.modulusLength} bits, at least ${MIN_RSA_KEY_SIZE} required)`,
                        'ESHORTKEY',
                        'weak-key'
                    );
                }
            } catch (err) {
                this.errors.push({
                    selector: signatureData.selector,
                    signingDomain: signatureData.signingDomain,
                    err
                });
                continue;
            }

            try {
                if (this.strict && hashAlgo === 'sha1') {
                    // RFC 8301 section 3.1, "rsa-sha1 MUST NOT be used for signing"
                    let err = new Error('rsa-sha1 is not allowed for signing');
                    err.code = 'EINVALIDALGO';
                    throw err;
                }

                // throws if invalid, also for ed25519-sha1, which is not an algorithm. ARC
                // signatures are never made with sha1, no ARC validator accepts them
                validateAlgorithm(algorithm, signatureData.type === 'ARC');

                if (hashAlgo === 'sha1') {
                    this.warn('rsa-sha1');
                }
            } catch (err) {
                this.errors.push({
                    algorithm,
                    canonicalization,
                    selector: signatureData.selector,
                    signingDomain: signatureData.signingDomain,
                    err
                });
                continue;
            }

            let { canonicalizedHeader, dkimHeaderOpts } = generateCanonicalizedHeader(
                signatureData.type,
                signingHeaderLines,
                Object.assign(
                    {},
                    signatureData,
                    {
                        instance: signatureData.type === 'ARC' ? instance : false, // ARC only
                        identity, // DKIM only
                        algorithm,
                        canonicalization: this.getCanonicalization(signatureData).canonicalization,

                        signTime: this.signTime,
                        expires: this.expires,
                        timestamp: timestamps.timestamp,
                        expiration: timestamps.expiration,

                        bodyHash: this.bodyHashes.has(hashKey) ? this.bodyHashes.get(hashKey).hash : null
                    },

                    // value for the l= tag (if needed)
                    typeof signatureData.maxBodyLength === 'number'
                        ? {
                              bodyHashedBytes: this.bodyHashes.get(hashKey).hasher.bodyHashedBytes,
                              canonicalizedLength: this.bodyHashes.get(hashKey).hasher.canonicalizedLength,
                              sourceBodyLength: this.bodyHashes.get(hashKey).hasher.byteLength
                          }
                        : {}
                )
            );

            try {
                let signature = crypto
                    .sign(
                        // use `null` as algorithm to detect it from the key file
                        signAlgo === 'rsa' ? algorithm : null,
                        signAlgo === 'rsa' ? canonicalizedHeader : crypto.createHash('sha256').update(canonicalizedHeader).digest(),
                        privateKeyObj
                    )
                    .toString('base64');

                dkimHeaderOpts.b = signature;

                const signatureHeaderLine = formatSignatureHeaderLine(signatureData.type, dkimHeaderOpts, true);

                switch (signatureData.type) {
                    case 'ARC':
                        this.arc.messageSignature = signatureHeaderLine;
                        break;

                    case 'DKIM':
                    default:
                        this.signatureHeaders.push(signatureHeaderLine);
                        break;
                }
            } catch (err) {
                this.errors.push({
                    type: signatureData.type,
                    algorithm,
                    selector: signatureData.selector,
                    signingDomain: signatureData.signingDomain,
                    err
                });
            }
        }
    }
}

module.exports = { DkimSigner };
