'use strict';

const {
    getSigningHeaderLines,
    formatSignatureHeaderLine,
    defaultDKIMFieldNames,
    defaultARCFieldNames,
    validateAlgorithm,
    getPrivateKey
} = require('../../lib/tools');
const { MessageParser } = require('./message-parser');
const { dkimBody } = require('./body');
const { generateCanonicalizedHeader } = require('./header');
const crypto = require('node:crypto');

class DkimSigner extends MessageParser {
    constructor(options) {
        super();

        let { canonicalization, algorithm, signTime, headerList, signatureData, arc, bodyHash, headers, getARChain, expires } = options || {};

        this.algorithm = algorithm || false;
        this.canonicalization = canonicalization || 'relaxed/relaxed';

        this.errors = [];

        this.expires = expires;
        this.signTime = signTime;

        this.headerList = headerList;

        this.signatureData = [].concat(signatureData || []).map(entry => {
            entry.type = 'DKIM';
            return entry;
        });

        this.signatureHeaders = [];

        this.arc = Object.assign({ chain: false }, arc);
        this.getARChain = getARChain;
        if (this.arc.signingDomain && this.arc.selector && this.arc.privateKey) {
            this.signatureData.push({
                type: 'ARC',
                signingDomain: this.arc.signingDomain, // d=
                selector: this.arc.selector, // s=
                privateKey: this.arc.privateKey,
                canonicalization: 'relaxed/relaxed',
                algorithm: 'rsa-sha256' // fixed for now, throws if non-rsa key is used
            });
        }

        this.bodyHashes = new Map();

        // precalculated hash and headers
        this.bodyHash = bodyHash || null;
        this.headers = headers;

        this.setupHashes();
    }

    getCanonicalization(signatureData) {
        let canonicalization = signatureData?.canonicalization || this.canonicalization;
        let headerCanon = canonicalization.split('/').shift().toLowerCase().trim();
        let bodyCanon = (canonicalization.split('/')[1] || 'simple').toLowerCase().trim();
        return { canonicalization, headerCanon, bodyCanon };
    }

    getAlgorithm(signatureData) {
        let algorithm = (signatureData?.algorithm || this.algorithm || '').toLowerCase().trim();
        let signAlgo = algorithm.split('-').shift().toLowerCase().trim() || false; // default is derived from key
        let hashAlgo = algorithm.split('-').pop().toLowerCase().trim() || 'sha256';

        return { algorithm, signAlgo, hashAlgo };
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

    async messageHeaders(headers) {
        this.headers = headers;

        if (this.getARChain) {
            try {
                this.arc.chain = this?.getARChain(headers);
                if (this.arc.chain?.length) {
                    this.arc.lastEntry = this.arc.chain[this.arc.chain.length - 1];
                    this.arc.instance = this.arc.instance ? this.arc.instance : this.arc.lastEntry.i + 1;
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

    async finalize() {
        for (let signatureData of this.signatureData || []) {
            if (!signatureData.privateKey) {
                continue;
            }

            let fieldNames = this.headerList && this.headerList.length ? this.headerList : false;
            if (!fieldNames) {
                switch (signatureData.type) {
                    case 'ARC':
                        fieldNames = defaultARCFieldNames;
                        break;

                    case 'DKIM':
                    default:
                        fieldNames = defaultDKIMFieldNames;
                        break;
                }
            }

            let signingHeaderLines = getSigningHeaderLines(this.headers.parsed, this.headerList);

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
            } catch (err) {
                this.errors.push({
                    selector: signatureData.selector,
                    signingDomain: signatureData.signingDomain,
                    err
                });
                continue;
            }

            try {
                // throws if invalid
                validateAlgorithm(algorithm);
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
                        instance: this.arc?.instance, // ARC only
                        algorithm,
                        canonicalization: this.getCanonicalization(signatureData).canonicalization,

                        signTime: this.signTime,
                        expires: this.expires,

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
