'use strict';

const { getSigningHeaderLines, formatSignatureHeaderLine, defaultDKIMFieldNames, defaultARCFieldNames } = require('../../lib/tools');
const { MessageParser } = require('./message-parser');
const { dkimBody } = require('./body');
const { generateCanonicalizedHeader } = require('./header');
const crypto = require('crypto');

class DkimSigner extends MessageParser {
    constructor(options) {
        super();

        let { canonicalization, algorithm, signTime, headerList, signatureData, arc, bodyHash, headers } = options || {};

        this.algorithm = algorithm || false;
        this.canonicalization = canonicalization || 'relaxed/relaxed';

        this.errors = [];

        this.signTime = signTime;
        this.headerList = headerList;

        this.signatureData = [].concat(signatureData || []).map(entry => {
            entry.type = 'DKIM';
            return entry;
        });

        this.signatureHeaders = [];

        this.arc = Object.assign({}, arc);
        if (this.arc && this.arc.instance && this.arc.signingDomain && this.arc.selector && this.arc.privateKey) {
            this.signatureData.push({
                type: 'ARC',
                signingDomain: this.arc.signingDomain, // d=
                selector: this.arc.selector, // s=
                privateKey: this.arc.privateKey,
                canonicalization: 'relaxed/relaxed',
                algorithm: 'rsa-sha256', // fixed for now, throws if non-rsa key is used
                instance: this.arc.instance
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

            let { hashAlgo } = this.getAlgorithm(signatureData);
            let { bodyCanon } = this.getCanonicalization(signatureData);

            let hashKey = `${bodyCanon}:${hashAlgo}`;

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

    validateAlgorithm(algorithm) {
        try {
            if (!algorithm || !/^[^-]+-[^-]+$/.test(algorithm)) {
                throw new Error('Invalid algorithm format');
            }

            let [signAlgo, hashAlgo] = algorithm.split('-');

            if (!['rsa', 'ed25519'].includes(signAlgo)) {
                throw new Error('Unknown signing algorithm: ' + signAlgo);
            }

            if (!['sha256', 'sha1'].includes(hashAlgo)) {
                throw new Error('Unknown hashing algorithm: ' + hashAlgo);
            }
        } catch (err) {
            err.code = 'EINVALIDALGO';
            throw err;
        }
    }

    async messageHeaders(headers) {
        this.headers = headers;

        for (let hashKey of this.bodyHashes.keys()) {
            let [bodyCanon, hashAlgo] = hashKey.split(':');
            this.bodyHashes.get(hashKey).hasher = dkimBody(bodyCanon, hashAlgo);
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
            let { bodyCanon } = this.getCanonicalization(signatureData);

            let hashKey = `${bodyCanon}:${hashAlgo}`;

            try {
                let keyType = crypto.createPrivateKey({ key: signatureData.privateKey, format: 'pem' }).asymmetricKeyType;
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
                this.validateAlgorithm(algorithm);
            } catch (err) {
                this.errors.push({
                    algorithm,
                    selector: signatureData.selector,
                    signingDomain: signatureData.signingDomain,
                    err
                });
                continue;
            }

            let { canonicalizedHeader, dkimHeaderOpts } = generateCanonicalizedHeader(
                signatureData.type,
                signingHeaderLines,
                Object.assign({}, signatureData, {
                    instance: signatureData.instance, // ARC only
                    algorithm,
                    canonicalization: this.getCanonicalization(signatureData).canonicalization,
                    signTime: this.signTime,
                    bodyHash: this.bodyHashes.has(hashKey) ? this.bodyHashes.get(hashKey).hash : null
                })
            );

            try {
                let signature = crypto
                    .sign(
                        // use `null` as algorithm to detect it from the key file
                        signAlgo === 'rsa' ? algorithm : null,
                        canonicalizedHeader,
                        signatureData.privateKey
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
