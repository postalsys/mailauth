'use strict';

const { getSignedHeaderLines, formatDKIMHeaderLine } = require('../../lib/tools');
const { MessageParser } = require('./message-parser');
const { dkimBody } = require('./body');
const { dkimHeader } = require('./header');
const crypto = require('crypto');

class DkimSigner extends MessageParser {
    constructor(options) {
        super();

        let { canonicalization, signTime, headerList, signatureData } = options || {};

        this.canonicalization = canonicalization || 'relaxed/relaxed';
        this.headerCanon = this.canonicalization.split('/').shift().toLowerCase().trim();
        // if body canonicalization is not set, then defaults to 'simple'
        this.bodyCanon = (this.canonicalization.split('/')[1] || 'simple').toLowerCase().trim();

        this.errors = [];

        this.signTime = signTime;
        this.headerList = headerList;

        this.signatureData = signatureData;
        this.signatureHeaders = [];

        this.bodyHashes = new Map();
        this.setupHashes();
    }

    setupHashes() {
        for (let signatureData of this.signatureData || []) {
            if (!signatureData.privateKey) {
                continue;
            }

            let algorithm = (signatureData.algorithm || '').toLowerCase().trim();
            let hashAlgo = algorithm.split('-').pop().toLowerCase().trim() || 'sha256';

            if (!this.bodyHashes.has(hashAlgo)) {
                this.bodyHashes.set(hashAlgo, { hasher: null, hash: null });
            }
        }
    }

    validateAlgorithm(algorithm) {
        try {
            if (!algorithm || !/^[^-]+-[^-]+$/.test(algorithm)) {
                throw new Error('Invalid algorithm format');
            }

            let [signing, hashing] = algorithm.split('-');

            if (!['rsa', 'ed25519'].includes(signing)) {
                throw new Error('Unknown signing algorithm: ' + signing);
            }

            if (!['sha256', 'sha1'].includes(hashing)) {
                throw new Error('Unknown hashing algorithm: ' + hashing);
            }
        } catch (err) {
            err.code = 'EINVALIDALGO';
            throw err;
        }
    }

    async messageHeaders(headers) {
        this.headers = headers;

        for (let hashAlgo of this.bodyHashes.keys()) {
            this.bodyHashes.get(hashAlgo).hasher = dkimBody(this.bodyCanon, hashAlgo);
        }
    }

    async nextChunk(chunk) {
        for (let hashAlgo of this.bodyHashes.keys()) {
            if (this.bodyHashes.get(hashAlgo).hasher) {
                this.bodyHashes.get(hashAlgo).hasher.update(chunk);
            }
        }
    }

    async finalChunk() {
        if (!this.headers) {
            return;
        }

        for (let hashAlgo of this.bodyHashes.keys()) {
            if (this.bodyHashes.get(hashAlgo).hasher) {
                this.bodyHashes.get(hashAlgo).hash = this.bodyHashes.get(hashAlgo).hasher.digest('base64');
            }
        }

        let signedHeaderLines = getSignedHeaderLines(this.headers.parsed, this.headerList);

        for (let signatureData of this.signatureData || []) {
            if (!signatureData.privateKey) {
                continue;
            }

            let algorithm = (signatureData.algorithm || '').toLowerCase().trim();
            let signAlgo = algorithm.split('-').shift().toLowerCase().trim() || null;
            let hashAlgo = algorithm.split('-').pop().toLowerCase().trim() || 'sha256';

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

            let { signingHeaders, dkimHeaderOpts } = dkimHeader(
                signedHeaderLines,
                Object.assign({}, signatureData, {
                    algorithm,
                    canonicalization: this.canonicalization,
                    signTime: this.signTime,
                    bodyHash: this.bodyHashes.has(hashAlgo) ? this.bodyHashes.get(hashAlgo).hash : null
                })
            );

            try {
                let signature = crypto
                    .sign(
                        // use `null` as algorithm to detect it from the key file
                        signAlgo === 'rsa' ? algorithm : null,
                        signingHeaders,
                        signatureData.privateKey
                    )
                    .toString('base64');

                dkimHeaderOpts.b = signature;
                this.signatureHeaders.push(formatDKIMHeaderLine(dkimHeaderOpts, true));
            } catch (err) {
                this.errors.push({
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
