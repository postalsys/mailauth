'use strict';

const { getSigningHeaderLines, formatSignatureHeaderLine, defaultDKIMFieldNames, defaultARCFieldNames } = require('../../lib/tools');
const { MessageParser } = require('./message-parser');
const { dkimBody } = require('./body');
const { generateCanonicalizedHeader } = require('./header');
const crypto = require('crypto');

class DkimSigner extends MessageParser {
    constructor(options) {
        super();

        let { canonicalization, signTime, headerList, signatureData, arc } = options || {};

        this.canonicalization = canonicalization || 'relaxed/relaxed';
        this.headerCanon = this.canonicalization.split('/').shift().toLowerCase().trim();
        // if body canonicalization is not set, then defaults to 'simple'
        this.bodyCanon = (this.canonicalization.split('/')[1] || 'simple').toLowerCase().trim();

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
            this.arc.set = this.arc.set || {};
            this.signatureData.push({
                type: 'ARC',
                signingDomain: this.arc.signingDomain, // d=
                selector: this.arc.selector, // s=
                privateKey: this.arc.privateKey,
                algorithm: 'rsa-sha256', // fixed for now
                instance: this.arc.instance
            });
        }

        this.bodyHashes = new Map();
        this.setupHashes();
    }

    setupHashes() {
        for (let signatureData of this.signatureData) {
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

            let { canonicalizedHeader, dkimHeaderOpts } = generateCanonicalizedHeader(
                signatureData.type,
                signingHeaderLines,
                Object.assign({}, signatureData, {
                    instance: signatureData.instance, // ARC only
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
                        canonicalizedHeader,
                        signatureData.privateKey
                    )
                    .toString('base64');

                dkimHeaderOpts.b = signature;

                const signatureHeaderLine = formatSignatureHeaderLine(signatureData.type, dkimHeaderOpts, true);

                switch (signatureData.type) {
                    case 'ARC':
                        this.arc.set['arc-message-signature'] = signatureHeaderLine;
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
