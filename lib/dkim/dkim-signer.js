'use strict';

const { getSignedHeaderLines, formatDKIMHeaderLine } = require('../../lib/tools');
const { MessageParser } = require('./message-parser');
const { dkimBody } = require('./body');
const { dkimHeader } = require('./header');
const crypto = require('crypto');

class DkimSigner extends MessageParser {
    constructor(options) {
        super();

        let { algorithm, canonicalization, signTime, headerList, signatureData } = options || {};

        this.algorithm = algorithm || 'rsa-sha256';
        this.signAlgo = this.algorithm.split('-').shift().toLowerCase().trim();
        this.hashAlgo = this.algorithm.split('-').pop().toLowerCase().trim();

        this.canonicalization = canonicalization || 'relaxed/relaxed';
        this.headerCanon = this.canonicalization.split('/').shift().toLowerCase().trim();
        // if body canonicalization is not set, then defaults to 'simple'
        this.bodyCanon = (this.canonicalization.split('/')[1] || 'simple').toLowerCase().trim();

        this.errors = [];

        this.signTime = signTime;
        this.headerList = headerList;

        this.signatureData = signatureData;
        this.signatureHeaders = [];

        this.bodyHash = false;
    }

    async messageHeaders(headers) {
        this.headers = headers;
        this.bodyHash = dkimBody(this.bodyCanon, this.hashAlgo);
    }

    async nextChunk(chunk) {
        this.bodyHash.update(chunk);
    }

    async finalChunk() {
        if (!this.headers || !this.bodyHash) {
            return;
        }

        this.bodyHash = this.bodyHash.digest('base64');

        let signedHeaderLines = getSignedHeaderLines(this.headers.parsed, this.headerList);

        for (let signatureData of this.signatureData || []) {
            if (!signatureData.privateKey) {
                continue;
            }

            let { signingHeaders, dkimHeaderOpts } = dkimHeader(
                signedHeaderLines,
                Object.assign(
                    {
                        algorithm: this.algorithm,
                        canonicalization: this.canonicalization,
                        signTime: this.signTime,
                        bodyHash: this.bodyHash
                    },
                    signatureData
                )
            );

            try {
                let keyType = crypto.createPrivateKey({ key: signatureData.privateKey, format: 'pem' }).asymmetricKeyType;
                if (keyType !== this.signAlgo) {
                    // invalid key type
                    let err = new Error(`Invalid key type: ${keyType} (expecting ${this.signAlgo})`);
                    err.code = 'EKEY';
                    throw err;
                }
            } catch (err) {
                this.errors.push({
                    a: dkimHeaderOpts.a,
                    c: dkimHeaderOpts.c,
                    s: dkimHeaderOpts.s,
                    d: dkimHeaderOpts.d,
                    err
                });
                continue;
            }

            try {
                let signature = crypto
                    .sign(
                        // use `null` as algorithm to detect it from the key file
                        this.signAlgo === 'rsa' ? this.algorithm : null,
                        signingHeaders,
                        signatureData.privateKey
                    )
                    .toString('base64');

                dkimHeaderOpts.b = signature;
                this.signatureHeaders.push(formatDKIMHeaderLine(dkimHeaderOpts, true));
            } catch (err) {
                this.errors.push({
                    a: dkimHeaderOpts.a,
                    c: dkimHeaderOpts.c,
                    s: dkimHeaderOpts.s,
                    d: dkimHeaderOpts.d,
                    err
                });
            }
        }
    }
}

module.exports = { DkimSigner };
