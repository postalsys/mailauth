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
                this.signatureHeaders.push(
                    `X-MailAuth-Signing-Error: ${signatureData.signingDomain} (${err.message.replace(/\r?\n/g, ' ').replace(/\s+/g, ' ').trim()})`
                );
            }
        }
    }
}

module.exports = { DkimSigner };
