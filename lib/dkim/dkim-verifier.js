'use strict';

const { getSignedHeaderLines, getPublicKey, parseDkimHeader } = require('../../lib/tools');
const { MessageParser } = require('./message-parser');
const { dkimBody } = require('./body');
const { dkimHeader } = require('./header');
const addressparser = require('nodemailer/lib/addressparser');
const crypto = require('crypto');

class DkimVerifier extends MessageParser {
    constructor(options) {
        super();

        this.options = options || {};
        this.resolver = this.options.resolver;

        this.results = [];

        this.signatureHeaders = [];
        this.bodyHashes = new Map();

        this.headerFrom = false;
        this.envelopeFrom = false;
    }

    async messageHeaders(headers) {
        this.headers = headers;
        this.signatureHeaders = headers.parsed.filter(h => h.key === 'dkim-signature').map(h => parseDkimHeader(h.line));

        let fromHeader = headers.parsed.find(h => h.key === 'from');
        if (fromHeader) {
            fromHeader = fromHeader.line.toString();
            let splitterPos = fromHeader.indexOf(':');
            if (splitterPos >= 0) {
                fromHeader = fromHeader.substr(splitterPos + 1);
            }
            let from = addressparser(fromHeader.trim());
            this.headerFrom = from.length && from[0].address ? from[0].address : false;
        }

        if (this.options.returnPath) {
            let returnPath = addressparser(this.options.returnPath);
            this.envelopeFrom = returnPath.length && returnPath[0].address ? returnPath[0].address : false;
        } else {
            let returnPathHeader = headers.parsed.filter(h => h.key === 'return-path').pop();
            if (returnPathHeader) {
                returnPathHeader = returnPathHeader.line.toString();
                let splitterPos = returnPathHeader.indexOf(':');
                if (splitterPos >= 0) {
                    returnPathHeader = returnPathHeader.substr(splitterPos + 1);
                }
                let returnPath = addressparser(returnPathHeader.trim());
                this.envelopeFrom = returnPath.length && returnPath[0].address ? returnPath[0].address : false;
            }
        }

        for (let signatureHeader of this.signatureHeaders) {
            signatureHeader.algorithm = signatureHeader.parsed.a || '';
            signatureHeader.signAlgo = signatureHeader.algorithm.split('-').shift().toLowerCase().trim();
            signatureHeader.hashAlgo = signatureHeader.algorithm.split('-').pop().toLowerCase().trim();

            signatureHeader.canonicalization = signatureHeader.parsed.c || '';
            signatureHeader.headerCanon = signatureHeader.canonicalization.split('/').shift().toLowerCase().trim();
            // if body canonicalization is not set, then defaults to 'simple'
            signatureHeader.bodyCanon = (signatureHeader.canonicalization.split('/')[1] || 'simple').toLowerCase().trim();

            signatureHeader.signingDomain = signatureHeader.parsed.d || '';
            signatureHeader.selector = signatureHeader.parsed.s || '';

            if (
                !['rsa', 'ed25519'].includes(signatureHeader.signAlgo) ||
                !['sha256', 'sha1'].includes(signatureHeader.hashAlgo) ||
                !['relaxed', 'simple'].includes(signatureHeader.headerCanon) ||
                !['relaxed', 'simple'].includes(signatureHeader.bodyCanon) ||
                !signatureHeader.signingDomain ||
                !signatureHeader.selector
            ) {
                signatureHeader.skip = true;
                continue;
            }

            signatureHeader.bodyHashKey = [signatureHeader.bodyCanon, signatureHeader.hashAlgo].join(':');
            if (!this.bodyHashes.has(signatureHeader.bodyHashKey)) {
                let maxLength = false;
                if (signatureHeader.parsed.l && Number(signatureHeader.parsed.l) > 0 && !isNaN(signatureHeader.parsed.l)) {
                    maxLength = Number(signatureHeader.parsed.l);
                }
                this.bodyHashes.set(signatureHeader.bodyHashKey, dkimBody(signatureHeader.bodyCanon, signatureHeader.hashAlgo, maxLength));
            }
        }
    }

    async nextChunk(chunk) {
        for (let bodyHash of this.bodyHashes.values()) {
            bodyHash.update(chunk);
        }
    }

    async finalChunk() {
        try {
            if (!this.headers || !this.bodyHashes.size) {
                return;
            }

            for (let [key, bodyHash] of this.bodyHashes.entries()) {
                this.bodyHashes.set(key, bodyHash.digest('base64'));
            }

            for (let signatureHeader of this.signatureHeaders) {
                if (signatureHeader.skip) {
                    // TODO: add failing header line?
                    continue;
                }

                let signedHeaderLines = getSignedHeaderLines(this.headers.parsed, signatureHeader.parsed.h, true);

                let { signingHeaders } = dkimHeader(signedHeaderLines, {
                    dkimHeaderLine: signatureHeader.original,
                    canonicalization: signatureHeader.canonicalization
                });

                let error;
                let publicKey;
                let status;

                let bodyHash = this.bodyHashes.get(signatureHeader.bodyHashKey);
                if (signatureHeader.parsed.bh !== bodyHash) {
                    status = 'neutral';
                    error = `body hash did not verify`;
                } else {
                    try {
                        publicKey = await getPublicKey(`${signatureHeader.selector}._domainkey.${signatureHeader.signingDomain}`, this.resolver);
                        try {
                            status = crypto.verify(
                                signatureHeader.signAlgo === 'rsa' ? signatureHeader.algorithm : null,
                                signingHeaders,
                                publicKey,
                                Buffer.from(signatureHeader.parsed.b, 'base64')
                            )
                                ? 'pass'
                                : 'fail';
                            if (status === 'fail') {
                                error = 'bad signature';
                            }
                        } catch (err) {
                            status = 'neutral';
                            error = err.message;
                        }
                    } catch (err) {
                        switch (err.code) {
                            case 'ENOTFOUND':
                                status = 'neutral';
                                error = `no key`;
                                break;

                            case 'EINVALIDVER':
                                status = 'neutral';
                                error = `unknown key version`;
                                break;

                            case 'EINVALIDTYPE':
                                status = 'neutral';
                                error = `unknown key type`;
                                break;

                            case 'EINVALIDVAL':
                                status = 'neutral';
                                error = `invalid public key`;
                                break;

                            case 'ESHORTKEY':
                                status = 'policy';
                                error = `weak key`;
                                break;

                            default:
                                status = 'temperror';
                                error = `DNS failure. ${err.message}`;
                        }
                    }
                }

                let result = {
                    signingDomain: signatureHeader.signingDomain,
                    selector: signatureHeader.selector,
                    signature: signatureHeader.parsed.b,
                    algo: signatureHeader.parsed.a,
                    format: signatureHeader.parsed.c,
                    bodyHash,
                    bodyHashExpecting: signatureHeader.parsed.bh,
                    status
                };

                if (publicKey) {
                    result.publicKey = publicKey.toString();
                }

                if (error) {
                    result.message = error;
                }

                this.results.push(result);
            }
        } finally {
            if (!this.results.length) {
                this.results.push({
                    status: 'none',
                    message: 'message not signed'
                });
            }

            this.results.forEach(result => {
                result.info = [
                    `dkim=${result.status}`,
                    result.message ? `(${result.message})` : '',
                    result.signingDomain ? `header.i=@${result.signingDomain}` : '',
                    result.selector ? `header.s=${result.selector}` : '',
                    result.signature ? `header.b="${result.signature.substr(0, 8)}"` : ''
                ]
                    .filter(val => val)
                    .join(' ');
            });
        }
    }
}

module.exports = { DkimVerifier };
