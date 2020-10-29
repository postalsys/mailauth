'use strict';

const { getSignedHeaderLines, getPublicKey, parseDkimHeaders, formatAuthHeaderRow } = require('../../lib/tools');
const { MessageParser } = require('./message-parser');
const { dkimBody } = require('./body');
const { generateCanonicalizedHeader } = require('./header');
const { getARChain } = require('../arc');
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

        this.headerFrom = [];
        this.envelopeFrom = false;
    }

    async messageHeaders(headers) {
        this.headers = headers;

        try {
            this.arChain = { chain: getARChain(headers) };
        } catch (err) {
            this.arChain = { err };
        }

        this.signatureHeaders = headers.parsed
            .filter(h => h.key === 'dkim-signature')
            .map(h => {
                const value = parseDkimHeaders(h.line);
                value.type = 'DKIM';
                return value;
            });

        let fromHeaders = headers?.parsed?.filter(h => h.key === 'from');
        for (let fromHeader of fromHeaders) {
            fromHeader = fromHeader.line.toString();
            let splitterPos = fromHeader.indexOf(':');
            if (splitterPos >= 0) {
                fromHeader = fromHeader.substr(splitterPos + 1);
            }
            let from = addressparser(fromHeader.trim());
            for (let addr of from) {
                if (addr && addr.address) {
                    this.headerFrom.push(addr.address);
                }
            }
        }

        if (this.options.sender) {
            let returnPath = addressparser(this.options.sender);
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

        // include ARC-Message-Signature as one of the signature headers to check for
        if (this.arChain?.chain) {
            const chainData = this.arChain.chain[this.arChain.chain.length - 1];
            const signatureHeader = chainData['arc-message-signature'];
            signatureHeader.type = 'ARC';
            this.signatureHeaders.push(signatureHeader);
        }

        for (let signatureHeader of this.signatureHeaders) {
            signatureHeader.algorithm = signatureHeader.parsed?.a?.value || '';
            signatureHeader.signAlgo = signatureHeader.algorithm.split('-').shift().toLowerCase().trim();
            signatureHeader.hashAlgo = signatureHeader.algorithm.split('-').pop().toLowerCase().trim();

            signatureHeader.canonicalization = signatureHeader.parsed?.c?.value || '';
            signatureHeader.headerCanon = signatureHeader.canonicalization.split('/').shift().toLowerCase().trim();
            // if body canonicalization is not set, then defaults to 'simple'
            signatureHeader.bodyCanon = (signatureHeader.canonicalization.split('/')[1] || 'simple').toLowerCase().trim();

            signatureHeader.signingDomain = signatureHeader.parsed?.d?.value || '';
            signatureHeader.selector = signatureHeader.parsed?.s?.value || '';

            const validSignAlgo = ['rsa', 'ed25519'];
            const validHeaderAlgo = signatureHeader.type === 'DKIM' ? ['sha256', 'sha1'] : ['sha256'];
            const validHeaderCanon = signatureHeader.type === 'DKIM' ? ['relaxed', 'simple'] : ['relaxed'];
            const validBodyCanon = signatureHeader.type === 'DKIM' ? ['relaxed', 'simple'] : ['relaxed'];

            if (
                !validSignAlgo.includes(signatureHeader.signAlgo) ||
                !validHeaderAlgo.includes(signatureHeader.hashAlgo) ||
                !validHeaderCanon.includes(signatureHeader.headerCanon) ||
                !validBodyCanon.includes(signatureHeader.bodyCanon) ||
                !signatureHeader.signingDomain ||
                !signatureHeader.selector
            ) {
                signatureHeader.skip = true;
                continue;
            }

            signatureHeader.bodyHashKey = [signatureHeader.bodyCanon, signatureHeader.hashAlgo].join(':');
            if (!this.bodyHashes.has(signatureHeader.bodyHashKey)) {
                let maxLength = false;

                if (signatureHeader.parsed?.l?.value) {
                    maxLength = signatureHeader.parsed?.l?.value;
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

                let signedHeaderLines = getSignedHeaderLines(this.headers.parsed, signatureHeader.parsed?.h?.value, true);

                let { canonicalizedHeader } = generateCanonicalizedHeader(signatureHeader.type, signedHeaderLines, {
                    signatureHeaderLine: signatureHeader.original,
                    canonicalization: signatureHeader.canonicalization,
                    instance: signatureHeader.type === 'ARC' ? signatureHeader.parsed?.i?.value : false
                });

                let publicKey;
                let status = {
                    result: 'neutral',
                    comment: false,
                    // ptype properties
                    header: {
                        // signing domain
                        i: signatureHeader.signingDomain ? `@${signatureHeader.signingDomain}` : false,
                        // dkim selector
                        s: signatureHeader.selector,
                        // algo
                        a: signatureHeader.parsed?.a?.value,
                        // signature value
                        b: signatureHeader.parsed?.b?.value ? `${signatureHeader.parsed?.b?.value.substr(0, 8)}` : false
                    },
                    policy: {}
                };

                let bodyHash = this.bodyHashes.get(signatureHeader.bodyHashKey);
                if (signatureHeader.parsed?.bh?.value !== bodyHash) {
                    status.result = 'neutral';
                    status.comment = `body hash did not verify`;
                } else {
                    try {
                        publicKey = await getPublicKey(
                            signatureHeader.type,
                            `${signatureHeader.selector}._domainkey.${signatureHeader.signingDomain}`,
                            this.resolver
                        );

                        try {
                            status.result = crypto.verify(
                                signatureHeader.signAlgo === 'rsa' ? signatureHeader.algorithm : null,
                                canonicalizedHeader,
                                publicKey,
                                Buffer.from(signatureHeader.parsed?.b?.value, 'base64')
                            )
                                ? 'pass'
                                : 'fail';
                            if (status === 'fail') {
                                status.comment = 'bad signature';
                            }
                        } catch (err) {
                            status.result = 'neutral';
                            status.comment = err.message;
                        }
                    } catch (err) {
                        switch (err.code) {
                            case 'ENOTFOUND':
                                status.result = 'neutral';
                                status.comment = `no key`;
                                break;

                            case 'EINVALIDVER':
                                status.result = 'neutral';
                                status.comment = `unknown key version`;
                                break;

                            case 'EINVALIDTYPE':
                                status.result = 'neutral';
                                status.comment = `unknown key type`;
                                break;

                            case 'EINVALIDVAL':
                                status.result = 'neutral';
                                status.comment = `invalid public key`;
                                break;

                            case 'ESHORTKEY':
                                status.result = 'policy';
                                status.policy['dkim-rules'] = `weak-key`;
                                break;

                            default:
                                status.result = 'temperror';
                                status.comment = `DNS failure: ${err.code || err.message}`;
                        }
                    }
                }

                let result = {
                    type: signatureHeader.type,
                    signingDomain: signatureHeader.signingDomain,
                    selector: signatureHeader.selector,
                    signature: signatureHeader.parsed?.b?.value,
                    algo: signatureHeader.parsed?.a?.value,
                    format: signatureHeader.parsed?.c?.value,
                    bodyHash,
                    bodyHashExpecting: signatureHeader.parsed?.bh?.value,
                    status
                };

                if (publicKey) {
                    result.publicKey = publicKey.toString();
                }

                this.results.push(result);
            }
        } finally {
            if (!this.results.length) {
                this.results.push({
                    status: {
                        result: 'none',
                        comment: 'message not signed'
                    }
                });
            }

            this.results.forEach(result => {
                result.info = formatAuthHeaderRow('dkim', result.status);
            });
        }
    }
}

module.exports = { DkimVerifier };
