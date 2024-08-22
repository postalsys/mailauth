'use strict';

const { Buffer } = require('node:buffer');
const { getSigningHeaderLines, getPublicKey, parseDkimHeaders, formatAuthHeaderRow, getAlignment, getCurTime } = require('../../lib/tools');
const { MessageParser } = require('./message-parser');
const { dkimBody } = require('./body');
const { generateCanonicalizedHeader } = require('./header');
const { getARChain } = require('../arc');
const addressparser = require('nodemailer/lib/addressparser');
const crypto = require('node:crypto');
const libmime = require('libmime');

class DkimVerifier extends MessageParser {
    constructor(options) {
        super();

        this.options = options || {};
        this.resolver = this.options.resolver;
        this.minBitLength = this.options.minBitLength;

        this.curTime = getCurTime(this.options.curTime);

        this.results = [];

        this.signatureHeaders = [];
        this.bodyHashes = new Map();

        this.headerFrom = [];
        this.envelopeFrom = false;

        // ARC verification info
        this.arc = { chain: false };

        // should we also seal this message using ARC
        this.seal = this.options.seal;

        if (this.seal) {
            // calculate body hash for the seal
            let bodyCanon = 'relaxed';
            let hashAlgo = 'sha256';
            this.sealBodyHashKey = `${bodyCanon}:${hashAlgo}:`;
            this.bodyHashes.set(this.sealBodyHashKey, dkimBody(bodyCanon, hashAlgo, false));
        }
    }

    async messageHeaders(headers) {
        this.headers = headers;

        try {
            this.arc.chain = getARChain(headers);
            if (this.arc.chain?.length) {
                this.arc.lastEntry = this.arc.chain[this.arc.chain.length - 1];
            }
        } catch (err) {
            this.arc.error = err;
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

        // include newest ARC-Message-Signature as one of the signature headers to check for
        if (this.arc.lastEntry) {
            const signatureHeader = this.arc.lastEntry['arc-message-signature'];
            signatureHeader.type = 'ARC';
            this.signatureHeaders.push(signatureHeader);

            const sealHeader = this.arc.lastEntry['arc-seal'];
            sealHeader.type = 'AS';
            this.signatureHeaders.push(sealHeader);
        }

        for (let signatureHeader of this.signatureHeaders) {
            signatureHeader.algorithm = signatureHeader.parsed?.a?.value || '';
            signatureHeader.signAlgo = signatureHeader.algorithm.split('-').shift().toLowerCase().trim();
            signatureHeader.hashAlgo = signatureHeader.algorithm.split('-').pop().toLowerCase().trim();

            signatureHeader.canonicalization = signatureHeader.parsed?.c?.value || '';
            signatureHeader.headerCanon = signatureHeader.canonicalization.split('/').shift().toLowerCase().trim() || 'simple';
            // if body canonicalization is not set, then defaults to 'simple'
            signatureHeader.bodyCanon = (signatureHeader.canonicalization.split('/')[1] || 'simple').toLowerCase().trim();

            signatureHeader.signingDomain = signatureHeader.parsed?.d?.value || '';
            signatureHeader.selector = signatureHeader.parsed?.s?.value || '';

            signatureHeader.timestamp =
                signatureHeader.parsed?.t && !isNaN(signatureHeader.parsed?.t?.value) ? new Date(signatureHeader.parsed?.t?.value * 1000) : null;

            signatureHeader.expiration =
                signatureHeader.parsed?.x && !isNaN(signatureHeader.parsed?.x?.value) ? new Date(signatureHeader.parsed?.x?.value * 1000) : null;

            signatureHeader.maxBodyLength =
                signatureHeader.parsed?.l?.value && !isNaN(signatureHeader.parsed?.l?.value) ? signatureHeader.parsed?.l?.value : '';

            const validSignAlgo = ['rsa', 'ed25519'];
            const validHeaderAlgo = signatureHeader.type === 'DKIM' ? ['sha256', 'sha1'] : ['sha256'];
            const validHeaderCanon = signatureHeader.type !== 'AS' ? ['relaxed', 'simple'] : ['relaxed'];
            const validBodyCanon = signatureHeader.type !== 'AS' ? ['relaxed', 'simple'] : ['relaxed'];

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

            signatureHeader.bodyHashKey = [signatureHeader.bodyCanon, signatureHeader.hashAlgo, signatureHeader.maxBodyLength].join(':');
            if (!this.bodyHashes.has(signatureHeader.bodyHashKey)) {
                this.bodyHashes.set(signatureHeader.bodyHashKey, dkimBody(signatureHeader.bodyCanon, signatureHeader.hashAlgo, signatureHeader.maxBodyLength));
            }

            let headersArray = this.headers.parsed;
            const findLastMethod = typeof headersArray.findLast === 'function' ? headersArray.findLast : headersArray.find;
            if (typeof headersArray.findLast !== 'function') {
                headersArray = [].concat(headersArray).reverse();
            }
            const contentTypeHeader = findLastMethod.call(headersArray, header => header.key === 'content-type');
            if (contentTypeHeader) {
                let line = contentTypeHeader.line.toString();
                if (line.indexOf(':') >= 0) {
                    line = line.substring(line.indexOf(':') + 1).trim();
                }
                const parsedContentType = libmime.parseHeaderValue(line);
                for (let hasher of this.bodyHashes.values()) {
                    hasher.setContentType(parsedContentType);
                }
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

            // convert bodyHashes from hash objects to base64 strings
            for (let [key, bodyHash] of this.bodyHashes.entries()) {
                this.bodyHashes.get(key).hash = bodyHash.digest('base64');
                this.bodyHashes.get(key).mimeStructureStart = bodyHash.getMimeStructureStart();
            }

            for (let signatureHeader of this.signatureHeaders) {
                if (signatureHeader.skip) {
                    // TODO: add failing header line?
                    continue;
                }

                let signingHeaderLines = getSigningHeaderLines(this.headers.parsed, signatureHeader.parsed?.h?.value, true);

                let { canonicalizedHeader } = generateCanonicalizedHeader(signatureHeader.type, signingHeaderLines, {
                    signatureHeaderLine: signatureHeader.original,
                    canonicalization: signatureHeader.canonicalization,
                    instance: ['ARC', 'AS'].includes(signatureHeader.type) ? signatureHeader.parsed?.i?.value : false
                });

                let signingHeaders = {
                    keys: signingHeaderLines.keys,
                    headers: signingHeaderLines.headers.map(l => l.line.toString()),
                    canonicalizedHeader: canonicalizedHeader.toString('base64')
                };

                let publicKey, rr, modulusLength;
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
                    }
                };

                if (signatureHeader.type === 'DKIM' && this.headerFrom?.length) {
                    status.aligned = this.headerFrom?.length
                        ? getAlignment(this.headerFrom[0].split('@').pop(), [signatureHeader.signingDomain])?.domain || false
                        : false;
                }

                const bodyHash = this.bodyHashes.get(signatureHeader.bodyHashKey)?.hash;
                const mimeStructureStart = this.bodyHashes.get(signatureHeader.bodyHashKey)?.mimeStructureStart;

                if (signatureHeader.parsed?.bh?.value !== bodyHash) {
                    status.result = 'neutral';
                    status.comment = `body hash did not verify`;
                } else {
                    try {
                        let res = await getPublicKey(
                            signatureHeader.type,
                            `${signatureHeader.selector}._domainkey.${signatureHeader.signingDomain}`,
                            this.minBitLength,
                            this.resolver
                        );

                        publicKey = res?.publicKey;
                        rr = res?.rr;
                        modulusLength = res?.modulusLength;

                        try {
                            status.result = crypto.verify(
                                signatureHeader.signAlgo === 'rsa' ? signatureHeader.algorithm : null,
                                signatureHeader.signAlgo === 'rsa' ? canonicalizedHeader : crypto.createHash('sha256').update(canonicalizedHeader).digest(),
                                publicKey,
                                Buffer.from(signatureHeader.parsed?.b?.value, 'base64')
                            )
                                ? 'pass'
                                : 'fail';

                            if (status.result === 'fail') {
                                status.comment = 'bad signature';
                            }

                            if (status.result === 'pass') {
                                if (signatureHeader.expiration && signatureHeader.timestamp && signatureHeader.expiration < signatureHeader.timestamp) {
                                    status.result = 'neutral';
                                    status.comment = 'invalid expiration';
                                }

                                if (signatureHeader.expiration && signatureHeader.expiration < this.curTime) {
                                    status.result = 'neutral';
                                    status.comment = 'expired';
                                }
                            }
                        } catch (err) {
                            status.result = 'neutral';
                            status.comment = err.message;
                        }
                    } catch (err) {
                        if (err.rr) {
                            rr = err.rr;
                        }

                        switch (err.code) {
                            case 'ENOTFOUND':
                            case 'ENODATA':
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
                                if (!status.policy) {
                                    status.policy = {};
                                }
                                status.policy['dkim-rules'] = `weak-key`;
                                break;

                            default:
                                status.result = 'temperror';
                                status.comment = `DNS failure: ${err.code || err.message}`;
                        }
                    }
                }

                signatureHeader.bodyHashedBytes = this.bodyHashes.get(signatureHeader.bodyHashKey)?.bodyHashedBytes;
                signatureHeader.canonicalizedLength = this.bodyHashes.get(signatureHeader.bodyHashKey)?.canonicalizedLength;
                signatureHeader.sourceBodyLength = this.bodyHashes.get(signatureHeader.bodyHashKey)?.byteLength;

                if (typeof signatureHeader.maxBodyLength === 'number' && signatureHeader.maxBodyLength !== signatureHeader.bodyHashedBytes) {
                    console.log('TOTAL', signatureHeader.bodyHashedBytes, 'EXPECTING', signatureHeader.maxBodyLength);
                    //status.result = 'fail';
                    //status.comment = `invalid body length ${signatureHeader.bodyHashedBytes}`;
                }

                let result = {
                    id: signatureHeader.parsed?.b?.value
                        ? crypto.createHash('sha256').update(Buffer.from(signatureHeader.parsed?.b?.value, 'base64')).digest('hex')
                        : crypto.randomUUID(),
                    signingDomain: signatureHeader.signingDomain,
                    selector: signatureHeader.selector,
                    signature: signatureHeader.parsed?.b?.value,
                    algo: signatureHeader.parsed?.a?.value,
                    format: signatureHeader.parsed?.c?.value,
                    bodyHash,
                    bodyHashExpecting: signatureHeader.parsed?.bh?.value,
                    signingHeaders,
                    status
                };

                if (typeof signatureHeader.sourceBodyLength === 'number') {
                    result.sourceBodyLength = signatureHeader.sourceBodyLength;
                }

                if (typeof signatureHeader.bodyHashedBytes === 'number') {
                    result.canonBodyLength = signatureHeader.bodyHashedBytes;
                }

                if (typeof signatureHeader.canonicalizedLength === 'number') {
                    result.canonBodyLengthTotal = signatureHeader.canonicalizedLength;
                }

                if (typeof signatureHeader.maxBodyLength === 'number') {
                    result.canonBodyLengthLimited = true;
                    result.canonBodyLengthLimit = signatureHeader.maxBodyLength;
                    if (result.canonBodyLengthTotal > result.canonBodyLength) {
                        status.underSized = result.canonBodyLengthTotal - result.canonBodyLength;
                    }
                } else {
                    result.canonBodyLengthLimited = false;
                }

                if (typeof mimeStructureStart === 'number') {
                    result.mimeStructureStart = mimeStructureStart;
                }

                if (publicKey) {
                    result.publicKey = publicKey.toString();
                }

                if (modulusLength) {
                    result.modulusLength = modulusLength;
                }

                if (rr) {
                    result.rr = rr;
                }

                if (typeof result.status.comment === 'boolean') {
                    delete result.status.comment;
                }

                switch (signatureHeader.type) {
                    case 'ARC':
                        if (this.arc.lastEntry) {
                            this.arc.lastEntry.messageSignature = result;
                        }
                        break;
                    case 'DKIM':
                    default:
                        this.results.push(result);
                        break;
                }
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

        if (this.seal && this.bodyHashes.has(this.sealBodyHashKey) && typeof this.bodyHashes.get(this.sealBodyHashKey)?.hash === 'string') {
            this.seal.bodyHash = this.bodyHashes.get(this.sealBodyHashKey).hash;
        }
    }
}

module.exports = { DkimVerifier };
