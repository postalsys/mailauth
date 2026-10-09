'use strict';

const { Buffer } = require('node:buffer');
const {
    getSigningHeaderLines,
    parseDkimHeaders,
    formatAuthHeaderRow,
    getAlignment,
    getCurTime,
    toALabel,
    isHostNameDomain,
    normalizeDomainName,
    isSameOrSubdomain,
    addWarning,
    KEY_ERROR_COMMENTS,
    isValidDnsName,
    splitAlgorithm,
    isSupportedAlgorithm,
    createKeyCache
} = require('../../lib/tools');
const { DOMAIN_NAME, SELECTOR, LOCAL_PART, TIMESTAMP, BODY_LENGTH } = require('./syntax');
const { MessageParser } = require('./message-parser');
const { dkimBody } = require('./body');
const { generateCanonicalizedHeader } = require('./header');
const { getARChain } = require('../arc');
const addressparser = require('nodemailer/lib/addressparser');
const { parseFromHeader, getAuthorDomain } = require('../dmarc/author-domain');
const crypto = require('node:crypto');
const libmime = require('libmime');

// RFC 6376 section 3.5 syntax, used by the strict mode
// sig-a-tag-alg = sig-a-tag-k "-" sig-a-tag-h, both ALPHA *(ALPHA / DIGIT)
const ALGORITHM = /^[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*$/;

// sig-c-tag-alg is "simple", "relaxed" or a hyphenated-word, sig-c-tag one or two of them
// separated by "/" (RFC 6376 section 3.5). An empty c= is not an omitted one (section 3.2)
const C_TAG_ALG = '[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?';
const CANONICALIZATION = new RegExp(`^${C_TAG_ALG}(?:/${C_TAG_ALG})?$`);

// Required tags of a DKIM-Signature (RFC 6376 section 3.5)
const REQUIRED_DKIM_TAGS = ['v', 'a', 'b', 'bh', 'd', 'h', 's'];

// Decodes dkim-quoted-printable (RFC 6376 section 2.11), used by the i= tag. FWS is not part
// of the value
const decodeDkimQuotedPrintable = value => {
    let bytes = Buffer.from((value || '').toString().replace(/[ \t\r\n]+/g, ''), 'utf8');
    let decoded = [];
    for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] === 0x3d && i + 2 < bytes.length && /^[0-9A-Fa-f]{2}$/.test(bytes.subarray(i + 1, i + 3).toString())) {
            decoded.push(parseInt(bytes.subarray(i + 1, i + 3).toString(), 16));
            i += 2;
        } else {
            decoded.push(bytes[i]);
        }
    }
    return Buffer.from(decoded).toString('utf8');
};

class DkimVerifier extends MessageParser {
    constructor(options) {
        super();

        this.options = options || {};
        this.resolver = this.options.resolver;
        this.minBitLength = this.options.minBitLength;

        // follow RFC 6376, RFC 8301 and RFC 8463 exactly instead of the lenient defaults
        this.strict = !!this.options.strict;

        // RFC 8301 section 3.1 on its own, without the rest of the strict mode
        this.rejectRsaSha1 = this.strict || !!this.options.rejectRsaSha1;

        this.curTime = getCurTime(this.options.curTime);

        this.results = [];

        this.signatureHeaders = [];
        this.bodyHashes = new Map();

        this.headerFrom = [];
        this.fromFields = 0;
        // "valid", "lax" or "invalid", see parseFromHeader
        this.fromSyntax = 'valid';
        // the Author Domain result of getAuthorDomain, set when there is a From address
        this.author = false;
        this.envelopeFrom = false;

        // ARC verification info, `warnings` lists what the lenient mode accepted in the chain
        this.arc = { chain: false, warnings: [] };

        // one key lookup per key record for the message. The ARC validation reuses it through
        // the (hidden) keyCache property of the ARC data
        this.keyCache = createKeyCache(this.resolver);
        Object.defineProperty(this.arc, 'keyCache', { value: this.keyCache, enumerable: false, configurable: true, writable: true });

        // should we also seal this message using ARC. A copy, so the body hash stored on it
        // below never ends up on the caller's object, which may be shared by concurrent calls
        this.seal = this.options.seal ? Object.assign({}, this.options.seal) : false;

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
            this.arc.chain = getARChain(headers, { strict: this.strict, warnings: this.arc.warnings });
            if (this.arc.chain?.length) {
                this.arc.lastEntry = this.arc.chain[this.arc.chain.length - 1];
            }
        } catch (err) {
            this.arc.error = err;
        }

        this.signatureHeaders = headers.parsed
            .filter(h => h.key === 'dkim-signature')
            .map(h => {
                // RFC 6376 section 3.2: tag names are case-sensitive, so in the strict mode "D="
                // is an unknown tag and not the d= tag
                const value = parseDkimHeaders(h.line, { strict: this.strict });
                value.type = 'DKIM';
                return value;
            });

        let fromHeaders = headers?.parsed?.filter(h => h.key === 'from');
        this.fromFields = fromHeaders.length;
        for (let fromHeader of fromHeaders) {
            fromHeader = fromHeader.line.toString();
            let splitterPos = fromHeader.indexOf(':');
            if (splitterPos >= 0) {
                fromHeader = fromHeader.substr(splitterPos + 1);
            }
            // the full addr-specs, including the mailboxes of a group (RFC 6854). A general
            // purpose address parser guesses at malformed input, which could hand DMARC a domain
            // that is not the one a reader sees, so the RFC 5322 grammar is followed instead
            let { addresses, syntax } = parseFromHeader(fromHeader);
            this.headerFrom.push(...addresses);
            if (syntax === 'invalid' || this.fromSyntax === 'valid') {
                this.fromSyntax = syntax;
            }
        }

        if (this.headerFrom.length) {
            // the same Author Domain rules as the DMARC check: a From header field that does
            // not yield a single Author Domain aligns with no signature
            this.author = getAuthorDomain(this.headerFrom, this.fromFields, { fromSyntax: this.fromSyntax, strict: this.strict });
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

        // include newest ARC-Message-Signature as one of the signature headers to check for.
        // The ARC-Seal is validated by the ARC module, it is not a DKIM signature, so it is
        // not evaluated here (a c= tag on it used to make it one, and it ended up in the
        // DKIM results)
        if (this.arc.lastEntry) {
            const signatureHeader = this.arc.lastEntry['arc-message-signature'];
            signatureHeader.type = 'ARC';
            this.signatureHeaders.push(signatureHeader);

            if (!this.strict && !signatureHeader.parsed?.c) {
                // Without c= the ARC-Message-Signature uses simple/simple, the DKIM-Signature
                // default (RFC 8617 section 4.1.2, RFC 6376 section 3.5). Older versions of this
                // library, and the ARC drafts, used relaxed/relaxed instead, so the lenient mode
                // also tries that when simple/simple does not verify, and marks the result
                signatureHeader.fallbackCanonicalization = 'relaxed/relaxed';
            }
        }

        for (let signatureHeader of this.signatureHeaders) {
            this.prepareSignature(signatureHeader);

            if (signatureHeader.skip || signatureHeader.invalid) {
                continue;
            }

            signatureHeader.bodyHashKey = this.addBodyHash(signatureHeader.bodyCanon, signatureHeader.hashAlgo, signatureHeader.maxBodyLength);
            if (signatureHeader.fallbackCanonicalization) {
                signatureHeader.fallbackBodyHashKey = this.addBodyHash(
                    getBodyCanon(signatureHeader.fallbackCanonicalization),
                    signatureHeader.hashAlgo,
                    signatureHeader.maxBodyLength
                );
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

    // Registers a body hash, once for every canonicalization, hash and length combination
    addBodyHash(bodyCanon, hashAlgo, maxBodyLength) {
        let bodyHashKey = [bodyCanon, hashAlgo, maxBodyLength].join(':');
        if (!this.bodyHashes.has(bodyHashKey)) {
            this.bodyHashes.set(bodyHashKey, dkimBody(bodyCanon, hashAlgo, maxBodyLength));
        }
        return bodyHashKey;
    }

    /**
     * Reads the tags of a signature header and validates them (RFC 6376 section 6.1.1).
     *
     * Sets `skip` for a signature that is not processed at all: the lenient mode leaves those
     * out of the results as it always has, the strict mode reports them as neutral. Sets
     * `invalid` to a reason for a signature that is reported as neutral without looking up
     * its key. Collects `warnings` for what the lenient mode accepts and the strict mode would
     * not.
     */
    prepareSignature(signatureHeader) {
        const strict = this.strict;
        const isDkim = signatureHeader.type === 'DKIM';

        signatureHeader.warnings = [];
        const warn = warning => addWarning(signatureHeader.warnings, warning);
        // A rule the strict mode enforces: returns true when the signature is invalid for it,
        // otherwise notes the warning (if any) and returns false
        const violation = (reason, warning) => {
            if (strict) {
                signatureHeader.invalid = reason;
                return true;
            }
            if (warning) {
                warn(warning);
            }
            return false;
        };

        // the raw tag values, as they were written, for the syntax checks
        const rawTags = new Map();
        for (let tag of signatureHeader.tags || []) {
            rawTags.set(tag.name, tag.value);
        }

        let tagListErrors = signatureHeader.syntaxErrors || [];
        let hasCaseFoldedTags = (signatureHeader.tags || []).some(tag => tag.name !== tag.name.toLowerCase());

        const parsed = signatureHeader.parsed || {};

        signatureHeader.algorithm = (parsed.a?.value || '').toString();
        Object.assign(signatureHeader, splitAlgorithm(signatureHeader.algorithm));

        let canonicalization = (parsed.c?.value || '').toString();
        signatureHeader.headerCanon = canonicalization.split('/').shift().toLowerCase().trim() || 'simple';
        signatureHeader.bodyCanon = getBodyCanon(canonicalization);
        // the canonicalization as read here, for the header canonicalizer. The c= text itself
        // can be malformed, "/relaxed" has no header part
        signatureHeader.canonicalization = `${signatureHeader.headerCanon}/${signatureHeader.bodyCanon}`;

        signatureHeader.signingDomain = (parsed.d?.value || '').toString();
        signatureHeader.selector = (parsed.s?.value || '').toString();

        signatureHeader.timestamp = parsed.t && !isNaN(parsed.t.value) ? new Date(parsed.t.value * 1000) : null;

        signatureHeader.expiration = parsed.x && !isNaN(parsed.x.value) ? new Date(parsed.x.value * 1000) : null;

        // `l=0` is a valid sig-l-tag and means that no body byte is covered by the
        // signature, so the value has to be tested for being a number, not for being
        // truthy, or a zero length limit would be read as no limit at all
        signatureHeader.maxBodyLength = typeof parsed.l?.value === 'number' && !isNaN(parsed.l.value) ? parsed.l.value : '';

        // AUID, "@d" when i= is not set (RFC 6376 section 3.5)
        if (isDkim && parsed.i && typeof parsed.i.value === 'string') {
            signatureHeader.identity = decodeDkimQuotedPrintable(parsed.i.value);
        } else if (isDkim) {
            signatureHeader.identity = signatureHeader.signingDomain ? `@${signatureHeader.signingDomain}` : '';
        }

        const validCanon = ['relaxed', 'simple'];

        // rsa-sha1 is only a DKIM algorithm, ARC signatures always use sha256
        if (!isSupportedAlgorithm(signatureHeader.signAlgo, signatureHeader.hashAlgo, isDkim) || (strict && !ALGORITHM.test(signatureHeader.algorithm))) {
            signatureHeader.skip = 'unknown algorithm';
            return;
        }

        if (!validCanon.includes(signatureHeader.headerCanon) || !validCanon.includes(signatureHeader.bodyCanon)) {
            signatureHeader.skip = 'unknown canonicalization';
            return;
        }

        if (!signatureHeader.signingDomain || !signatureHeader.selector) {
            signatureHeader.skip = 'signature missing required tag';
            return;
        }

        if (isDkim) {
            // RFC 6376 section 3.2 and 6.1.1
            if (tagListErrors.length && violation('signature syntax error', 'tag-syntax')) {
                return;
            }
            if (hasCaseFoldedTags) {
                warn('tag-syntax');
            }

            let missingTags = REQUIRED_DKIM_TAGS.filter(tag => !parsed[tag]);
            if (missingTags.length) {
                if (violation('signature missing required tag')) {
                    return;
                }
                // without h= the default header list is used, which does include From
                missingTags.forEach(tag => warn(`missing-${tag}`));
            }

            // "Verifiers MUST return PERMFAIL (incompatible version)"
            if (parsed.v && rawTags.get('v') !== '1' && violation('incompatible version', 'invalid-v')) {
                return;
            }

            let numericError = [
                ['t', TIMESTAMP],
                ['x', TIMESTAMP],
                ['l', BODY_LENGTH]
            ].some(([tag, format]) => parsed[tag] && !format.test(rawTags.get(tag) || ''));
            if (numericError && violation('signature syntax error', 'tag-syntax')) {
                return;
            }

            // the lenient mode reads a missing part as "simple" and ignores a third one
            let canonError = parsed.c && !CANONICALIZATION.test((rawTags.get('c') || '').replace(/[ \t\r\n]+/g, ''));
            if (canonError && violation('signature syntax error', 'tag-syntax')) {
                return;
            }

            // "This list MUST NOT be empty", the From check below covers the lenient mode
            if (parsed.h && !normalizeFieldList(parsed.h.value).length && violation('signature syntax error')) {
                return;
            }

            // toALabel converts each label on its own, so these also make up the key record name
            let signingDomainALabel = toALabel(signatureHeader.signingDomain);
            let selectorALabel = toALabel(signatureHeader.selector);
            if (!isHostNameDomain(signingDomainALabel)) {
                signatureHeader.invalid = 'signature syntax error';
                return;
            }

            // DOMAIN_NAME limits the length of each label, the key record name has to fit in
            // the 253 octets of a DNS name as well
            let invalidNames =
                !DOMAIN_NAME.test(signingDomainALabel) ||
                !SELECTOR.test(selectorALabel) ||
                !isValidDnsName(`${selectorALabel}._domainkey.${signingDomainALabel}`);
            if (invalidNames && violation('signature syntax error', 'tag-syntax')) {
                return;
            }

            if (parsed.q) {
                // "dns/txt" is the only query method, unrecognized ones are ignored
                let methods = (parsed.q.value || '')
                    .toString()
                    .split(':')
                    .map(method => method.trim().toLowerCase());
                if (!methods.includes('dns/txt') && violation('unsupported query method', 'query-method')) {
                    return;
                }
            }

            if (parsed.i) {
                // RFC 6376 section 6.1.1: the i= domain has to be d= or one of its subdomains
                let identity = signatureHeader.identity;
                let atPos = identity.lastIndexOf('@');
                let localPart = atPos >= 0 ? identity.substring(0, atPos) : '';
                let identityDomain = atPos >= 0 ? identity.substring(atPos + 1) : '';

                let validSyntax = atPos >= 0 && (!localPart || LOCAL_PART.test(localPart)) && DOMAIN_NAME.test(toALabel(identityDomain));
                let validDomain = atPos >= 0 && isSameOrSubdomain(identityDomain, signatureHeader.signingDomain);

                if ((!validSyntax || !validDomain) && violation(validSyntax ? 'domain mismatch' : 'signature syntax error', 'identity-domain')) {
                    return;
                }
                signatureHeader.identityDomain = identityDomain;
            }

            if (signatureHeader.timestamp && signatureHeader.expiration && signatureHeader.expiration <= signatureHeader.timestamp) {
                // "The value of the x= tag MUST be greater than the value of the t= tag". An x=
                // before t= fails in both modes, an x= equal to t= only in the strict mode
                if (violation('invalid expiration')) {
                    return;
                }
                if (signatureHeader.expiration.getTime() === signatureHeader.timestamp.getTime()) {
                    warn('invalid-expiration');
                }
            }

            if (signatureHeader.hashAlgo === 'sha1') {
                // RFC 8301 section 3.1: rsa-sha1 MUST NOT be used for verifying. Only the
                // strict mode and rejectRsaSha1 reject it, the lenient mode lets the key owner
                // opt out of it with the h= tag of the key record
                warn('rsa-sha1');
            }
        }

        // RFC 6376 section 6.1.1: a signature that does not cover From is ignored in every
        // mode. It says nothing about the author the DMARC check is about, and the From
        // header could have been replaced after signing. The same applies to the
        // ARC-Message-Signature, which has the DKIM-Signature syntax (RFC 8617 section 4.1.2)
        let signedFields = parsed.h ? normalizeFieldList(parsed.h.value) : ['from'];
        if (!signedFields.includes('from')) {
            signatureHeader.invalid = 'From field not signed';
            return;
        }
    }

    async nextChunk(chunk) {
        for (let bodyHash of this.bodyHashes.values()) {
            bodyHash.update(chunk);
        }
    }

    getSignatureTimeValid(signatureHeader) {
        // Signature claims to be from the future
        if (signatureHeader.timestamp && signatureHeader.timestamp > this.curTime) {
            return false;
        }
        // Signature has expired
        if (signatureHeader.expiration && signatureHeader.expiration < this.curTime) {
            return false;
        }
        // Within validity window or no constraints (vacuously true)
        return true;
    }

    getStatusHeader(signatureHeader) {
        let header = {};

        if (this.strict && signatureHeader.type === 'DKIM') {
            // RFC 8601 section 2.7.1: header.d is the d= domain and header.i the AUID, which is
            // the i= value or "@d" when there is no i=. Both use the domain-name syntax of
            // RFC 6376 section 3.5, where an internationalized domain name is an A-label
            let identity = signatureHeader.identity || '';
            let atPos = identity.lastIndexOf('@');
            header.d = signatureHeader.signingDomain ? toALabel(signatureHeader.signingDomain) : false;
            header.i = identity ? (atPos >= 0 ? identity.substring(0, atPos + 1) + toALabel(identity.substring(atPos + 1)) : identity) : false;
        } else {
            // signing domain
            header.i = signatureHeader.signingDomain ? `@${signatureHeader.signingDomain}` : false;
        }

        // dkim selector
        header.s = signatureHeader.selector;
        // algo
        header.a = signatureHeader.parsed?.a?.value;
        // signature value
        header.b = signatureHeader.parsed?.b?.value ? `${signatureHeader.parsed?.b?.value.toString().substr(0, 8)}` : false;

        return header;
    }

    // The result properties every signature has, whether it was verified or not
    baseResult(signatureHeader, format) {
        return {
            id: signatureHeader.parsed?.b?.value
                ? crypto.createHash('sha256').update(Buffer.from(signatureHeader.parsed.b.value.toString(), 'base64')).digest('hex')
                : crypto.randomUUID(),
            signingDomain: signatureHeader.signingDomain,
            selector: signatureHeader.selector,
            signature: signatureHeader.parsed?.b?.value,
            algo: signatureHeader.parsed?.a?.value,
            format
        };
    }

    /**
     * Verifies a signature
     *
     * @param {Object} signatureHeader Signature prepared by prepareSignature()
     * @param {Boolean} [fallback] If true, verify with `fallbackCanonicalization` instead of the
     *        canonicalization of the signature. The result is then built as if the signature
     *        had that c= value, and the signature header object is not updated
     * @returns {Object} Signature result
     */
    async verifySignature(signatureHeader, fallback) {
        // the canonicalization as prepareSignature() read it
        const canonicalization = fallback ? signatureHeader.fallbackCanonicalization : signatureHeader.canonicalization;
        const bodyHashKey = fallback ? signatureHeader.fallbackBodyHashKey : signatureHeader.bodyHashKey;

        let signingHeaderLines = getSigningHeaderLines(this.headers.parsed, signatureHeader.parsed?.h?.value, true);

        let { canonicalizedHeader } = generateCanonicalizedHeader(signatureHeader.type, signingHeaderLines, {
            signatureHeaderLine: signatureHeader.original,
            canonicalization,
            instance: signatureHeader.type === 'ARC' ? signatureHeader.parsed?.i?.value : false,
            strict: this.strict
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
            header: this.getStatusHeader(signatureHeader)
        };

        if (signatureHeader.type === 'DKIM' && this.author) {
            status.aligned = (this.author.authorDomain && getAlignment(this.author.authorDomain, [signatureHeader.signingDomain])?.domain) || false;
        }

        const bodyHasher = this.bodyHashes.get(bodyHashKey);
        const bodyHash = bodyHasher?.hash;
        const mimeStructureStart = bodyHasher?.mimeStructureStart;

        const warnings = [].concat(signatureHeader.warnings || []);

        // RFC 6376 section 3.5 l=: "This value MUST NOT be larger than the actual number of
        // octets in the canonicalized message body"
        let invalidBodyLength =
            signatureHeader.type === 'DKIM' &&
            typeof signatureHeader.maxBodyLength === 'number' &&
            typeof bodyHasher?.canonicalizedLength === 'number' &&
            signatureHeader.maxBodyLength > bodyHasher.canonicalizedLength;
        if (invalidBodyLength && !this.strict) {
            addWarning(warnings, 'tag-syntax');
        }

        if (signatureHeader.invalid || (invalidBodyLength && this.strict)) {
            // RFC 6376 section 6.1.1 PERMFAIL, reported as neutral, which RFC 8601 section
            // 2.7.1 uses for a signature with syntax errors. The key is not looked up
            status.result = 'neutral';
            status.comment = signatureHeader.invalid || 'signature syntax error';
        } else if (signatureHeader.parsed?.bh?.value !== bodyHash) {
            // RFC 6376 section 6.1.3 step 3 is a PERMFAIL, which RFC 8601 reports as "fail".
            // The lenient mode keeps reporting neutral, as it always has
            status.result = this.strict ? 'fail' : 'neutral';
            status.comment = `body hash did not verify`;
        } else if (this.rejectRsaSha1 && signatureHeader.type === 'DKIM' && signatureHeader.hashAlgo === 'sha1') {
            // RFC 8301 section 3.1, "rsa-sha1 MUST NOT be used for signing or verifying"
            status.result = 'policy';
            status.comment = 'weak algorithm';
            status.policy = { 'dkim-rules': 'weak-algorithm' };
        } else {
            try {
                let res = await this.keyCache.get(
                    signatureHeader.type,
                    `${signatureHeader.selector}._domainkey.${signatureHeader.signingDomain}`,
                    this.minBitLength,
                    {
                        strict: this.strict,
                        hashAlgo: signatureHeader.hashAlgo
                    }
                );

                publicKey = res?.publicKey;
                rr = res?.rr;
                modulusLength = res?.modulusLength;

                addWarning(warnings, ...(res?.warnings || []));

                if (res?.testing) {
                    // key t=y, the domain is testing DKIM (RFC 6376 section 3.6.1)
                    status.testing = true;
                }

                let keyError = false;
                if (res?.keyType && res.keyType !== signatureHeader.signAlgo) {
                    // RFC 6376 section 6.1.2 step 8, in every mode. The crypto library does not
                    // catch every mismatch: an RSA key verifies a PKCS#1 v1.5 signature over the
                    // digest that an ed25519-sha256 signature is made over
                    keyError = 'inappropriate key algorithm';
                } else if (
                    res?.flags?.includes('s') &&
                    signatureHeader.identityDomain &&
                    normalizeDomainName(signatureHeader.identityDomain) !== normalizeDomainName(signatureHeader.signingDomain)
                ) {
                    // key t=s: "the i= domain MUST NOT be a subdomain of d="
                    if (this.strict) {
                        keyError = 'domain mismatch';
                    } else {
                        addWarning(warnings, 'identity-domain');
                    }
                }

                if (keyError) {
                    status.result = 'neutral';
                    status.comment = keyError;
                } else {
                    try {
                        status.result = crypto.verify(
                            signatureHeader.signAlgo === 'rsa' ? signatureHeader.algorithm : null,
                            signatureHeader.signAlgo === 'rsa' ? canonicalizedHeader : crypto.createHash('sha256').update(canonicalizedHeader).digest(),
                            publicKey,
                            Buffer.from(signatureHeader.parsed?.b?.value || '', 'base64')
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
                }
            } catch (err) {
                if (err.rr) {
                    rr = err.rr;
                }

                if (KEY_ERROR_COMMENTS.has(err.code)) {
                    status.result = 'neutral';
                    status.comment = KEY_ERROR_COMMENTS.get(err.code);
                } else if (err.code === 'ESHORTKEY') {
                    status.result = 'policy';
                    if (!status.policy) {
                        status.policy = {};
                    }
                    status.policy['dkim-rules'] = `weak-key`;
                } else {
                    status.result = 'temperror';
                    status.comment = `DNS failure: ${err.code || err.message}`;
                }
            }
        }

        if (warnings.length) {
            // what the lenient mode accepted that the strict mode would not, never rendered
            // into the Authentication-Results header
            status.warnings = warnings;
        }

        const bodyHashedBytes = bodyHasher?.bodyHashedBytes;
        const canonicalizedLength = bodyHasher?.canonicalizedLength;
        const sourceBodyLength = bodyHasher?.byteLength;

        if (!fallback) {
            signatureHeader.bodyHashedBytes = bodyHashedBytes;
            signatureHeader.canonicalizedLength = canonicalizedLength;
            signatureHeader.sourceBodyLength = sourceBodyLength;
        }

        let result = Object.assign(this.baseResult(signatureHeader, fallback ? canonicalization : signatureHeader.parsed?.c?.value), {
            bodyHash,
            bodyHashExpecting: signatureHeader.parsed?.bh?.value,
            signingHeaders,
            status,
            signTime: signatureHeader.timestamp && !isNaN(signatureHeader.timestamp) ? signatureHeader.timestamp.toISOString() : null,
            expiresAfter: signatureHeader.expiration && !isNaN(signatureHeader.expiration) ? signatureHeader.expiration.toISOString() : null,
            signatureTimeValid: this.getSignatureTimeValid(signatureHeader)
        });

        if (typeof sourceBodyLength === 'number') {
            result.sourceBodyLength = sourceBodyLength;
        }

        if (typeof bodyHashedBytes === 'number') {
            result.canonBodyLength = bodyHashedBytes;
        }

        if (typeof canonicalizedLength === 'number') {
            result.canonBodyLengthTotal = canonicalizedLength;
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

        return result;
    }

    // A signature that could not be processed at all. The strict mode reports it as neutral
    // (RFC 8601 section 2.7.1: "the signature or signatures contained syntax errors or were
    // not otherwise able to be processed"), as "none" means that the message was not signed
    skippedSignatureResult(signatureHeader) {
        let status = {
            result: 'neutral',
            comment: signatureHeader.skip,
            header: this.getStatusHeader(signatureHeader)
        };

        return Object.assign(this.baseResult(signatureHeader, signatureHeader.parsed?.c?.value), { status });
    }

    async finalChunk() {
        try {
            if (!this.headers || (!this.bodyHashes.size && !this.signatureHeaders.some(signatureHeader => signatureHeader.invalid || signatureHeader.skip))) {
                return;
            }

            // convert bodyHashes from hash objects to base64 strings
            for (let [key, bodyHash] of this.bodyHashes.entries()) {
                this.bodyHashes.get(key).hash = bodyHash.digest('base64');
                this.bodyHashes.get(key).mimeStructureStart = bodyHash.getMimeStructureStart();
            }

            for (let signatureHeader of this.signatureHeaders) {
                let result;

                if (signatureHeader.skip) {
                    if (!this.strict || signatureHeader.type !== 'DKIM') {
                        // the lenient mode does not report what it can not process
                        continue;
                    }
                    result = this.skippedSignatureResult(signatureHeader);
                } else {
                    result = await this.verifySignature(signatureHeader);

                    if (signatureHeader.fallbackCanonicalization && !signatureHeader.invalid && result.status.result !== 'pass') {
                        // only used when it verifies, the result of the default canonicalization
                        // is kept otherwise. The key lookup is cached, so it is not repeated
                        let fallbackResult = await this.verifySignature(signatureHeader, true);
                        if (fallbackResult.status.result === 'pass') {
                            fallbackResult.status.warnings = addWarning([].concat(fallbackResult.status.warnings || []), 'ams-c-default');
                            result = fallbackResult;
                        }
                    }
                }

                switch (signatureHeader.type) {
                    case 'ARC':
                        if (!this.arc.lastEntry) {
                            break;
                        }
                        this.arc.lastEntry.messageSignature = result;
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
                result.info = formatAuthHeaderRow('dkim', result.status, { strict: this.strict });
            });
        }

        if (this.seal && this.bodyHashes.has(this.sealBodyHashKey) && typeof this.bodyHashes.get(this.sealBodyHashKey)?.hash === 'string') {
            this.seal.bodyHash = this.bodyHashes.get(this.sealBodyHashKey).hash;
        }
    }
}

// the body canonicalization of a c= value, 'simple' when it is not set (RFC 6376 section 3.5)
const getBodyCanon = canonicalization => (canonicalization.split('/')[1] || 'simple').toLowerCase().trim();

// the lower case header field names of an h= tag
const normalizeFieldList = value =>
    (value || '')
        .toString()
        .split(':')
        .map(name => name.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '').toLowerCase())
        .filter(name => name);

module.exports = { DkimVerifier };
