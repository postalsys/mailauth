'use strict';

const { Buffer } = require('node:buffer');
const { isIP } = require('node:net');
const {
    parseDkimHeaders,
    formatRelaxedLine,
    stripSignatureValue,
    formatAuthHeaderRow,
    formatSignatureHeaderLine,
    writeToStream,
    validateAlgorithm,
    createError,
    addWarning,
    KEY_ERROR_COMMENTS,
    splitAlgorithm,
    createKeyCache
} = require('../../lib/tools');
const { TIMESTAMP, BODY_LENGTH, MAX_ARC_INSTANCE, ARC_HEADER_KEYS } = require('../dkim/syntax');
const crypto = require('node:crypto');
const { DkimSigner } = require('../dkim/dkim-signer');

// RFC 8617 section 3.9: chain-status = ("none" / "fail" / "pass"). ABNF strings are case-insensitive
const CHAIN_STATUS = ['none', 'pass', 'fail'];

// RFC 8617 section 3.9: position = 1*2DIGIT
const INSTANCE_VALUE = /^[0-9]{1,2}$/;

// RFC 8617 section 4.1.1: arc-info = instance [CFWS] ";" authres-payload, so the instance is the
// first thing in an ARC-Authentication-Results value. Comments (without nesting) are allowed as CFWS
const CFWS = '(?:[ \\t\\r\\n]|\\([^()\\\\]*\\))*';
const AAR_INSTANCE = new RegExp(`^${CFWS}i${CFWS}=${CFWS}([0-9]{1,2})${CFWS};`);

// Tags an ARC-Seal (RFC 8617 section 4.1.3) and an ARC-Message-Signature (section 4.1.2, with
// the DKIM-Signature tags of RFC 6376 section 3.5 except v= and i=) can not do without
const REQUIRED_TAGS = {
    'arc-seal': ['a', 'b', 'cv', 'd', 's'],
    'arc-message-signature': ['a', 'b', 'bh', 'd', 'h', 's']
};

const NUMERIC_TAGS = {
    'arc-seal': [['t', TIMESTAMP]],
    'arc-message-signature': [
        ['t', TIMESTAMP],
        ['x', TIMESTAMP],
        ['l', BODY_LENGTH]
    ]
};

const SHORT_NAMES = {
    'arc-seal': 'as',
    'arc-message-signature': 'ams',
    'arc-authentication-results': 'aar'
};

// the cv= value of an ARC set in lower case, or an empty string
const getCv = arcInstance => (arcInstance?.['arc-seal']?.parsed?.cv?.value || '').toString().toLowerCase().trim();

// The highest i= found on the ARC header fields of a message, or 0, and the cv= of the seal
// with that instance. A new set follows it (RFC 8617 section 5.1 step 3) even when the chain
// can not be parsed, so that it never reuses an instance that already exists
const getHighestArcInstance = headers => {
    let highest = 0;
    let latestCv = false;
    for (let row of headers?.parsed || []) {
        if (!ARC_HEADER_KEYS.includes(row.key)) {
            continue;
        }
        let parsed;
        try {
            parsed = parseDkimHeaders(row.line)?.parsed;
        } catch (err) {
            continue;
        }
        let instance = parsed?.i?.value;
        if (typeof instance !== 'number' || !Number.isInteger(instance) || instance < 1) {
            continue;
        }
        if (instance > highest) {
            highest = instance;
            latestCv = false;
        }
        if (instance === highest && row.key === 'arc-seal' && typeof parsed?.cv?.value === 'string') {
            latestCv = parsed.cv.value.toLowerCase().trim();
        }
    }
    return { highest, latestCv };
};

// Where a new ARC set goes (RFC 8617 section 5.1 steps 2 and 3): the highest existing instance
// and the cv= of its seal, from the header fields and from the parsed chain, for callers that
// pass the chain without the complete header list
const getArcPosition = (headers, chain) => {
    let { highest, latestCv } = getHighestArcInstance(headers);
    let lastEntry = chain?.length ? chain[chain.length - 1] : false;
    if (lastEntry && lastEntry.i >= highest) {
        highest = lastEntry.i;
        latestCv = getCv(lastEntry) || latestCv;
    }
    return { highest, latestCv };
};

// the DNS name of the key record of an ARC-Seal
const sealKeyName = seal => `${seal.parsed?.s?.value}._domainkey.${seal.parsed?.d?.value}`;

const verifyAS = async (chain, opts) => {
    const { strict, warnings, keyCache } = opts || {};

    let chunks = [];
    let signatureHeader;

    for (let i = 0; i < chain.length; i++) {
        let isLast = i === chain.length - 1;
        let link = chain[i];

        chunks.push(formatRelaxedLine(link['arc-authentication-results'].original, '\r\n'));
        chunks.push(formatRelaxedLine(link['arc-message-signature'].original, '\r\n'));

        if (!isLast) {
            chunks.push(formatRelaxedLine(link['arc-seal'].original, '\r\n'));
        } else {
            signatureHeader = link['arc-seal'];
            if (!signatureHeader.parsed?.s?.value || !signatureHeader.parsed?.d?.value) {
                throw createError(`Invalid ARC-Seal header`, 'invalid_arc_seal');
            }

            chunks.push(stripSignatureValue(formatRelaxedLine(link['arc-seal'].original), strict));
        }
    }

    // The algorithm is read from the seal itself. Every seal of the chain is verified here, not
    // only the newest one, so nothing set up elsewhere for the newest seal can be relied on
    let algorithm = (signatureHeader.parsed?.a?.value || '').toString().toLowerCase().trim();
    try {
        // rsa-sha256 and ed25519-sha256 only, ARC has no rsa-sha1
        validateAlgorithm(algorithm, true);
    } catch (err) {
        throw createError(`i=${chain.length} invalid seal algorithm`, 'invalid_arc_seal');
    }
    let { signAlgo } = splitAlgorithm(algorithm);

    let canonicalizedHeader = Buffer.concat(chunks);

    let publicKey;
    let queryDomain = sealKeyName(signatureHeader);
    try {
        // the key record's own h= and s= restrictions apply to ARC keys as well (RFC 6376
        // section 3.6.1), and every ARC signature uses sha256
        let res = await keyCache.get('AS', queryDomain, opts?.minBitLength, { strict, hashAlgo: 'sha256' });
        publicKey = res?.publicKey;

        if (res?.keyType && res.keyType !== signAlgo) {
            // RFC 6376 section 6.1.2 step 8: the key has to suit the a= algorithm
            throw createError('Key type does not match the seal algorithm', 'EINVALIDKEYALGO');
        }

        if (Array.isArray(warnings)) {
            addWarning(warnings, ...(res?.warnings || []));
        }
    } catch (err) {
        err.queryDomain = queryDomain;
        // the error code is what the ARC result reports as a comment
        throw err;
    }

    let pass = false;
    try {
        pass = crypto.verify(
            signAlgo === 'rsa' ? 'sha256' : null,
            // RFC 8463 section 3: Ed25519 signs the SHA-256 hash of the canonicalized data
            signAlgo === 'rsa' ? canonicalizedHeader : crypto.createHash('sha256').update(canonicalizedHeader).digest(),
            publicKey,
            Buffer.from(signatureHeader.parsed?.b?.value || '', 'base64')
        );
    } catch (err) {
        pass = false;
    }

    if (!pass) {
        throw createError(`i=${chain.length} seal signature validation failed`, 'failing_arc_seal');
    }

    return true;
};

const signAS = async (chain, entry, signatureData) => {
    let { instance, algorithm, selector, signingDomain, bodyHash, cv, signTime, privateKey } = signatureData;

    instance = instance || 1;

    const { signAlgo } = splitAlgorithm(algorithm);

    signTime = signTime || new Date();

    let chunks = [];

    if (cv === 'pass') {
        // sign existing only chain for passing validation
        for (let i = 0; i < chain.length; i++) {
            let link = chain[i];

            chunks.push(formatRelaxedLine(link['arc-authentication-results'].original, '\r\n'));
            chunks.push(formatRelaxedLine(link['arc-message-signature'].original, '\r\n'));
            chunks.push(formatRelaxedLine(link['arc-seal'].original, '\r\n'));
        }
    }

    chunks.push(formatRelaxedLine(entry['arc-authentication-results'], '\r\n'));
    chunks.push(formatRelaxedLine(entry['arc-message-signature'], '\r\n'));

    let headerOpts = {
        i: instance,
        a: algorithm,
        s: selector,
        d: signingDomain,
        cv,
        bh: bodyHash
    };

    if (signTime) {
        if (typeof signTime === 'string' || typeof signTime === 'number') {
            signTime = new Date(signTime);
        }

        if (Object.prototype.toString.call(signTime) === '[object Date]' && signTime.toString() !== 'Invalid Date') {
            // we need a unix timestamp value
            signTime = Math.floor(signTime.getTime() / 1000);
            headerOpts.t = signTime;
        }
    }

    let canonSignatureHeaderLine = formatSignatureHeaderLine(
        'AS',
        Object.assign(
            {
                // make sure that b= always has a value, otherwise folding would be different
                b: 'a'.repeat(73)
            },
            headerOpts
        ),
        true
    );

    chunks.push(stripSignatureValue(formatRelaxedLine(canonSignatureHeaderLine)));

    let canonicalizedHeader = Buffer.concat(chunks);

    let signature = crypto
        .sign(
            // use `null` as algorithm to detect it from the key file
            signAlgo === 'rsa' ? algorithm : null,
            signAlgo === 'rsa' ? canonicalizedHeader : crypto.createHash('sha256').update(canonicalizedHeader).digest(),
            privateKey
        )
        .toString('base64');

    headerOpts.b = signature;

    return formatSignatureHeaderLine('AS', headerOpts, true);
};

/**
 * Validates the ARC-Seal signatures of a chain (RFC 8617 section 5.2 steps 2, 3.C and 6).
 * Throws if the chain is not valid, so it never returns true for a chain with an invalid seal.
 *
 * @param {Object} data { chain } as returned by getARChain()
 * @param {Object} [opts] { resolver, minBitLength, strict, warnings, keyCache }, where keyCache
 *        is a createKeyCache() of the same resolver, shared with other key lookups of the message
 * @returns {Boolean} false if there is no chain, true if every seal validates
 */
const verifyASChain = async (data, opts) => {
    if (!data?.chain?.length) {
        return false;
    }

    const chain = data.chain;
    opts = Object.assign({}, opts);
    if (!opts.keyCache) {
        opts.keyCache = createKeyCache(opts.resolver);
    }

    for (let i = 0; i < chain.length; i++) {
        let arcInstance = chain[i];

        if (arcInstance?.i !== i + 1) {
            throw createError(`i=${arcInstance?.i} expected=${i + 1}`, 'invalid_arc_instance');
        }

        for (let headerKey of ARC_HEADER_KEYS) {
            if (!arcInstance[headerKey]) {
                throw createError(`i=${arcInstance.i} no ${headerKey} set`, 'missing_arc_header');
            }
        }

        // Step 2 (a newest seal with cv=fail fails the chain) and step 3.C: cv=none for i=1 and
        // cv=pass for every later set. The values are compared case-insensitively, as an ABNF
        // string is. A seal with cv=fail only signs its own set (section 5.1.2), so it can
        // never vouch for the sets before it
        let cv = getCv(arcInstance);
        let expected = i === 0 ? 'none' : 'pass';
        if (cv !== expected) {
            throw createError(`i=${arcInstance.i} cv=${cv}`, 'invalid_cv_value');
        }
    }

    // The keys of all the seals are fetched at once. A failed lookup is only reported when its
    // seal is validated, so the errors come in the same order as without the prefetch
    for (let link of chain) {
        let seal = link['arc-seal'];
        if (seal.parsed?.s?.value && seal.parsed?.d?.value) {
            opts.keyCache.get('AS', sealKeyName(seal), opts.minBitLength, { strict: opts.strict, hashAlgo: 'sha256' });
        }
    }

    // Step 6: every seal, from the newest to the oldest, throws if validation fails
    for (let i = chain.length - 1; i >= 0; i--) {
        await verifyAS(chain.slice(0, i + 1), opts);
    }

    return true;
};

// The instance of an ARC header field exactly as written, or null. For the
// ARC-Authentication-Results it is the leading "i=N;" (RFC 8617 section 4.1.1), for the other
// two it is the value of the (case-sensitive) i tag
const getRawInstance = (headerKey, value, line) => {
    if (headerKey === 'arc-authentication-results') {
        let str = (line || '').toString('binary');
        str = str.substring(str.indexOf(':') + 1);
        let match = AAR_INSTANCE.exec(str);
        return match ? match[1] : null;
    }

    let tag = (value?.tags || []).find(tag => tag.name === 'i');
    return tag ? tag.value : null;
};

// Checks the tag-list of an ARC-Seal or ARC-Message-Signature (RFC 6376 section 3.2 and 3.5,
// RFC 8617 section 4.1). The strict mode, where getARChain has read the tags case-sensitively,
// rejects the set for any syntax error, the lenient mode keeps reading them the way it always
// has and only notes what the strict mode would have rejected
const checkTagList = (arcInstance, headerKey, strict, warn) => {
    let header = arcInstance[headerKey];
    let tags = header.tags || [];

    let problems = [].concat(header.syntaxErrors || []);

    let rawTags = new Map();
    for (let tag of tags) {
        rawTags.set(tag.name, tag.value);
    }

    for (let tag of REQUIRED_TAGS[headerKey]) {
        if (!rawTags.has(tag)) {
            problems.push(`missing ${tag}=`);
        }
    }

    for (let [tag, format] of NUMERIC_TAGS[headerKey]) {
        if (rawTags.has(tag) && !format.test(rawTags.get(tag))) {
            problems.push(`invalid ${tag}=`);
        }
    }

    if (strict) {
        if (problems.length) {
            throw createError(`i=${arcInstance.i} ${SHORT_NAMES[headerKey]} ${problems[0]}`, 'invalid_arc_tags');
        }
        return;
    }

    if (problems.length || tags.some(tag => tag.name !== tag.name.toLowerCase())) {
        warn('arc-tag-syntax');
    }
};

/**
 * Collects the ARC sets of a message and validates the structure of the chain (RFC 8617
 * section 5.2 steps 1 to 3).
 *
 * @param {Object} headers Parsed message headers
 * @param {Object} [opts]
 * @param {Boolean} [opts.strict=false] Apply the RFC 8617 and RFC 6376 syntax rules exactly
 * @param {Array} [opts.warnings] Lax acceptance markers are added here
 * @returns {Array|false} The ARC sets ordered by instance, or false if there are none. Throws
 *          for a chain that is not valid
 */
const getARChain = (headers, opts) => {
    opts = opts || {};
    const strict = !!opts.strict;
    const warn = warning => {
        if (Array.isArray(opts.warnings)) {
            addWarning(opts.warnings, warning);
        }
    };

    let headerRows = (headers && headers.parsed) || [];

    let arcChain = new Map();
    for (let row of headerRows) {
        if (ARC_HEADER_KEYS.includes(row.key)) {
            // RFC 6376 section 3.2: "Tags MUST be interpreted in a case-sensitive manner", so
            // the strict mode keys the tags of the ARC-Seal and ARC-Message-Signature by name
            // as written
            let value = parseDkimHeaders(row.line, { strict });

            let rawInstance = getRawInstance(row.key, value, row.line);
            let validInstance =
                typeof rawInstance === 'string' && INSTANCE_VALUE.test(rawInstance) && Number(rawInstance) >= 1 && Number(rawInstance) <= MAX_ARC_INSTANCE;

            let instance;
            if (strict) {
                if (!validInstance) {
                    // RFC 8617 section 3.9, instance = "i=" 1*2DIGIT, 1 to 50. A header field
                    // with any other instance is not part of a valid chain
                    throw createError(`invalid ${SHORT_NAMES[row.key]} instance`, 'invalid_arc_instance');
                }
                instance = Number(rawInstance);
            } else {
                // the lenient mode reads the instance as a number, and ignores ARC header
                // fields that have none
                instance = value?.parsed?.i?.value;
                if (!validInstance) {
                    warn('arc-instance-syntax');
                }
            }

            if (instance) {
                if (!arcChain.has(instance)) {
                    arcChain.set(instance, {
                        i: instance
                    });
                } else if (arcChain.get(instance)[row.key]) {
                    // value for this header is already set
                    throw createError(`i=${instance} multiple ${row.key} values`, 'multiple_arc_keys');
                }
                arcChain.get(instance)[row.key] = value;
            }
        }
    }

    arcChain = Array.from(arcChain.values()).sort((a, b) => a.i - b.i);
    if (!arcChain.length) {
        // empty chain
        return false;
    }

    if (arcChain.length > MAX_ARC_INSTANCE) {
        throw createError(`chain-length=${arcChain.length}`, 'invalid_arc_count');
    }

    for (let i = 0; i < arcChain.length; i++) {
        const arcInstance = arcChain[i];
        const isNewest = i === arcChain.length - 1;

        if (arcInstance.i !== i + 1) {
            // not a complete sequence
            throw createError(`i=${arcInstance.i} expected=${i + 1}`, 'invalid_arc_instance');
        }

        for (let headerKey of ARC_HEADER_KEYS) {
            if (!arcInstance[headerKey]) {
                // missing required header
                throw createError(`i=${arcInstance.i} no ${headerKey} set`, 'missing_arc_header');
            }
        }

        // Every seal is validated, so the syntax of every seal counts. Only the newest
        // ARC-Message-Signature is validated (step 4), the older ones are just sealed data
        checkTagList(arcInstance, 'arc-seal', strict, warn);
        if (isNewest) {
            checkTagList(arcInstance, 'arc-message-signature', strict, warn);
        }

        let cv = getCv(arcInstance);

        if (i === 0 && cv !== 'none') {
            throw createError(`i=1 cv="${arcInstance['arc-seal']?.parsed?.cv?.value}`, 'invalid_cv_value');
        }

        // c= is not checked here. An ARC-Seal has no c= tag (RFC 8617 section 4.1.3, it always
        // uses relaxed header canonicalization), so a c= tag on it is an unknown tag, and
        // unknown tags are ignored (RFC 6376 section 3.2). The newest ARC-Message-Signature is
        // verified by the DKIM verifier, where a missing c= means simple/simple (RFC 6376
        // section 3.5) and the lenient mode also tries relaxed/relaxed

        if (arcInstance['arc-seal']?.parsed?.a && !arcInstance['arc-seal']?.parsed?.a?.value) {
            throw createError(`i=${arcInstance.i} empty a`, 'invalid_a_value');
        }

        if (!arcInstance['arc-seal']?.parsed?.a?.value) {
            throw createError(`i=${arcInstance.i} missing a`, 'missing_a_value');
        }

        // throws if using non-supported algorithm
        validateAlgorithm(arcInstance['arc-seal']?.parsed?.a?.value, true);
        validateAlgorithm(arcInstance['arc-message-signature']?.parsed?.a?.value, true);

        if (i > 0 && cv !== 'pass') {
            throw createError(`i=${arcInstance.i} cv=${arcInstance['arc-seal']?.parsed?.cv?.value}`, 'invalid_cv_value');
        }

        if (arcInstance['arc-seal']?.parsed?.h) {
            throw createError(`i=${arcInstance.i} unexpected as h`, 'unexpected_as_h_value');
        }

        let amsH = arcInstance['arc-message-signature']?.parsed?.h?.value
            ?.toString()
            .trim()
            .toLowerCase()
            .split(':')
            .map(v => v.trim())
            .filter(v => v);

        if (amsH?.some(v => v === 'arc-seal')) {
            throw createError(`i=${arcInstance.i} invalid ams h`, 'invalid_ams_h_value');
        }
    }

    return arcChain;
};

// {chain, last}
const arc = async (data, opts) => {
    opts = opts || {};
    const strict = !!opts.strict;

    const status = {
        result: 'none'
    };

    const result = { status };

    Object.defineProperty(result, 'chain', {
        enumerable: false,
        configurable: false,
        writable: false,
        value: data.chain
    });

    // what the lenient mode accepted that the strict mode would have rejected
    const warnings = [].concat(data?.warnings || []);

    try {
        if (data.error) {
            // raise error from `getARChain`
            throw data.error;
        }

        let hasChain = await verifyASChain(data, {
            resolver: opts.resolver,
            minBitLength: opts.minBitLength,
            strict,
            warnings,
            // the key lookups of the DKIM verifier, when they used the same resolver
            keyCache: data.keyCache?.resolver === opts.resolver ? data.keyCache : undefined
        });

        if (hasChain) {
            result.i = data?.lastEntry?.i || false;
            result.signature = data?.lastEntry?.messageSignature || false;

            if (result?.signature?.status?.result !== 'pass') {
                // no valid ARC-Message-Signature found
                throw createError(`i=${result.i} no valid signature`, 'missing_valid_ams');
            }

            addWarning(warnings, ...(result.signature.status.warnings || []));

            result.authenticationResults = data?.lastEntry?.['arc-authentication-results']?.parsed;

            if (result.authenticationResults) {
                delete result.authenticationResults.i;
                delete result.authenticationResults.header;

                if (result.authenticationResults.value) {
                    let mta = result.authenticationResults.value;
                    delete result.authenticationResults.value;
                    result.authenticationResults = Object.assign({ mta }, result.authenticationResults);
                }

                ['arc', 'spf', 'dmarc'].forEach(key => {
                    if (result.authenticationResults[key]) {
                        let res = result.authenticationResults[key].value;
                        delete result.authenticationResults[key].value;
                        result.authenticationResults[key] = Object.assign({ result: res }, result.authenticationResults[key]);
                    }
                });

                if (result.authenticationResults.dkim && result.authenticationResults.dkim.length) {
                    result.authenticationResults.dkim = result.authenticationResults.dkim.map(entry => {
                        let result = entry.value;
                        delete entry.value;
                        return Object.assign({ result }, entry);
                    });
                }
            }

            status.result = 'pass';
        } else {
            result.i = 0;
            status.result = 'none';
        }
    } catch (err) {
        // all failures are permanent in the scope of ARC
        result.i = data?.lastEntry?.i || false;
        status.result = 'fail';
        // if last entry was listed as passing then add our seal even if the validation failed
        status.shouldSeal = ['pass', 'none'].includes(getCv(data?.lastEntry));

        switch (err.code) {
            case 'invalid_arc_seal':
            case 'failing_arc_seal':
            case 'multiple_arc_keys':
            case 'invalid_arc_count':
            case 'invalid_arc_instance':
            case 'missing_arc_header':
            case 'invalid_cv_value':
            case 'unexpected_as_h_value':
            case 'invalid_ams_h_value':
            case 'missing_valid_ams':
            case 'invalid_arc_tags':
                status.comment = err.message
                    .toLowerCase()
                    .replace(/["'()]/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim()
                    .substr(0, 128);
                break;

            case 'ENOTFOUND':
            case 'ENODATA':
            case 'EINVALIDVER':
            case 'EINVALIDTYPE':
            case 'EINVALIDVAL':
            case 'EINVALIDHASH':
            case 'EINVALIDSERVICE':
                if (err.queryDomain) {
                    status.comment = `${KEY_ERROR_COMMENTS.get(err.code)} for ${err.queryDomain}`;
                }
                break;

            case 'EINVALIDKEYALGO':
                if (err.queryDomain) {
                    status.comment = `inappropriate key algorithm for ${err.queryDomain}`;
                }
                break;

            case 'ESHORTKEY':
                status.policy = { 'dkim-rules': 'weak-key' };
                if (err.queryDomain) {
                    status.comment = `weak key for ${err.queryDomain}`;
                }
                break;
        }
    }

    if (strict && opts.ip && isIP(opts.ip.toString())) {
        // RFC 8617 section 6: smtp.remote-ip SHOULD be recorded
        status.smtp = { 'remote-ip': opts.ip.toString() };
    }

    // The strict mode reports arc=none as well (RFC 8617 section 5.2 step 1 and section 6), the
    // lenient mode leaves it out of the Authentication-Results header as it always has
    if (status.result !== 'none' || strict) {
        if (status.result === 'pass' && result.authenticationResults) {
            let comment = [`i=${result.i}`, result.authenticationResults.spf ? `spf=${result.authenticationResults.spf.result}` : false];

            if (result.authenticationResults.dkim && result.authenticationResults.dkim.length) {
                for (let entry of result.authenticationResults.dkim) {
                    comment.push(`dkim=${entry.result}`);
                    // a crafted dotted key (header.i.x=1) parses into an object, not a string
                    if (typeof entry?.header?.i === 'string') {
                        comment.push(`dkdomain=${entry.header.i.replace(/^@/, '')}`);
                    }
                }
            }

            if (result.authenticationResults.dmarc) {
                comment.push(`dmarc=${result.authenticationResults.dmarc.result}`);
                if (typeof result.authenticationResults.dmarc?.header?.from === 'string') {
                    comment.push(`fromdomain=${result.authenticationResults.dmarc.header.from}`);
                }
            }

            status.comment = comment.filter(v => v).join(' ');
        }

        result.info = formatAuthHeaderRow('arc', status, { strict });
    }

    if (warnings.length && status.result !== 'fail') {
        // never rendered into the Authentication-Results header
        result.warnings = warnings;
    }

    return result;
};

const sealError = (seal, err) => ({
    type: 'ARC',
    selector: seal?.selector,
    signingDomain: seal?.signingDomain,
    err
});

// whether an option has a value, false and an empty string mean that it is not set
const isSet = value => typeof value !== 'undefined' && value !== null && value !== false && value !== '';

/**
 * Creates an ARC set (RFC 8617 section 5.1) for a message
 *
 * @param {ReadableStream|Buffer|String|false} input The message, or false to use `data.headers`
 *        and `seal.bodyHash` instead
 * @param {Object} data { headers, arc, seal, strict }
 * @returns {Object} { headers, errors, warnings }. `headers` is empty when no set was created,
 *          and `errors` says why
 */
const createSeal = async (input, data) => {
    let { headers, arc } = data;
    // a copy, the instance chosen below is stored on it and the caller's object, which may be
    // reused for the next message, stays unchanged
    let seal = Object.assign({}, data.seal);
    let bodyHash = seal?.bodyHash;

    const strict = !!(data.strict || seal?.strict);
    const warnings = [];
    const warn = warning => addWarning(warnings, warning);

    let dkimSigner;
    // the signer's warnings first, then the ones of the seal, each listed once
    const collectWarnings = () => addWarning([].concat(dkimSigner?.warnings || []), ...warnings);

    const refuse = (message, code) => ({ headers: [], errors: [sealError(seal, createError(message, code))], warnings: collectWarnings() });

    // Caller input that can only produce an ARC set every validator rejects is refused in
    // every mode
    let explicitInstance = isSet(seal.i);
    if (explicitInstance) {
        let instance = Number(seal.i);
        if (!Number.isInteger(instance) || instance < 1 || instance > MAX_ARC_INSTANCE) {
            // RFC 8617 section 4.2.1, instance values range from 1 to 50
            return refuse(`ARC instance ${JSON.stringify(seal.i)} is out of range (1-${MAX_ARC_INSTANCE})`, 'EINVALIDINSTANCE');
        }
        seal.i = instance;
    }

    let cv = false;
    if (isSet(seal.cv)) {
        cv = seal.cv.toString().toLowerCase().trim();
        if (!CHAIN_STATUS.includes(cv)) {
            return refuse(`Invalid cv value ${JSON.stringify(seal.cv)} (expecting "none", "pass" or "fail")`, 'EINVALIDCV');
        }
    }

    let algorithm = false;
    if (seal.algorithm) {
        algorithm = seal.algorithm.toString().toLowerCase().trim();
        try {
            // rsa-sha256 or ed25519-sha256, no validator accepts an ARC signature made with sha1
            validateAlgorithm(algorithm, true);
        } catch (err) {
            return refuse(`Unsupported ARC algorithm ${JSON.stringify(seal.algorithm)}`, 'EINVALIDALGO');
        }
    }

    // RFC 8617 section 4.1.1, the payload of the ARC-Authentication-Results header. A line break
    // is only allowed as folding (CRLF followed by whitespace and more content), anything else
    // would start a new header field or end the header block
    let authResults = isSet(seal.authResults) ? String(seal.authResults) : '';
    if (!/\S/.test(authResults)) {
        return refuse('The authResults value for the ARC-Authentication-Results header is missing', 'EINVALIDAUTHRESULTS');
    }
    if (!/^(?:[^\r\n]|\r\n[ \t]+[^ \t\r\n])*$/.test(authResults)) {
        return refuse('The authResults value contains a line break that is not header folding', 'EINVALIDAUTHRESULTS');
    }

    // Step 1. Calculate ARC-Message-Signature
    dkimSigner = new DkimSigner({
        // headers and bodyHash are prepared values if we do not have the source message anymore
        headers,
        bodyHash: seal.bodyHash,

        signTime: seal.signTime,

        // which headers to sign
        headerList: seal.headerList,

        strict,

        arc: {
            instance: seal.i,
            // follows the key type when not set
            algorithm,
            signingDomain: seal.signingDomain,
            selector: seal.selector,
            privateKey: seal.privateKey
        },

        getARChain, // pass as a property so we do not have to use circular require()

        // a set without an explicit instance follows the highest existing one, the same
        // value is used for the ARC-Seal below
        getArcInstance: hdrs => getArcPosition(hdrs, (arc || dkimSigner.arc)?.chain).highest + 1
    });

    if (input) {
        await writeToStream(dkimSigner, input);

        let { hashAlgo } = dkimSigner.getAlgorithm(seal);
        let { bodyCanon } = dkimSigner.getCanonicalization(seal);

        let hashKey = `${bodyCanon}:${hashAlgo}:`;

        bodyHash = dkimSigner.bodyHashes.get(hashKey)?.hash;

        headers = dkimSigner.headers;
        arc = arc || dkimSigner.arc;
    } else {
        // this gives us dkimSigner.arc.messageSignature
        await dkimSigner.finalize();
    }

    let { highest, latestCv } = getArcPosition(headers, arc?.chain);

    if (!explicitInstance) {
        if (highest >= MAX_ARC_INSTANCE) {
            // RFC 8617 section 4.2.1, instance values range from 1 to 50. A 51st set would make
            // the whole chain invalid for every validator, so the message is not sealed
            return refuse(`Can not add ARC set i=${highest + 1}, the chain already has ${highest} sets`, 'EINVALIDINSTANCE');
        }
        seal.i = highest + 1;
    }

    // RFC 8617 section 5.1 step 2: a chain whose newest seal says cv=fail is not sealed again
    if (latestCv === 'fail') {
        return refuse(`The newest ARC-Seal (i=${highest}) has cv=fail, the chain can not be sealed again`, 'EARCCHAINFAILED');
    }

    // RFC 8617 section 5.1 step 3: the next instance follows the highest existing one
    if (seal.i <= highest) {
        // a second set with the same instance makes the whole chain invalid
        return refuse(`ARC instance ${seal.i} already exists on the message (highest instance ${highest})`, 'EINVALIDINSTANCE');
    }

    if (seal.i !== highest + 1) {
        // an explicit instance that leaves a gap, which no validator accepts
        if (strict) {
            return refuse(`ARC instance ${seal.i} does not follow the highest existing instance ${highest}`, 'EINVALIDINSTANCE');
        }
        warn('arc-instance-gap');
    }

    if (!cv) {
        if (seal.i !== 1) {
            // there is no way to tell here whether the chain validated
            return refuse(`A cv value is required for ARC instance ${seal.i}`, 'EINVALIDCV');
        }
        // RFC 8617 section 4.4, there was no chain
        cv = 'none';
    }

    if ((seal.i === 1) !== (cv === 'none')) {
        // RFC 8617 section 5.2 step 3.C: cv=none for i=1, pass or fail for every later set
        if (strict) {
            return refuse(`cv=${cv} is not valid for ARC instance ${seal.i}`, 'EINVALIDCV');
        }
        warn('arc-cv-instance');
    }

    if (cv === 'pass' && seal.i > 1 && !arc?.chain?.length) {
        // a cv=pass seal signs the whole chain (RFC 8617 section 5.1.1), and there is no valid
        // chain on the message to sign
        return refuse(`cv=pass needs a valid ARC chain to seal`, 'EINVALIDCV');
    }

    const messageSignature = dkimSigner.arc?.messageSignature;
    if (!messageSignature) {
        // The ARC-Message-Signature is missing whenever signing it failed, an unusable key
        // being the usual reason. There is no ARC set to seal then: sealing anyway hashes
        // a header that does not exist and puts an empty line into the header block, which
        // ends it early for everything downstream
        return { headers: [], errors: dkimSigner.errors, warnings: collectWarnings() };
    }

    const authResultsHeader = `ARC-Authentication-Results: i=${seal.i}; ${authResults}`;

    // the ARC-Seal uses the algorithm of the ARC-Message-Signature, which follows the key type
    // when no algorithm was given
    let sealAlgorithm = (parseDkimHeaders(messageSignature)?.parsed?.a?.value || algorithm || 'rsa-sha256').toString().toLowerCase();

    // Step 2. Calculate ARC-Seal
    let arcSeal;
    try {
        arcSeal = await signAS(
            arc?.chain || [],
            {
                'arc-authentication-results': authResultsHeader,
                'arc-message-signature': messageSignature
            },
            {
                instance: seal.i,
                algorithm: sealAlgorithm,
                signingDomain: seal.signingDomain,
                selector: seal.selector,
                bodyHash,
                cv,
                signTime: seal.signTime,
                privateKey: seal.privateKey
            }
        );
    } catch (err) {
        return { headers: [], errors: dkimSigner.errors.concat(sealError(seal, err)), warnings: collectWarnings() };
    }

    return {
        headers: [arcSeal, messageSignature, authResultsHeader],
        errors: dkimSigner.errors,
        warnings: collectWarnings()
    };
};

const sealMessage = async (input, seal) => {
    const { headers } = await createSeal(input, { seal });
    return headers.length ? Buffer.from(headers.join('\r\n') + '\r\n') : Buffer.from('');
};

module.exports = { getARChain, verifyASChain, arc, createSeal, sealMessage };
