/* eslint no-control-regex: 0 */

'use strict';

const { Buffer } = require('node:buffer');
const punycode = require('punycode.js');
const libmime = require('libmime');
const dns = require('node:dns').promises;
const crypto = require('node:crypto');
const https = require('node:https');
const packageData = require('../package');
const parseDkimHeaders = require('./parse-dkim-headers');
const tldts = require('tldts');
const Joi = require('joi');
const base64Schema = Joi.string().base64({ paddingRequired: false });

const defaultDKIMFieldNames =
    'From:Sender:Reply-To:Subject:Date:Message-ID:To:' +
    'Cc:MIME-Version:Content-Type:Content-Transfer-Encoding:Content-ID:' +
    'Content-Description:Resent-Date:Resent-From:Resent-Sender:' +
    'Resent-To:Resent-Cc:Resent-Message-ID:In-Reply-To:References:' +
    'List-Id:List-Help:List-Unsubscribe:List-Subscribe:List-Post:' +
    'List-Owner:List-Archive:BIMI-Selector';

const defaultARCFieldNames = `DKIM-Signature:Delivered-To:${defaultDKIMFieldNames}`;
const defaultASFieldNames = `ARC-Authentication-Results:ARC-Message-Signature:ARC-Seal`;

const keyOrderingDKIM = ['v', 'a', 'c', 'd', 'h', 'i', 'l', 'q', 's', 't', 'x', 'z', 'bh', 'b'];
const keyOrderingARC = ['i', 'a', 'c', 'd', 'h', 'l', 'q', 's', 't', 'x', 'z', 'bh', 'b'];
const keyOrderingAS = ['i', 'a', 't', 'cv', 'd', 's', 'b'];

const TLDTS_OPTS = {
    allowIcannDomains: true,
    allowPrivateDomains: true
};

const writeToStream = async (stream, input, chunkSize) => {
    chunkSize = chunkSize || 64 * 1024;

    if (typeof input === 'string') {
        input = Buffer.from(input);
    }

    return new Promise((resolve, reject) => {
        if (typeof input.on === 'function') {
            // pipe as stream
            input.pipe(stream);
            input.on('error', reject);
        } else {
            let pos = 0;
            let writeChunk = () => {
                if (pos >= input.length) {
                    return stream.end();
                }

                let chunk;
                if (pos + chunkSize >= input.length) {
                    chunk = input.slice(pos);
                } else {
                    chunk = input.slice(pos, pos + chunkSize);
                }
                pos += chunk.length;

                if (stream.write(chunk) === false) {
                    stream.once('drain', () => writeChunk());
                    return;
                }
                setImmediate(writeChunk);
            };
            setImmediate(writeChunk);
        }

        stream.on('end', resolve);
        stream.on('finish', resolve);
        stream.on('error', reject);
    });
};

// Lowercases a 'binary' string the way RFC 6376 section 3.4.2 means it. String.prototype
// toLowerCase() is Unicode aware and maps the latin1 bytes 0xC0-0xDE to 0xE0-0xFE, which
// corrupts a UTF-8 sequence and folds two distinct header names onto one. Only a string
// that has such a byte needs the slower per character mapping
const NON_ASCII = /[^\x00-\x7f]/;
const lowerCaseASCII = str => (NON_ASCII.test(str) ? str.replace(/[A-Z]/g, c => c.toLowerCase()) : str.toLowerCase());

// RFC 5322 section 3.6.8: field-name = 1*ftext, and ftext is printable US-ASCII except
// the colon. A fold, and the obsolete syntax of section 4.5.8, may put whitespace between
// the name and the colon
const FIELD_START = /^[\x21-\x39\x3b-\x7e]+[ \t\r\n]*:/;

// Whether a row opens a header of its own. Anything else is appended to the row above,
// which is wider than the CRLF-then-WSP fold of RFC 5322 section 2.2.3 and deliberately
// so: a line that is not a well formed field is read differently by different parsers,
// and mailauth's own libmime, like most MUAs, appends any line it calls whitespace to the
// value above it. Asking what a field looks like instead of what whitespace looks like
// covers every spelling of it, including the multi-byte ones a leading byte test misses,
// such as UTF-8 NBSP (C2 A0) and the ideographic space (E3 80 80). Appending a line can
// only add bytes to a signed value, so it can only ever turn a pass into a fail; reading
// the line the other way round is what cannot be undone. formatRelaxedLine is not lenient
// in the same way, what a signature covers is RFC 6376 section 3.4.2 alone
const startsField = row =>
    // only the start of the row decides this, and a fold can push the colon no further
    // than onto the line after the name
    FIELD_START.test(row.length > 1 ? `${row[0]}\r\n${row[1]}` : row[0]);

const parseHeaders = buf => {
    let rows = buf
        .toString('binary')
        .replace(/[\r\n]+$/, '')
        .split(/\r?\n/)
        .map(row => [row]);

    if (rows.length === 1 && !rows[0][0]) {
        // nothing to parse, rather than one row that is not a header
        return { parsed: [], original: buf };
    }

    for (let i = rows.length - 1; i > 0; i--) {
        if (!startsField(rows[i])) {
            rows[i - 1] = rows[i - 1].concat(rows[i]);
            rows.splice(i, 1);
        }
    }

    rows = rows.map(row => {
        row = row.join('\r\n');
        let key = row.match(/^[^:]+/);
        let casedKey;
        if (key) {
            // a fold may sit between the field name and the colon, and the CRLF it leaves
            // behind is not part of the name. Without this the key of a header folded that
            // way matches nothing, and a From read by every MUA stops being a From here
            casedKey = key[0];
            if (casedKey.indexOf('\n') >= 0) {
                casedKey = casedKey.replace(/\r?\n/g, '');
            }
            casedKey = casedKey.replace(/^[ \t]+|[ \t]+$/g, '');
            key = lowerCaseASCII(casedKey);
        }

        return { key, casedKey, line: Buffer.from(row, 'binary') };
    });

    return { parsed: rows, original: buf };
};

// Normalizes an h= tag, or a configured header list, exactly as parseHeaders normalizes a
// field name. Anything else and an entry names a key no parsed row can ever equal
const normalizeFieldNames = fieldNames =>
    fieldNames
        .split(':')
        .map(key => lowerCaseASCII(key.replace(/^[ \t]+|[ \t]+$/g, '')))
        .filter(key => key);

const defaultDKIMFieldNamesNormalized = normalizeFieldNames(defaultDKIMFieldNames);

const getSigningHeaderLines = (parsedHeaders, fieldNames, verify) => {
    // an h= tag is attacker controlled on inbound mail, so only the constant default list
    // is normalized ahead of time
    fieldNames = typeof fieldNames === 'string' ? normalizeFieldNames(fieldNames) : defaultDKIMFieldNamesNormalized;

    let signingList = [];

    if (verify) {
        let parsedList = [].concat(parsedHeaders);
        for (let fieldName of fieldNames) {
            for (let i = parsedList.length - 1; i >= 0; i--) {
                let header = parsedList[i];
                if (fieldName === header.key) {
                    signingList.push(header);
                    parsedList.splice(i, 1);
                    break;
                }
            }
        }
    } else {
        for (let i = parsedHeaders.length - 1; i >= 0; i--) {
            let header = parsedHeaders[i];
            if (fieldNames.includes(header.key)) {
                signingList.push(header);
            }
        }
    }

    return {
        keys: signingList.map(entry => entry.casedKey).join(': '),
        headers: signingList
    };
};

/**
 * Generates `DKIM-Signature: ...` header for selected values
 * @param {Object} values
 */
const formatSignatureHeaderLine = (type, values, folded) => {
    type = (type || '').toString().toUpperCase();

    let keyOrdering, headerKey;
    switch (type) {
        case 'DKIM':
            headerKey = 'DKIM-Signature';
            keyOrdering = keyOrderingDKIM;
            values = Object.assign(
                {
                    v: 1,
                    t: Math.floor(Date.now() / 1000),
                    q: 'dns/txt'
                },
                values
            );
            break;

        case 'ARC':
            headerKey = 'ARC-Message-Signature';
            keyOrdering = keyOrderingARC;
            values = Object.assign(
                {
                    t: Math.floor(Date.now() / 1000),
                    q: 'dns/txt'
                },
                values
            );
            break;

        case 'AS':
            headerKey = 'ARC-Seal';
            keyOrdering = keyOrderingAS;
            values = Object.assign(
                {
                    t: Math.floor(Date.now() / 1000)
                },
                values
            );
            break;

        default:
            throw new Error('Unknown Signature type');
    }

    const header =
        `${headerKey}: ` +
        Object.keys(values)
            .filter(key => values[key] !== false && typeof values[key] !== 'undefined' && values[key] !== null && keyOrdering.includes(key))
            .sort((a, b) => keyOrdering.indexOf(a) - keyOrdering.indexOf(b))
            .map(key => {
                // the filter above already dropped false, null and undefined, so a falsy
                // value left here is a meaningful one. `l=0` is a valid sig-l-tag (RFC 6376
                // section 3.5, 1*76DIGIT) and must not be serialized as a valueless `l=`
                let val = values[key];
                if (key === 'b' && folded && val) {
                    // fold signature value
                    return `${key}=${val}`.replace(/.{75}/g, '$& ').trim();
                }

                if (['d', 's'].includes(key)) {
                    try {
                        // convert to A-label if needed
                        val = punycode.toASCII(val);
                    } catch (err) {
                        // ignore
                    }
                }

                if (key === 'i' && type === 'DKIM') {
                    val = val.toString();
                    let atPos = val.indexOf('@');
                    if (atPos >= 0) {
                        let domainPart = val.substr(atPos + 1);
                        try {
                            // convert to A-label if needed
                            domainPart = punycode.toASCII(domainPart);
                        } catch (err) {
                            // ignore
                        }
                        val = val.substr(0, atPos + 1) + domainPart;
                    }
                }

                return `${key}=${val}`;
            })
            .join('; ');

    if (folded) {
        return libmime.foldLines(header);
    }

    return header;
};

const getPublicKey = async (type, name, minBitLength, resolver) => {
    minBitLength = minBitLength || 1024;
    resolver = resolver || dns.resolve;

    let list = await resolver(name, 'TXT');
    let rr =
        list &&
        []
            .concat(list[0] || [])
            .join('')
            .replace(/\s+/g, '');

    if (rr) {
        // prefix value for parsing as there is no default value
        let entry = parseDkimHeaders(`DNS: TXT;${rr}`);

        const publicKeyValue = entry?.parsed?.p?.value;
        if (!publicKeyValue) {
            let err = new Error('Missing key value');
            err.code = 'EINVALIDVAL';
            err.rr = rr;
            throw err;
        }

        let validation = base64Schema.validate(publicKeyValue);
        if (validation.error) {
            let err = new Error('Invalid base64 format for public key');
            err.code = 'EINVALIDVAL';
            err.rr = rr;
            err.details = validation.error;
            throw err;
        }

        if (type === 'DKIM' && entry?.parsed?.v && (entry?.parsed?.v?.value || '').toString().toLowerCase().trim() !== 'dkim1') {
            let err = new Error('Unknown key version');
            err.code = 'EINVALIDVER';
            err.rr = rr;
            throw err;
        }

        let paddingNeeded = publicKeyValue.length % 4 ? 4 - (publicKeyValue.length % 4) : 0;
        let paddedPublicKey = publicKeyValue + '='.repeat(paddingNeeded);

        let rawPublicKey = Buffer.from(publicKeyValue, 'base64');
        let publicKeyObj;
        let publicKeyOpts;

        if (rawPublicKey.length === 32) {
            // seems like an ed25519 key
            rawPublicKey = Buffer.concat([Buffer.from('302A300506032B6570032100', 'hex'), rawPublicKey]);
            publicKeyOpts = {
                key: rawPublicKey,
                format: 'der',
                type: 'spki'
            };
        } else {
            const publicKeyPem = Buffer.from(`-----BEGIN PUBLIC KEY-----\n${paddedPublicKey.replace(/.{64}/g, '$&\n').trim()}\n-----END PUBLIC KEY-----`);
            publicKeyOpts = {
                key: publicKeyPem,
                format: 'pem'
            };
        }

        try {
            publicKeyObj = crypto.createPublicKey(publicKeyOpts);
        } catch (err) {
            let error = new Error('Unknown key type (${keyType})', { cause: err });
            error.code = 'EINVALIDTYPE';
            error.rr = rr;
            throw error;
        }

        let keyType = publicKeyObj.asymmetricKeyType;

        if (!['rsa', 'ed25519'].includes(keyType) || (entry?.parsed?.k && entry?.parsed?.k?.value?.toLowerCase() !== keyType)) {
            let err = new Error('Unknown key type (${keyType})');
            err.code = 'EINVALIDTYPE';
            err.rr = rr;
            throw err;
        }

        let modulusLength = publicKeyObj.asymmetricKeyDetails.modulusLength;

        if (keyType === 'rsa' && modulusLength < minBitLength) {
            let err = new Error('RSA key too short');
            err.code = 'ESHORTKEY';
            err.rr = rr;
            throw err;
        }

        return {
            publicKey: publicKeyObj.export({
                type: publicKeyObj.asymmetricKeyType === 'ed25519' ? 'spki' : 'pkcs1',
                format: 'pem'
            }),
            rr,
            modulusLength
        };
    }

    let err = new Error('Missing key value');
    err.code = 'EINVALIDVAL';
    throw err;
};

const getPrivateKey = privateKeyBuf => {
    let privateKeyOpts;

    if (typeof privateKeyBuf === 'string') {
        privateKeyBuf = Buffer.from(privateKeyBuf);
    }

    if (privateKeyBuf.length === 32) {
        // seems like a raw ed25519 key
        privateKeyBuf = Buffer.concat([Buffer.from('MC4CAQAwBQYDK2VwBCIEIA==', 'base64'), privateKeyBuf]);
        privateKeyOpts = {
            key: privateKeyBuf,
            format: 'der',
            type: 'pkcs8'
        };
    } else {
        privateKeyOpts = { key: privateKeyBuf, format: 'pem' };
    }

    return crypto.createPrivateKey(privateKeyOpts);
};

const fetch = url =>
    new Promise((resolve, reject) => {
        https
            .get(
                url,
                {
                    headers: {
                        'User-Agent': `mailauth/${packageData.version} (+${packageData.homepage}`
                    }
                },
                res => {
                    let chunks = [];
                    let chunklen = 0;
                    res.on('readable', () => {
                        let chunk;
                        while ((chunk = res.read()) !== null) {
                            chunks.push(chunk);
                            chunklen += chunk.length;
                        }
                    });

                    res.on('end', () => {
                        resolve({
                            statusCode: res.statusCode,
                            headers: res.headers,
                            body: Buffer.concat(chunks, chunklen)
                        });
                    });
                }
            )
            .on('error', reject);
    });

const escapePropValue = value => {
    value = (value || '')
        .toString()
        .replace(/[\x00-\x1F]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

    if (!/[\s\x00-\x1F\x7F-\uFFFF()<>,;:\\"/[\]?=]/.test(value)) {
        // return token value
        return value;
    }

    // return quoted string with escaped quotes
    return `"${value.replace(/["\\]/g, c => `\\${c}`)}"`;
};

const escapeCommentValue = value => {
    value = (value || '')
        .toString()
        .replace(/[\x00-\x1F]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

    return `${value.replace(/[\\)]/g, c => `\\${c}`)}`;
};

const formatAuthHeaderRow = (method, status) => {
    status = status || {};
    let parts = [];

    parts.push(`${method}=${status.result || 'none'}`);

    if (status.underSized) {
        parts.push(`(${escapeCommentValue(`undersized signature: ${status.underSized} bytes unsigned`)})`);
    }

    if (status.comment) {
        parts.push(`(${escapeCommentValue(status.comment)})`);
    }

    for (let ptype of ['policy', 'smtp', 'body', 'header']) {
        if (!status[ptype] || typeof status[ptype] !== 'object') {
            continue;
        }

        for (let prop of Object.keys(status[ptype])) {
            if (status[ptype][prop]) {
                parts.push(`${ptype}.${prop}=${escapePropValue(status[ptype][prop])}`);
            }
        }
    }

    return parts.join(' ');
};

// RFC 6376 section 3.4.2. Only SP and HTAB are whitespace here: the line is a
// 'binary' string, so a byte such as 0xA0 (the second byte of a UTF-8
// non-breaking space) must not be collapsed or trimmed
const formatRelaxedLine = (line, suffix) => {
    let result =
        // a missing line is nothing to canonicalize. Optional chaining would resolve the
        // whole chain to undefined and the concatenation below would then hash the
        // 9 byte string "undefined" as if it were a header
        (line || '')
            .toString('binary')
            // unfold
            .replace(/\r?\n/g, '')
            // key to lowercase, trim around :
            .replace(/^([^:]*):[ \t]*/, (m, k) => lowerCaseASCII(k).replace(/^[ \t]+|[ \t]+$/g, '') + ':')
            // single WSP
            .replace(/[ \t]+/g, ' ')
            // no WSP around the value
            .replace(/^ | $/g, '') + (suffix ? suffix : '');

    return Buffer.from(result, 'binary');
};

// RFC 6376 section 3.7: when the signature header is hashed, its own b= value is treated
// as empty. The tag can be preceded by WSP and, in a header that has not been unfolded
// yet, by the CRLF of a fold. Nothing else is whitespace here, for the same reason it is
// not in formatRelaxedLine: a byte such as 0xA0 in front of b= is content, and matching it
// would strip a decoy tag and leave the real signature inside the hashed header
const stripSignatureValue = line => Buffer.from(line.toString('binary').replace(/([;: \t\r\n]+b=)[^;]+/, '$1'), 'binary');

const formatDomain = domain => {
    domain = domain.toLowerCase().trim();
    try {
        domain = punycode.toASCII(domain).toLowerCase().trim();
    } catch (err) {
        // ignore punycode errors
    }
    // the root label is not part of the name, so "example.com." and "example.com" are the same domain
    return domain.replace(/\.+$/, '');
};

const getAlignment = (fromDomain, domainList, strict) => {
    // This argument used to be an options object. Every object is truthy, so a leftover
    // { strict: false } call would otherwise mean hard strict, the opposite of what it asks for.
    if (strict && typeof strict === 'object') {
        strict = strict.strict;
    }

    domainList = []
        .concat(domainList || [])
        .map(entry => {
            if (typeof entry === 'string') {
                return { domain: entry };
            }
            return entry;
        })
        .sort((a, b) => (a.underSized || 0) - (b.underSized || 0));

    if (strict) {
        // strict alignment: the domains must be identical (RFC 9989 §3.2.10.2)
        let from = formatDomain(fromDomain);
        if (!from) {
            // a bare root label normalizes to an empty string, which must not align with anything
            return false;
        }
        for (let entry of domainList) {
            if (formatDomain(entry.domain) === from) {
                return entry;
            }
        }
        return false;
    }

    // relaxed alignment: the domains must share an Organizational Domain (RFC 9989 §3.2.10.1)
    let fromOrg = formatDomain(tldts.getDomain(fromDomain, TLDTS_OPTS) || fromDomain);
    if (!fromOrg) {
        return false;
    }
    for (let entry of domainList) {
        let entryOrg = formatDomain(tldts.getDomain(entry.domain, TLDTS_OPTS) || entry.domain);
        if (entryOrg === fromOrg) {
            return entry;
        }
    }

    return false;
};

const validateAlgorithm = (algorithm, strict) => {
    try {
        if (!algorithm || !/^[^-]+-[^-]+$/.test(algorithm)) {
            throw new Error('Invalid algorithm format');
        }

        let [signAlgo, hashAlgo] = algorithm.toLowerCase().split('-');

        if (!['rsa', 'ed25519'].includes(signAlgo)) {
            let error = new Error('Unknown signing algorithm');
            error.signAlgo = signAlgo;
            throw error;
        }

        if (!['sha256'].concat(!strict ? 'sha1' : []).includes(hashAlgo)) {
            let error = new Error('Unknown hashing algorithm');
            error.hashAlgo = hashAlgo;
            throw error;
        }
    } catch (err) {
        err.code = 'EINVALIDALGO';
        throw err;
    }
};

const getPtrHostname = parsedAddr => {
    let bytes = parsedAddr.toByteArray();
    if (bytes.length === 4) {
        return `${bytes
            .map(a => a.toString(10))
            .reverse()
            .join('.')}.in-addr.arpa`;
    } else {
        return `${bytes
            .flatMap(a => a.toString(16).padStart(2, '0').split(''))
            .reverse()
            .join('.')}.ip6.arpa`;
    }
};

function getCurTime(timeValue) {
    if (timeValue) {
        if (typeof timeValue === 'object' && typeof timeValue.toISOString === 'function') {
            return timeValue;
        }

        // `curTime.toString` is the method, never the string, so the guard below used to
        // pass for every value and handed back an Invalid Date. That silently became a
        // NaN timestamp in a signature, and a comparison that is false either way in the
        // verifier, so an unparseable value falls back to the current time instead
        if (typeof timeValue === 'number' || !isNaN(timeValue)) {
            let timestamp = Number(timeValue);
            let curTime = new Date(timestamp);
            if (curTime.toString() !== 'Invalid Date') {
                return curTime;
            }
        } else if (typeof timeValue === 'string') {
            let curTime = new Date(timeValue);
            if (curTime.toString() !== 'Invalid Date') {
                return curTime;
            }
        }
    }

    return new Date();
}

function parseTagValueRecord(record, options = {}) {
    const {
        requiredTags = [],
        allowedTags = null, // null means allow all, array means restrict to these
        caseSensitive = false,
        strictMode = false, // if true, stops parsing on first malformed part
        allowDuplicateKeys = true // if false, treats duplicate keys as errors
    } = options;

    let sanitized = (record || '')
        .replace(/[\x00-\x1F]+/g, ' ') // control chars
        .replace(/\\r\\n/g, '')
        .replace(/\\n/g, '')
        .replace(/\r?\n/g, '')
        .replace(/\s+/g, ' ')
        .trim();

    // Split on semicolons
    const parts = sanitized.split(';');
    // no prototype, so that a tag named "__proto__" is stored as a normal key instead of
    // replacing the prototype, and so that "toString" and friends are not seen as already set
    const tags = Object.create(null);
    const validPairs = [];
    const errors = [];
    const warnings = [];

    for (let part of parts) {
        part = part.trim();
        if (!part) continue; // Skip empty parts

        // Look for tag=value pattern
        const equalIndex = part.indexOf('=');
        if (equalIndex === -1) {
            const error = `Malformed part (no equals sign): "${part}"`;
            errors.push(error);
            if (strictMode) break;
            continue;
        }

        let key = part.substring(0, equalIndex).trim();
        let value = part.substring(equalIndex + 1).trim();

        const normalizedKey = caseSensitive ? key : key.toLowerCase();

        // Validate key format (should be alphanumeric, may include hyphens/underscores)
        if (!/^[a-zA-Z0-9_-]+$/.test(key)) {
            const error = `Invalid tag name: "${key}"`;
            errors.push(error);
            if (strictMode) break;
            continue;
        }

        if (allowedTags && !allowedTags.includes(normalizedKey)) {
            warnings.push(`Unknown/disallowed tag ignored: "${key}"`);
            continue;
        }

        if (normalizedKey in tags) {
            if (!allowDuplicateKeys) {
                const error = `Duplicate tag not allowed: "${key}"`;
                errors.push(error);
                if (strictMode) break;
                continue;
            }

            if (Array.isArray(tags[normalizedKey])) {
                tags[normalizedKey].push(value);
            } else {
                tags[normalizedKey] = [tags[normalizedKey], value];
            }
            warnings.push(`Duplicate tag "${key}" found`);
        } else {
            tags[normalizedKey] = value;
        }

        validPairs.push([normalizedKey, value]);
    }

    for (const requiredTag of requiredTags) {
        const normalizedRequired = caseSensitive ? requiredTag : requiredTag.toLowerCase();
        if (!(normalizedRequired in tags)) {
            errors.push(`Missing required tag: "${requiredTag}"`);
        }
    }

    const sanitizedRecord = validPairs.map(([key, value]) => `${key}=${value}`).join('; ');

    return {
        tags,
        errors,
        warnings,
        isValid: errors.length === 0,
        sanitizedRecord,
        originalRecord: record
    };
}

function convertToASCII(value) {
    return (value || '').replace(/[^\x20-\x7E]/g, '');
}

function validateTagValueRecord(record, recordType) {
    const configs = {
        BIMI: {
            requiredTags: ['v', 'l', 'a'],
            allowedTags: ['v', 'l', 'a'],
            caseSensitive: false,
            strictMode: true,
            allowDuplicateKeys: false,
            validators: {
                v: value => (/^BIMI\d+$/i.test(value) ? null : `Version must match BIMI<digit>, got: ${value}`),
                l: value => {
                    if (!value.trim()) return 'Location cannot be empty';
                    try {
                        const url = new URL(value.trim());
                        return url.protocol !== 'https:' ? 'Location must use HTTPS protocol' : null;
                    } catch (e) {
                        return `Invalid location URL: ${value}`;
                    }
                },
                a: value => {
                    if (!value.trim()) return 'Authority cannot be empty';
                    try {
                        const url = new URL(value.trim());
                        return url.protocol !== 'https:' ? 'Authority must use HTTPS protocol' : null;
                    } catch (e) {
                        return `Invalid authority URL: ${value}`;
                    }
                }
            },
            mappers: {
                v: value => convertToASCII(value)
            }
        }
    };

    const config = configs[recordType.toUpperCase()];
    if (!config) {
        throw new Error(`Unknown record type: ${recordType}`);
    }

    const parsed = parseTagValueRecord(record, config);

    // Mappers run regardless whether the resulting parsed object is valid
    if (config.mappers) {
        for (const [tag, mapper] of Object.entries(config.mappers)) {
            if (parsed.tags && tag in parsed.tags) {
                parsed.tags[tag] = mapper(parsed.tags[tag]);
            }
        }
    }

    if (config.validators && parsed.isValid) {
        for (const [tag, validator] of Object.entries(config.validators)) {
            if (parsed.tags && tag in parsed.tags) {
                const validationError = validator(parsed.tags[tag]);
                if (validationError) {
                    parsed.errors.push(validationError);
                }
            }
        }
        parsed.isValid = parsed.errors.length === 0;
    }

    return parsed;
}

module.exports = {
    writeToStream,
    parseHeaders,

    defaultDKIMFieldNames,
    defaultARCFieldNames,
    defaultASFieldNames,

    getSigningHeaderLines,
    formatSignatureHeaderLine,
    parseDkimHeaders,
    getPublicKey,
    getPrivateKey,
    formatAuthHeaderRow,
    escapeCommentValue,
    fetch,

    validateAlgorithm,

    getAlignment,

    formatRelaxedLine,
    stripSignatureValue,
    formatDomain,

    getPtrHostname,

    getCurTime,

    TLDTS_OPTS,

    validateTagValueRecord,
    parseTagValueRecord,
    convertToASCII
};
