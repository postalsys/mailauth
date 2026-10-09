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
const { parseTagList } = parseDkimHeaders;
const tldts = require('tldts');
const Joi = require('joi');
const { DOMAIN_NAME } = require('./dkim/syntax');
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
    allowPrivateDomains: true,
    // the input is a host name, not a URL. Otherwise "example.com/x.example.net" would be read
    // as the URL of the host "example.com"
    extractHostname: false
};

/**
 * Converts the U-labels of a domain name to A-labels (RFC 5890 section 2.3.2.1). Only the
 * labels that have non-ASCII characters in them are touched: they are normalized to NFC and
 * lower cased first, because the Punycode encoding of an upper case letter is a different
 * label than the encoding of its lower case form, and IDNA2008 has no upper case U-labels.
 * ASCII labels are returned as they are, so a value that is already an A-label (or plain
 * ASCII) never changes.
 *
 * @param {String} domain Domain name
 * @returns {String} Domain name with A-labels, or the input if it can not be converted
 */
const toALabel = domain => {
    domain = (domain || '').toString();
    if (!NON_ASCII.test(domain)) {
        return domain;
    }

    return domain
        .split('.')
        .map(label => {
            if (!NON_ASCII.test(label)) {
                return label;
            }
            try {
                return punycode.toASCII(label.normalize('NFC').toLowerCase());
            } catch (err) {
                return label;
            }
        })
        .join('.');
};

// lower case A-label form of a domain without the root dot, for comparing domains
const normalizeDomainName = domain =>
    toALabel((domain || '').toString().trim())
        .toLowerCase()
        .replace(/\.$/, '');

// Whether `child` is `parent` or one of its subdomains
const isSameOrSubdomain = (child, parent) => {
    child = normalizeDomainName(child);
    parent = normalizeDomainName(parent);
    return !!child && !!parent && (child === parent || child.endsWith(`.${parent}`));
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
// some mail readers append whitespace-looking lines to the value above them. Asking what
// a field looks like instead of what whitespace looks like
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

// A field name that can be written into h= although the message has no such field: RFC 5322
// ftext without the ";" that would end the tag (RFC 6376 section 3.2)
const OVERSIGN_FIELD_NAME = /^[\x21-\x39\x3c-\x7e]+$/;

// The names a signer lists in h= more times than the message has fields of that name
// (RFC 6376 sections 5.4.2 and 8.15), so that adding such a field breaks the signature. Only a
// name the header list repeats is over-signed: it appears in h= as many times as it is listed,
// or as many times as the message has it, whichever is more
const getOversignedNames = (fieldNames, signingList) => {
    let listed = new Map();
    for (let casedKey of fieldNames.split(':')) {
        casedKey = casedKey.replace(/^[ \t]+|[ \t]+$/g, '');
        let key = lowerCaseASCII(casedKey);
        if (!key) {
            continue;
        }
        if (!listed.has(key)) {
            listed.set(key, { casedKey, count: 0 });
        }
        listed.get(key).count++;
    }

    let extra = [];
    for (let [key, { casedKey, count }] of listed) {
        if (count < 2 || !OVERSIGN_FIELD_NAME.test(casedKey)) {
            continue;
        }
        let present = signingList.filter(header => header.key === key).length;
        for (let i = present; i < count; i++) {
            extra.push(casedKey);
        }
    }
    return extra;
};

const getSigningHeaderLines = (parsedHeaders, fieldNames, verify) => {
    let configuredFieldNames = typeof fieldNames === 'string' ? fieldNames : false;

    // an h= tag is attacker controlled on inbound mail, so only the constant default list
    // is normalized ahead of time
    fieldNames = configuredFieldNames !== false ? normalizeFieldNames(configuredFieldNames) : defaultDKIMFieldNamesNormalized;

    let signingList = [];
    // names listed in h= without a header field to hash for them
    let oversigned = [];

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

        if (configuredFieldNames) {
            oversigned = getOversignedNames(configuredFieldNames, signingList);
        }
    }

    return {
        keys: signingList
            .map(entry => entry.casedKey)
            .concat(oversigned)
            .join(': '),
        headers: signingList
    };
};

// RFC 6376 section 2.11 dkim-quoted-printable, for the i= tag of a DKIM-Signature. Every byte
// of the UTF-8 encoding that is not a dkim-safe-char (%x21-3A / %x3C / %x3E-7E) is written as
// "=XX". This includes "=" itself, which a verifier would otherwise read as an escape
const encodeDkimQuotedPrintable = value => {
    let result = '';
    for (let byte of Buffer.from((value || '').toString(), 'utf8')) {
        if (byte >= 0x21 && byte <= 0x7e && byte !== 0x3b && byte !== 0x3d) {
            result += String.fromCharCode(byte);
        } else {
            result += '=' + byte.toString(16).toUpperCase().padStart(2, '0');
        }
    }
    return result;
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
                    // convert to A-label if needed
                    val = toALabel(val);
                }

                if (key === 'i' && type === 'DKIM') {
                    val = val.toString();
                    // the domain is what follows the last "@", a quoted local-part may hold one
                    let atPos = val.lastIndexOf('@');
                    if (atPos >= 0) {
                        // convert to A-label if needed
                        val = val.substr(0, atPos + 1) + toALabel(val.substr(atPos + 1));
                    }
                    // the AUID is dkim-quoted-printable, a raw non-ASCII or "=" in it would be
                    // read back as something else
                    val = encodeDkimQuotedPrintable(val);
                }

                return `${key}=${val}`;
            })
            .join('; ');

    if (folded) {
        return libmime.foldLines(header);
    }

    return header;
};

/**
 * Creates an Error with a code, and any extra properties copied onto it
 *
 * @param {String} message Error message
 * @param {String} code Value for err.code
 * @param {Object} [extra] Properties to add to the error
 * @returns {Error}
 */
const createError = (message, code, extra) => {
    let err = new Error(message);
    err.code = code;
    return extra ? Object.assign(err, extra) : err;
};

/**
 * Appends every item that is not in the list yet, keeping the list free of duplicates
 *
 * @param {Array} list List to add to
 * @param {...*} items Items to add
 * @returns {Array} The same list
 */
const addWarning = (list, ...items) => {
    for (let item of items) {
        if (!list.includes(item)) {
            list.push(item);
        }
    }
    return list;
};

// The result comment for a key lookup that failed with one of these codes. The DKIM verifier
// reports them as they are, the ARC validator adds "for <query domain>"
const KEY_ERROR_COMMENTS = new Map([
    ['ENOTFOUND', 'no key'],
    ['ENODATA', 'no key'],
    // a key record name that can not exist in the DNS, so there is no key, now or later
    ['EBADNAME', 'no key'],
    ['EINVALIDVER', 'unknown key version'],
    ['EINVALIDTYPE', 'unknown key type'],
    ['EINVALIDVAL', 'invalid public key'],
    // the key record h= does not list the hash algorithm (RFC 6376 section 6.1.2)
    ['EINVALIDHASH', 'inappropriate hash algorithm'],
    // the key record s= does not list email (RFC 6376 section 3.6.1)
    ['EINVALIDSERVICE', 'key not for email']
]);

// an error about a key record, with the record itself as err.rr when there is one
const keyError = (message, code, rr, extra) => createError(message, code, Object.assign(rr ? { rr } : {}, extra));

// splits a colon separated key record list (h=, s=, t=) into lower case entries
const splitKeyList = value =>
    (typeof value === 'string' ? value : '')
        .split(':')
        .map(entry => entry.trim().toLowerCase())
        .filter(entry => entry);

/**
 * Exports a public key as PEM. RSA keys have always been returned in the PKCS#1 form, but some
 * OpenSSL versions (Node.js 24.21) can not write a key that was read from a bare RSAPublicKey in
 * that form, so SubjectPublicKeyInfo is used then. Both forms verify the same signatures
 *
 * @param {KeyObject} keyObj Public key
 * @returns {String} PEM encoded key
 */
const exportPublicKey = keyObj => {
    if (keyObj.asymmetricKeyType !== 'ed25519') {
        try {
            return keyObj.export({ type: 'pkcs1', format: 'pem' });
        } catch (err) {
            // fall back to SubjectPublicKeyInfo
        }
    }
    return keyObj.export({ type: 'spki', format: 'pem' });
};

/**
 * Tells a bare RSAPublicKey (RFC 3447 A.1.1, SEQUENCE of two INTEGERs) apart from a
 * SubjectPublicKeyInfo (a SEQUENCE that starts with the AlgorithmIdentifier SEQUENCE) by the
 * tag of the first element of the outer DER SEQUENCE
 *
 * @param {Buffer} der DER encoded key
 * @returns {Boolean} true for a bare RSAPublicKey
 */
const isBareRsaPublicKey = der => {
    if (der.length < 3 || der[0] !== 0x30) {
        return false;
    }
    let headerLength = der[1] < 0x80 ? 2 : 2 + (der[1] & 0x7f);
    return der[headerLength] === 0x02;
};

/**
 * Whether a name can exist in the DNS (RFC 1035 section 2.3.4): no empty label, labels of at
 * most 63 octets and a name of at most 253 octets, not counting a trailing root dot
 *
 * @param {String} name Domain name, with A-labels
 * @returns {Boolean} true when the name can be looked up
 */
const isValidDnsName = name => {
    name = (name || '').toString().replace(/\.$/, '');
    return Buffer.byteLength(name) <= 253 && name.split('.').every(label => label.length && Buffer.byteLength(label) <= 63);
};

/**
 * Fetches and validates a DKIM public key record (RFC 6376 section 3.6.1, RFC 8463)
 *
 * @param {String} type 'DKIM', 'ARC' (for an ARC-Message-Signature) or 'AS' (for an ARC-Seal)
 * @param {String} name DNS name of the key record, "selector._domainkey.domain"
 * @param {Number} [minBitLength=1024] Minimum RSA key size, smaller keys throw ESHORTKEY
 * @param {Function} [resolver] DNS resolver
 * @param {Object} [options]
 * @param {Boolean} [options.strict=false] Apply the RFC 6376 key record syntax rules exactly
 * @param {String} [options.hashAlgo] Hash algorithm of the signature ('sha256', 'sha1'). When set,
 *        a key record h= tag that does not list it throws EINVALIDHASH (RFC 6376 section 6.1.2)
 * @returns {Object} { publicKey, rr, modulusLength, keyType, flags, testing, warnings }
 */
const getPublicKey = async (type, name, minBitLength, resolver, options) => {
    minBitLength = minBitLength || 1024;
    resolver = resolver || dns.resolve;
    options = options || {};
    const strict = !!options.strict;

    // RFC 8616 section 3: a U-label is converted to an A-label before it is looked up
    let lookupName = toALabel(name);
    if (!isValidDnsName(lookupName)) {
        // the resolver would fail with an error that looks transient, or ask for a name that
        // can not have a record at all
        throw keyError('Invalid key record name', 'EBADNAME');
    }
    let list = await resolver(lookupName, 'TXT');
    let rr =
        list &&
        []
            .concat(list[0] || [])
            .join('')
            .replace(/\s+/g, '');

    if (!rr) {
        throw keyError('Missing key value', 'EINVALIDVAL');
    }

    const warnings = [];
    // A rule the strict mode enforces: throws in the strict mode, notes the warning otherwise
    const violation = (message, code, warning) => {
        if (strict) {
            throw keyError(message, code, rr);
        }
        addWarning(warnings, warning);
    };

    // tag names are case-sensitive, so strict mode reads them as they are
    let entry = parseTagList(rr, { strict });
    const tags = entry.parsed;

    if (entry.syntaxErrors.length) {
        // RFC 6376 section 6.1.2 step 5: a key record that does not adhere to the format is ignored
        violation(`Invalid key record syntax: ${entry.syntaxErrors[0]}`, 'EINVALIDVAL', 'key-syntax');
    }

    const publicKeyValue = tags.p?.value;
    if (!publicKeyValue) {
        // an empty p= means the key has been revoked
        throw keyError('Missing key value', 'EINVALIDVAL', rr);
    }

    let validation = base64Schema.validate(publicKeyValue);
    if (validation.error) {
        throw keyError('Invalid base64 format for public key', 'EINVALIDVAL', rr, { details: validation.error });
    }

    // ARC signatures use the same DKIM key records (RFC 8617 section 4.1), so the version
    // rules apply to them as well
    if (tags.v) {
        let version = (tags.v.value || '').toString();
        if (version.toLowerCase().trim() !== 'dkim1') {
            throw keyError('Unknown key version', 'EINVALIDVER', rr);
        }

        // key-v-tag is %x44.4B.49.4D.31, an exact string, and "MUST be the first tag"
        if (version !== 'DKIM1' || entry.tags[0]?.name !== 'v') {
            violation(version !== 'DKIM1' ? 'Unknown key version' : 'Key version tag is not the first tag', 'EINVALIDVER', 'key-v-syntax');
        }
    }

    // RFC 6376 section 3.6.1 s=: "Verifiers for a given service type MUST ignore this record
    // if the appropriate type is not listed", applied in every mode, it is the key owner's choice
    if (tags.s) {
        let services = splitKeyList(tags.s.value);
        if (!services.includes('email') && !services.includes('*')) {
            throw keyError('Key is not meant for email', 'EINVALIDSERVICE', rr);
        }
    }

    // RFC 6376 section 6.1.2 step 6: the key owner can limit the hash algorithms the key
    // is used with, which is also how a domain opts out of rsa-sha1 in the lenient mode
    if (tags.h && options.hashAlgo) {
        let hashes = splitKeyList(tags.h.value);
        if (!hashes.includes(options.hashAlgo.toLowerCase())) {
            throw keyError(`Key does not allow ${options.hashAlgo}`, 'EINVALIDHASH', rr);
        }
    }

    let declaredKeyType = tags.k ? (tags.k.value || '').toString().toLowerCase().trim() : false;

    let rawPublicKey = Buffer.from(publicKeyValue, 'base64');
    let publicKeyObj;

    let candidates = [];
    if (rawPublicKey.length === 32 && (!strict || declaredKeyType === 'ed25519')) {
        // RFC 8463 section 4: the raw 32 byte ed25519 key
        candidates.push({
            key: Buffer.concat([Buffer.from('302A300506032B6570032100', 'hex'), rawPublicKey]),
            format: 'der',
            type: 'spki'
        });
    } else if (isBareRsaPublicKey(rawPublicKey)) {
        // the bare RSAPublicKey of RFC 6376 section 3.6.1 (k=rsa), picked by its structure
        candidates.push({ key: rawPublicKey, format: 'der', type: 'pkcs1' });
    } else {
        // a SubjectPublicKeyInfo structure is what is published in practice
        candidates.push({ key: rawPublicKey, format: 'der', type: 'spki' });
    }

    let lastError;
    let exportedKey;
    for (let candidate of candidates) {
        try {
            let keyObj = crypto.createPublicKey(candidate);
            exportedKey = exportPublicKey(keyObj);
            publicKeyObj = keyObj;
            break;
        } catch (err) {
            lastError = err;
        }
    }

    if (!publicKeyObj) {
        let error = new Error('Unknown key type', { cause: lastError });
        error.code = 'EINVALIDTYPE';
        error.rr = rr;
        throw error;
    }

    let keyType = publicKeyObj.asymmetricKeyType;

    if (!['rsa', 'ed25519'].includes(keyType) || (declaredKeyType && declaredKeyType !== keyType)) {
        throw keyError(`Unknown key type (${keyType})`, 'EINVALIDTYPE', rr);
    }

    if (!declaredKeyType && keyType !== 'rsa') {
        // k= defaults to "rsa", an ed25519 key is only found by looking at the key data
        violation(`Unknown key type (${keyType})`, 'EINVALIDTYPE', 'key-type-inferred');
    }

    if (keyType === 'ed25519' && rawPublicKey.length !== 32) {
        // RFC 8463 section 4 publishes the bare key, not a SubjectPublicKeyInfo structure
        violation('Invalid ed25519 public key', 'EINVALIDVAL', 'key-ed25519-spki');
    }

    let modulusLength = publicKeyObj.asymmetricKeyDetails.modulusLength;

    if (keyType === 'rsa' && modulusLength < minBitLength) {
        throw keyError('RSA key too short', 'ESHORTKEY', rr);
    }

    // t= flags. "y" is the testing mode, "s" forbids an i= domain that is a subdomain of d=
    let flags = splitKeyList(tags.t?.value);

    return {
        publicKey: exportedKey,
        rr,
        modulusLength,
        keyType,
        flags,
        testing: flags.includes('y'),
        warnings
    };
};

/**
 * Creates a key lookup cache for one message. DKIM-Signatures, the ARC-Message-Signature and the
 * ARC-Seals that name the same key record share one getPublicKey() call, and so one DNS query.
 * Everything that changes the outcome of the lookup is part of the cache key, so a result is
 * never used for a different question
 *
 * @param {Function} [resolver] DNS resolver, used for every lookup of the cache
 * @returns {Object} { resolver, get(type, name, minBitLength, options) }, `get` takes the
 *          arguments of getPublicKey() without the resolver and returns the same promise for
 *          the same question
 */
const createKeyCache = resolver => {
    const cache = new Map();
    return {
        resolver,
        get(type, name, minBitLength, options) {
            options = options || {};
            let key = [!!options.strict, minBitLength || '', options.hashAlgo || '', name].join(':');
            let lookup = cache.get(key);
            if (!lookup) {
                lookup = getPublicKey(type, name, minBitLength, resolver, options);
                // a prefetched lookup can fail before anything waits for it. Every caller that
                // awaits the promise still gets the error
                lookup.catch(() => false);
                cache.set(key, lookup);
            }
            return lookup;
        }
    };
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

// RFC 2045 section 5.1 token: printable US-ASCII except SPACE and the tspecials ()<>@,;:\"/[]?=
const RFC2045_TOKEN = /^[!#$%&'*+\-.0-9A-Z^_`a-z{|}~]+$/;
// What the older formatter left unquoted: a token, or a token with "@" signs in it
const LEGACY_UNQUOTED = /^[!#$%&'*+\-.0-9A-Z^_`a-z{|}~@]+$/;
// RFC 5322 section 3.2.3 dot-atom-text
const DOT_ATOM_TEXT = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/;
// RFC 5322 section 3.2.4 quoted-string, without CFWS around it
const QUOTED_STRING = /^"(?:[^"\\\r\n]|\\[\x20-\x7e\t])*"$/;
// DOMAIN_NAME is the RFC 6376 section 3.5 domain-name, which RFC 8601 uses for pvalue

// A generated header line has to stay under the 998 character limit of RFC 5322 section
// 2.1.1, and a value with no whitespace in it can not be folded. A property value longer than
// this is left out (RFC 8601 section 2.2 lets a propspec be omitted) rather than truncated
// into a different identity, and a word of a comment is cut short, which only loses text
const MAX_HEADER_VALUE_LENGTH = 900;
const MAX_COMMENT_WORD_LENGTH = 400;

const cleanHeaderText = value =>
    (value || '')
        .toString()
        // CTLs and DEL are not allowed anywhere in a structured field body, not even escaped
        .replace(/[\x00-\x1F\x7F]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

const quoteString = value => `"${value.replace(/["\\]/g, c => `\\${c}`)}"`;

// A header value that is either an RFC 5322 dot-atom-text or, for anything else, a
// quoted-string, such as the key-value-pair values of Received-SPF (RFC 7208 section 9.1)
const formatDotAtomOrQuoted = value => {
    value = cleanHeaderText(value);
    return DOT_ATOM_TEXT.test(value) ? value : quoteString(value);
};

/**
 * Formats a property value for an Authentication-Results header (RFC 8601 section 2.2):
 * pvalue = value / [ [ local-part ] "@" ] domain-name, where value is a token or a
 * quoted-string. Returns an empty string when there is nothing to report.
 *
 * @param {String} value Property value
 * @param {Boolean} [strict] If true, an email identity is always written in the
 *        local-part@domain form that RFC 8601 section 2.2 requires, with the local-part quoted
 *        when it is not a dot-atom. Otherwise the output is kept as it was in older versions
 *        wherever that output was already valid, which quotes such identities as a whole
 */
const escapePropValue = (value, strict) => {
    value = cleanHeaderText(value);

    if (!value) {
        return '';
    }

    if (RFC2045_TOKEN.test(value)) {
        // return token value
        return value;
    }

    let atPos = value.lastIndexOf('@');
    if (atPos >= 0) {
        let localPart = value.substring(0, atPos);
        let domain = value.substring(atPos + 1);

        if (DOMAIN_NAME.test(domain)) {
            if (!localPart || DOT_ATOM_TEXT.test(localPart)) {
                // a valid [ [ local-part ] "@" ] domain-name as it is
                if (strict || LEGACY_UNQUOTED.test(value)) {
                    return value;
                }
            } else if (strict) {
                return `${QUOTED_STRING.test(localPart) ? localPart : quoteString(localPart)}@${domain}`;
            }
        }
    }

    // return quoted string with escaped quotes
    return quoteString(value);
};

/**
 * Makes a value safe to use as the content of an RFC 5322 comment. Both parentheses and the
 * backslash are escaped, so the comment always stays balanced and ends where it should.
 *
 * @param {String} value Comment text
 * @returns {String} Escaped comment text, without the parentheses around it
 */
const escapeCommentValue = value => {
    value = cleanHeaderText(value)
        .split(' ')
        .map(word => {
            if (Buffer.byteLength(word) <= MAX_COMMENT_WORD_LENGTH) {
                return word;
            }
            // the limit is in octets, a line of UTF-8 text is measured in octets on the wire
            let shortened = '';
            for (let char of word) {
                if (Buffer.byteLength(shortened + char) > MAX_COMMENT_WORD_LENGTH) {
                    break;
                }
                shortened += char;
            }
            return shortened + '...';
        })
        .join(' ');

    return value.replace(/[\\()]/g, c => `\\${c}`);
};

/**
 * Formats the authserv-id of an Authentication-Results header (RFC 8601 section 2.5). It is
 * usually the host name of the MTA, which is a token, and an internationalized host name is
 * converted to its A-label form. Any other value is written as a quoted-string, which RFC 8601
 * allows (authserv-id = value). With strict set such a value throws instead, as a reader that
 * splits the header on semicolons would still take a value such as "mx.example; dkim=pass"
 * for a result
 *
 * @param {String} authservId Usually the host name of the MTA
 * @param {Boolean} [strict] If true, throws for a value that is not a token
 * @returns {String} The authserv-id
 */
const formatAuthservId = (authservId, strict) => {
    let value = toALabel(cleanHeaderText(authservId));

    if (value && value.length <= MAX_HEADER_VALUE_LENGTH && RFC2045_TOKEN.test(value)) {
        return value;
    }

    if (!value || value.length > MAX_HEADER_VALUE_LENGTH || strict) {
        let err = new TypeError(`Invalid authserv-id ${JSON.stringify((authservId || '').toString())}, expecting a host name`);
        err.code = 'EINVALIDAUTHSERVID';
        throw err;
    }

    return quoteString(value);
};

/**
 * Formats a single resinfo of an Authentication-Results header (RFC 8601 section 2.2)
 *
 * @param {String} method Authentication method, eg. "dkim"
 * @param {Object} status Result status: result, comment, and the policy/smtp/body/header ptypes
 * @param {Object} [options]
 * @param {Boolean} [options.strict] Format email identities in the RFC 8601 section 2.2 form
 * @returns {String} Formatted resinfo, without the leading semicolon
 */
const formatAuthHeaderRow = (method, status, options) => {
    status = status || {};
    options = options || {};
    let parts = [];

    // the result is a Keyword (RFC 8601 section 2.2)
    let result = (status.result || '').toString().replace(/[^A-Za-z0-9-]+/g, '') || 'none';
    parts.push(`${method}=${result}`);

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
            let propValue = status[ptype][prop];
            if (!propValue || !['string', 'number', 'boolean'].includes(typeof propValue)) {
                continue;
            }

            let escaped = escapePropValue(propValue, options.strict);
            if (!escaped || Buffer.byteLength(escaped) > MAX_HEADER_VALUE_LENGTH) {
                continue;
            }

            parts.push(`${ptype}.${prop}=${escaped}`);
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
        // a string is a header line built here, and it is written out as UTF-8, so it is
        // hashed as the same UTF-8 bytes. A Buffer holds the bytes of the message as they are
        (typeof line === 'string' ? Buffer.from(line) : line || Buffer.alloc(0))
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

// RFC 6376 section 3.7: when the signature header is hashed, its own b= value "(including
// all surrounding whitespace)" is treated as empty. The segment emptied here has to be the
// exact one the tag-list parser (lib/parse-dkim-headers.js) takes the signature from, so the
// line is read the same way: split on the semicolons, which can not occur inside a tag value,
// and each tag name decoded as UTF-8 with the whitespace around it removed, as buildTagMap
// does. Matching a "b=" anywhere in the line instead would strip the wrong value when it
// appears inside another tag, such as a z= copy of a header or an unknown tag.
//
// The parser keeps the last value of a repeated tag. The lenient parser folds tag names to
// lower case, so there the last tag named "b" or "B" is the signature, the strict parser reads
// names case-sensitively (RFC 6376 section 3.2), so there it is the last tag named exactly "b".
const stripSignatureValue = (line, strict) => {
    let str = line.toString('binary');

    let colonPos = str.indexOf(':');
    let prefix = colonPos >= 0 ? str.substring(0, colonPos + 1) : '';
    let segments = (colonPos >= 0 ? str.substring(colonPos + 1) : str).split(';');

    for (let i = segments.length - 1; i >= 0; i--) {
        let eqPos = segments[i].indexOf('=');
        if (eqPos < 0) {
            continue;
        }
        let name = Buffer.from(segments[i].substring(0, eqPos), 'binary').toString().replace(/\s+/g, ' ').trim();
        if ((strict ? name : name.toLowerCase()) === 'b') {
            segments[i] = segments[i].substring(0, eqPos + 1);
            break;
        }
    }

    return Buffer.from(prefix + segments.join(';'), 'binary');
};

const formatDomain = domain => {
    // toALabel normalizes a U-label to NFC first, so this matches the d= and s= values the
    // signer writes and the verifier reports for the same name
    domain = toALabel(domain.toLowerCase().trim()).toLowerCase().trim();
    // the root label is not part of the name, so "example.com." and "example.com" are the same domain
    return domain.replace(/\.+$/, '');
};

// A domain as getAlignment() compares it, after formatDomain(): labels of letters, digits, "-"
// and "_" (which the lenient mode lets through), with no empty label. Anything else, such as
// the URL delimiters "/", "?" and "#", can not be a host name and never aligns
const ALIGNMENT_DOMAIN = /^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/;

// the Organizational Domain of a domain as found from the Public Suffix List, or false for a
// value that is not a host name
const getOrgDomain = domain => {
    domain = typeof domain === 'string' ? formatDomain(domain) : '';
    if (!ALIGNMENT_DOMAIN.test(domain)) {
        return false;
    }
    return tldts.getDomain(domain, TLDTS_OPTS) || domain;
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
        let from = typeof fromDomain === 'string' ? formatDomain(fromDomain) : '';
        if (!ALIGNMENT_DOMAIN.test(from)) {
            // a bare root label normalizes to an empty string, which must not align with
            // anything, and neither does a value that is not a host name
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
    let fromOrg = getOrgDomain(fromDomain);
    if (!fromOrg) {
        return false;
    }
    for (let entry of domainList) {
        if (getOrgDomain(entry.domain) === fromOrg) {
            return entry;
        }
    }

    return false;
};

// The signing and the hashing algorithm of an a= value such as "rsa-sha256", in lower case.
// A value without a dash gives the same string for both
const splitAlgorithm = algorithm => {
    let parts = (algorithm || '').toString().split('-');
    return {
        signAlgo: parts[0].toLowerCase().trim(),
        hashAlgo: parts[parts.length - 1].toLowerCase().trim()
    };
};

// Whether a signing and hashing algorithm pair is one this library signs and verifies with:
// rsa-sha256 and ed25519-sha256, and rsa-sha1 when `allowSha1` is set. RFC 8463 defines
// ed25519-sha256 only, "ed25519-sha1" is not an algorithm
const isSupportedAlgorithm = (signAlgo, hashAlgo, allowSha1) =>
    ['rsa', 'ed25519'].includes(signAlgo) && (hashAlgo === 'sha256' || (!!allowSha1 && signAlgo === 'rsa' && hashAlgo === 'sha1'));

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

        if (!isSupportedAlgorithm(signAlgo, hashAlgo, !strict)) {
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

    createError,
    addWarning,
    KEY_ERROR_COMMENTS,
    isValidDnsName,

    defaultDKIMFieldNames,
    defaultARCFieldNames,
    defaultASFieldNames,

    getSigningHeaderLines,
    formatSignatureHeaderLine,
    parseDkimHeaders,
    parseTagList,
    getPublicKey,
    getPrivateKey,
    formatAuthHeaderRow,
    escapeCommentValue,
    escapePropValue,
    formatAuthservId,
    MAX_HEADER_VALUE_LENGTH,
    formatDotAtomOrQuoted,
    fetch,

    validateAlgorithm,
    splitAlgorithm,
    isSupportedAlgorithm,
    createKeyCache,

    getAlignment,

    formatRelaxedLine,
    stripSignatureValue,
    formatDomain,
    toALabel,
    normalizeDomainName,
    isSameOrSubdomain,

    getPtrHostname,

    getCurTime,

    TLDTS_OPTS,

    validateTagValueRecord,
    parseTagValueRecord,
    convertToASCII
};
