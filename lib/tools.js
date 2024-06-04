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

const parseHeaders = buf => {
    let rows = buf
        .toString('binary')
        .replace(/[\r\n]+$/, '')
        .split(/\r?\n/)
        .map(row => [row]);
    for (let i = rows.length - 1; i >= 0; i--) {
        if (i > 0 && /^\s/.test(rows[i][0])) {
            rows[i - 1] = rows[i - 1].concat(rows[i]);
            rows.splice(i, 1);
        }
    }

    rows = rows.map(row => {
        row = row.join('\r\n');
        let key = row.match(/^[^:]+/);
        let casedKey;
        if (key) {
            casedKey = key[0].trim();
            key = casedKey.toLowerCase();
        }

        return { key, casedKey, line: Buffer.from(row, 'binary') };
    });

    return { parsed: rows, original: buf };
};

const getSigningHeaderLines = (parsedHeaders, fieldNames, verify) => {
    fieldNames = (typeof fieldNames === 'string' ? fieldNames : defaultDKIMFieldNames)
        .split(':')
        .map(key => key.trim().toLowerCase())
        .filter(key => key);

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
                    t: Math.round(Date.now() / 1000),
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
                    t: Math.round(Date.now() / 1000),
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
                    t: Math.round(Date.now() / 1000)
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
            .filter(key => values[key] !== false && typeof values[key] !== 'undefined' && values.key !== null && keyOrdering.includes(key))
            .sort((a, b) => keyOrdering.indexOf(a) - keyOrdering.indexOf(b))
            .map(key => {
                let val = values[key] || '';
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

        if (keyType === 'rsa' && modulusLength < 1024) {
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

const formatRelaxedLine = (line, suffix) => {
    let result =
        line
            ?.toString('binary')
            // unfold
            .replace(/\r?\n/g, '')
            // key to lowercase, trim around :
            .replace(/^([^:]*):\s*/, (m, k) => k.toLowerCase().trim() + ':')
            // single WSP
            .replace(/\s+/g, ' ')
            .trim() + (suffix ? suffix : '');

    return Buffer.from(result, 'binary');
};

const formatDomain = domain => {
    domain = domain.toLowerCase().trim();
    try {
        domain = punycode.toASCII(domain).toLowerCase().trim();
    } catch (err) {
        // ignore punycode errors
    }
    return domain;
};

const getAlignment = (fromDomain, domainList, strict) => {
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
        fromDomain = formatDomain(fromDomain);
        for (let entry of domainList) {
            let domain = formatDomain(tldts.getDomain(entry.domain, TLDTS_OPTS) || entry.domain);
            if (formatDomain(domain) === fromDomain) {
                return entry;
            }
        }
    }

    // match org domains
    fromDomain = formatDomain(tldts.getDomain(fromDomain, TLDTS_OPTS) || fromDomain);
    for (let entry of domainList) {
        let domain = formatDomain(tldts.getDomain(entry.domain, TLDTS_OPTS) || entry.domain);
        if (domain === fromDomain) {
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

        if (typeof timeValue === 'number' || !isNaN(timeValue)) {
            let timestamp = Number(timeValue);
            let curTime = new Date(timestamp);
            if (curTime.toString !== 'Invalid Date') {
                return curTime;
            }
        } else if (typeof timeValue === 'string') {
            let curTime = new Date(timeValue);
            if (curTime.toString !== 'Invalid Date') {
                return curTime;
            }
        }
    }

    return new Date();
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
    formatDomain,

    getPtrHostname,

    getCurTime,

    TLDTS_OPTS
};
