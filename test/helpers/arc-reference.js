'use strict';

// Independent ARC reference implementation, written from RFC 8617 (sections 4, 5.1 and 5.2),
// RFC 6376 (sections 3.2, 3.4 and 3.7) and RFC 8463 alone. It shares no code with mailauth, so
// a bug in mailauth can not be cancelled out by the same bug here. It builds ARC sets from
// literal tag lists (so tests can use any tag layout, including invalid ones) and validates a
// chain the way an RFC-literal validator would. All byte strings are latin1 ("binary") strings.

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');

const keys = new Map();

// A key pair by name, generated on first use. `type` is 'rsa' or 'ed25519'
const key = (name, type) => {
    if (!keys.has(name)) {
        let pair = (type || 'rsa') === 'rsa' ? crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }) : crypto.generateKeyPairSync('ed25519');
        pair.type = type || 'rsa';
        keys.set(name, pair);
    }
    return keys.get(name);
};

// The DNS TXT record of a key, `extra` is inserted in front of p=
const dnsTxt = (name, extra) => {
    let pair = keys.get(name);
    let der = pair.publicKey.export({ type: 'spki', format: 'der' });
    // RFC 8463 section 4: an ed25519 record holds the bare 32 byte key
    let p = (pair.type === 'rsa' ? der : der.subarray(-32)).toString('base64');
    return `v=DKIM1; k=${pair.type}; ${extra || ''}p=${p}`;
};

// A resolver for records, a map of "selector._domainkey.domain" to a key name or a literal TXT
// record. Every query is added to `resolver.calls`
const resolver = records => {
    let lookup = async (name, type) => {
        lookup.calls.push(`${type} ${name}`);
        let value = records[name.toLowerCase()];
        if (type === 'TXT' && value) {
            return [[keys.has(value) ? dnsTxt(value) : value]];
        }
        let err = new Error(`ENOTFOUND ${name}`);
        err.code = 'ENOTFOUND';
        throw err;
    };
    lookup.calls = [];
    return lookup;
};

// RFC 6376 section 3.4.2, for a complete "Name: value" field that may be folded
const relaxedHeader = field => {
    let idx = field.indexOf(':');
    let name = field
        .slice(0, idx)
        .replace(/[ \t]+$/, '')
        .toLowerCase();
    let value = field
        .slice(idx + 1)
        .replace(/\r\n/g, '')
        .replace(/[ \t]+/g, ' ')
        .replace(/^ /, '')
        .replace(/ $/, '');
    return `${name}:${value}`;
};

// RFC 6376 section 3.4.4
const relaxedBody = body => {
    let lines = body.split('\r\n').map(line => line.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
    while (lines.length && lines[lines.length - 1] === '') {
        lines.pop();
    }
    return lines.length ? lines.join('\r\n') + '\r\n' : '';
};

// RFC 6376 section 3.4.3
const simpleBody = body => {
    let result = body;
    while (result.endsWith('\r\n\r\n')) {
        result = result.slice(0, -2);
    }
    if (result === '') {
        return '\r\n';
    }
    return result.endsWith('\r\n') ? result : result + '\r\n';
};

// RFC 6376 section 3.7: the b= value is empty when the signature header itself is hashed
const stripB = field => field.replace(/(^|;)([ \t\r\n]*b[ \t\r\n]*=)[^;]*/, '$1$2');

const splitMessage = msg => {
    let idx = msg.indexOf('\r\n\r\n');
    let fields = [];
    for (let line of msg.slice(0, idx).split('\r\n')) {
        if (/^[ \t]/.test(line) && fields.length) {
            fields[fields.length - 1] += '\r\n' + line;
        } else {
            fields.push(line);
        }
    }
    return { fields, body: msg.slice(idx + 4) };
};

const fieldName = field => field.slice(0, field.indexOf(':')).trim().toLowerCase();

const signData = (alg, data, pair) => {
    if (alg.startsWith('rsa')) {
        return crypto.sign('sha256', Buffer.from(data, 'binary'), pair.privateKey).toString('base64');
    }
    // RFC 8463 section 3: Ed25519 signs the SHA-256 hash of the data
    let hash = crypto.createHash('sha256').update(Buffer.from(data, 'binary')).digest();
    return crypto.sign(null, hash, pair.privateKey).toString('base64');
};

const verifyData = (alg, data, publicKey, b) => {
    if (alg.startsWith('rsa')) {
        return crypto.verify('sha256', Buffer.from(data, 'binary'), publicKey, Buffer.from(b, 'base64'));
    }
    let hash = crypto.createHash('sha256').update(Buffer.from(data, 'binary')).digest();
    return crypto.verify(null, hash, publicKey, Buffer.from(b, 'base64'));
};

// fold at "; " to keep the lines short
const fold = str => str.replace(/; /g, ';\r\n\t');

/**
 * Builds an ARC-Message-Signature for `msg`
 *
 * opts: { i, d, s, keyName, alg, c (null leaves the tag out), signedWith (the canonicalization
 * actually used, defaults to c or simple/simple), h (array of names), extraTags }
 */
const makeAMS = (msg, opts) => {
    let { fields, body } = splitMessage(msg);
    let alg = opts.alg || 'rsa-sha256';
    let cTag = opts.c === undefined ? 'relaxed/relaxed' : opts.c;
    let [headerCanon, bodyCanon] = (opts.signedWith || cTag || 'simple/simple').split('/');
    let bh = crypto
        .createHash('sha256')
        .update(Buffer.from(bodyCanon === 'relaxed' ? relaxedBody(body) : simpleBody(body), 'binary'))
        .digest('base64');
    let h = opts.h || ['from', 'to', 'subject', 'date', 'message-id'];

    let field = fold(
        `ARC-Message-Signature: i=${opts.i}; a=${alg}; ${cTag ? `c=${cTag}; ` : ''}d=${opts.d}; s=${opts.s}; ${opts.extraTags || ''}h=${h.join(':')}; bh=${bh}; b=`
    );

    // header fields are used from the bottom up (RFC 6376 section 5.4.2)
    let used = {};
    let data = '';
    for (let name of h) {
        let candidates = fields.filter(f => fieldName(f) === name.toLowerCase());
        used[name] = (used[name] || 0) + 1;
        let selected = candidates[candidates.length - used[name]];
        if (selected) {
            data += (headerCanon === 'relaxed' ? relaxedHeader(selected) : selected) + '\r\n';
        }
    }
    data += headerCanon === 'relaxed' ? relaxedHeader(field) : field;

    return field + signData(alg, data, key(opts.keyName, alg.startsWith('rsa') ? 'rsa' : 'ed25519'));
};

/**
 * Builds an ARC-Seal. `prevSets` are the earlier sets as { aar, ams, as }, `cur` the new set's
 * { aar, ams }. opts: { i, cv, d, s, keyName, alg, t, rawTags (the literal tag list, up to and
 * including "b="), ownScope (sign only the new set, as a cv=fail seal does) }
 */
const makeAS = (prevSets, cur, opts) => {
    let alg = opts.alg || 'rsa-sha256';
    let tags = opts.rawTags || `i=${opts.i}; a=${alg}; cv=${opts.cv}; d=${opts.d}; s=${opts.s}; t=${opts.t || 1700000000}; b=`;
    let field = fold(`ARC-Seal: ${tags}`);

    let scope = (opts.cv || '').toLowerCase() === 'fail' || opts.ownScope ? [] : prevSets;
    let data = '';
    for (let set of scope) {
        data += relaxedHeader(set.aar) + '\r\n' + relaxedHeader(set.ams) + '\r\n' + relaxedHeader(set.as) + '\r\n';
    }
    data += relaxedHeader(cur.aar) + '\r\n' + relaxedHeader(cur.ams) + '\r\n' + relaxedHeader(field);

    return field + signData(alg, data, key(opts.keyName, alg.startsWith('rsa') ? 'rsa' : 'ed25519'));
};

/**
 * Adds an ARC set to `msg`. opts: { i, cv, d, s, keyName, alg, amsAlg, aar (the complete AAR
 * field), amsOpts (passed to makeAMS), and the makeAS options }
 *
 * @returns {Object} { msg, sets, set }
 */
const seal = (msg, prevSets, opts) => {
    let aar = opts.aar || `ARC-Authentication-Results: i=${opts.i}; ${opts.d}; spf=pass smtp.mailfrom=example.com`;
    let ams = makeAMS(msg, Object.assign({ i: opts.i, d: opts.d, s: opts.s, keyName: opts.keyName, alg: opts.amsAlg || opts.alg }, opts.amsOpts || {}));
    let as = makeAS(prevSets, { aar, ams }, opts);
    let set = { aar, ams, as };
    return { msg: `${as}\r\n${ams}\r\n${aar}\r\n${msg}`, sets: prevSets.concat(set), set };
};

// RFC 6376 section 3.2 tag-list, null if it is not valid
const parseTags = field => {
    let value = field.slice(field.indexOf(':') + 1).replace(/\r\n/g, '');
    let tags = {};
    let parts = value.split(';');
    for (let n = 0; n < parts.length; n++) {
        let part = parts[n];
        let match = /^[ \t]*([A-Za-z][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*?)[ \t]*$/.exec(part);
        if (!match) {
            if (part.trim() || n < parts.length - 1) {
                // only one trailing semicolon is allowed
                return null;
            }
            continue;
        }
        if (match[1] in tags) {
            return null;
        }
        tags[match[1]] = match[2];
    }
    return tags;
};

/**
 * Validates the ARC chain of `msg` per RFC 8617 section 5.2 (without the optional oldest-pass
 * step). `records` is the same map the resolver takes
 *
 * @returns {Object} { cv, reason }
 */
const validate = (msg, records) => {
    let { fields, body } = splitMessage(msg);

    let publicKey = name => {
        let value = records[name.toLowerCase()];
        if (!value) {
            return null;
        }
        let txt = keys.has(value) ? dnsTxt(value) : value;
        let raw = Buffer.from(/p=([^;]+)/.exec(txt)[1].trim(), 'base64');
        if (raw.length === 32) {
            return crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' });
        }
        return crypto.createPublicKey({ key: raw, format: 'der', type: 'spki' });
    };

    let sets = {};
    for (let field of fields) {
        let name = fieldName(field);
        if (!['arc-seal', 'arc-message-signature', 'arc-authentication-results'].includes(name)) {
            continue;
        }
        let value = field.slice(field.indexOf(':') + 1).replace(/\r\n/g, '');
        let match =
            name === 'arc-authentication-results'
                ? /^[ \t]*i[ \t]*=[ \t]*([0-9]{1,2})[ \t]*;/.exec(value)
                : /(?:^|;)[ \t]*i[ \t]*=[ \t]*([^;]*?)[ \t]*(?:;|$)/.exec(value);
        if (!match || !/^[0-9]{1,2}$/.test(match[1]) || +match[1] < 1 || +match[1] > 50) {
            return { cv: 'fail', reason: `bad instance in ${name}` };
        }
        let i = +match[1];
        sets[i] = sets[i] || {};
        if (sets[i][name]) {
            return { cv: 'fail', reason: 'duplicate header' };
        }
        sets[i][name] = field;
    }

    let count = Object.keys(sets).length;
    if (!count) {
        return { cv: 'none' };
    }
    if (count > 50) {
        return { cv: 'fail', reason: 'more than 50 sets' };
    }
    let n = Math.max(...Object.keys(sets).map(Number));

    let sealTags = i => parseTags(sets[i]['arc-seal']);

    if (sets[n]['arc-seal'] && sealTags(n) && (sealTags(n).cv || '').toLowerCase() === 'fail') {
        return { cv: 'fail', reason: 'newest cv=fail' };
    }

    for (let i = 1; i <= n; i++) {
        if (!sets[i] || Object.keys(sets[i]).length !== 3) {
            return { cv: 'fail', reason: `structure i=${i}` };
        }
        let tags = sealTags(i);
        if (!tags) {
            return { cv: 'fail', reason: `seal tag-list i=${i}` };
        }
        if ((tags.cv || '').toLowerCase() !== (i === 1 ? 'none' : 'pass')) {
            return { cv: 'fail', reason: `cv i=${i}` };
        }
        if ('h' in tags) {
            return { cv: 'fail', reason: 'h= in seal' };
        }
        if ('t' in tags && !/^[0-9]{1,12}$/.test(tags.t)) {
            // sig-t-tag = %x74 [FWS] "=" [FWS] 1*12DIGIT
            return { cv: 'fail', reason: `seal t= i=${i}` };
        }
    }

    // step 4, the newest ARC-Message-Signature
    let amsTags = parseTags(sets[n]['arc-message-signature']);
    if (!amsTags || !amsTags.h) {
        return { cv: 'fail', reason: 'AMS tag-list' };
    }
    let [headerCanon, bodyCanon] = (amsTags.c || 'simple/simple').split('/');
    let canonBody = (bodyCanon || 'simple') === 'relaxed' ? relaxedBody(body) : simpleBody(body);
    if (crypto.createHash('sha256').update(Buffer.from(canonBody, 'binary')).digest('base64') !== amsTags.bh.replace(/\s+/g, '')) {
        return { cv: 'fail', reason: 'AMS body hash' };
    }
    let h = amsTags.h.split(':').map(name => name.trim().toLowerCase());
    if (!h.includes('from')) {
        return { cv: 'fail', reason: 'AMS h= lacks From' };
    }
    let used = {};
    let data = '';
    for (let name of h) {
        let candidates = fields.filter(f => fieldName(f) === name);
        used[name] = (used[name] || 0) + 1;
        let selected = candidates[candidates.length - used[name]];
        if (selected) {
            data += (headerCanon === 'relaxed' ? relaxedHeader(selected) : selected) + '\r\n';
        }
    }
    let amsField = stripB(sets[n]['arc-message-signature']);
    data += headerCanon === 'relaxed' ? relaxedHeader(amsField) : amsField;
    let amsKey = publicKey(`${amsTags.s}._domainkey.${amsTags.d}`);
    if (!amsKey || !verifyData(amsTags.a, data, amsKey, amsTags.b.replace(/\s+/g, ''))) {
        return { cv: 'fail', reason: 'AMS signature' };
    }

    // step 6, every seal from the newest to the oldest
    for (let m = n; m >= 1; m--) {
        let tags = sealTags(m);
        let sealData = '';
        for (let i = 1; i <= m; i++) {
            sealData += relaxedHeader(sets[i]['arc-authentication-results']) + '\r\n' + relaxedHeader(sets[i]['arc-message-signature']) + '\r\n';
            sealData += i < m ? relaxedHeader(sets[i]['arc-seal']) + '\r\n' : relaxedHeader(stripB(sets[i]['arc-seal']));
        }
        let sealKey = publicKey(`${tags.s}._domainkey.${tags.d}`);
        if (!sealKey || !verifyData(tags.a, sealData, sealKey, tags.b.replace(/\s+/g, ''))) {
            return { cv: 'fail', reason: `seal signature i=${m}` };
        }
    }

    return { cv: 'pass' };
};

const baseMessage = () =>
    'From: Alice <alice@example.com>\r\nTo: bob@example.net\r\nSubject: hello\r\nDate: Thu, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nHello world\r\n';

module.exports = { key, dnsTxt, resolver, relaxedHeader, relaxedBody, simpleBody, stripB, splitMessage, makeAMS, makeAS, seal, validate, baseMessage };
