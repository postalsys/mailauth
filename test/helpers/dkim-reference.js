'use strict';

// Independent DKIM reference implementations, written from RFC 6376 sections 3.4, 3.5 and 3.7,
// RFC 8301 and RFC 8463 alone. They share no code with mailauth, so a bug in mailauth can not
// be cancelled out by the same bug here. `sign` builds signed messages from a literal
// signature header (so that tests can use any tag layout, including invalid ones) and
// `verify` checks a message the way an RFC-literal verifier would. All byte strings are
// handled as latin1 ("binary") strings.

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');

const WSP = '[ \\t]';
const FWS = `(?:${WSP}*\\r\\n)?${WSP}+`;
const TVAL = '[\\x21-\\x3a\\x3c-\\x7e]+';
const TAG_VALUE_RE = new RegExp(`^(?:${TVAL}(?:(?:${WSP}|${FWS})+${TVAL})*)?$`);
const TAG_SPEC_RE = new RegExp(`^(?:${FWS})?([A-Za-z][A-Za-z0-9_]*)(?:${FWS})?=(?:${FWS})?([\\s\\S]*?)(?:${FWS})?$`);

// RFC 5321 sub-domain = Let-dig [Ldh-str]
const SUBDOMAIN = '[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?';
const DOMAIN_NAME_RE = new RegExp(`^${SUBDOMAIN}(?:\\.${SUBDOMAIN})+$`);
const SELECTOR_RE = new RegExp(`^${SUBDOMAIN}(?:\\.${SUBDOMAIN})*$`);
const B64_RE = new RegExp(`^[A-Za-z0-9+/](?:(?:${FWS})?[A-Za-z0-9+/])*(?:(?:${FWS})?=(?:(?:${FWS})?=)?)?$`);
const FIELD_NAME = '[\\x21-\\x39\\x3b-\\x7e]+';
const H_RE = new RegExp(`^${FIELD_NAME}(?:(?:${FWS})?:(?:${FWS})?${FIELD_NAME})*$`);

function splitMessage(msg) {
    let idx = msg.indexOf('\r\n\r\n');
    if (idx < 0) return { header: msg, body: '' };
    return { header: msg.slice(0, idx + 2), body: msg.slice(idx + 4) };
}

function parseFields(header) {
    let lines = header.split('\r\n');
    if (lines[lines.length - 1] === '') lines.pop();
    let fields = [];
    for (let l of lines) {
        if (/^[ \t]/.test(l) && fields.length) fields[fields.length - 1] += '\r\n' + l;
        else fields.push(l);
    }
    return fields.map(raw => {
        let c = raw.indexOf(':');
        let name = raw
            .slice(0, c)
            .replace(/\r\n(?=[ \t])/g, '')
            .replace(/[ \t]+$/, '');
        return { raw, name, lname: name.replace(/[A-Z]/g, x => x.toLowerCase()) };
    });
}

function canonHeaderRelaxed(raw) {
    let c = raw.indexOf(':');
    let name = raw.slice(0, c);
    let value = raw.slice(c + 1);
    name = name.replace(/[A-Z]/g, x => x.toLowerCase());
    // unfold: CRLF followed by WSP
    value = value.replace(/\r\n(?=[ \t])/g, '');
    name = name.replace(/\r\n(?=[ \t])/g, '');
    value = value.replace(/[ \t]+/g, ' ');
    name = name.replace(/[ \t]+/g, ' ');
    value = value.replace(/ $/, '');
    name = name.replace(/ $/, '').replace(/^ /, '');
    value = value.replace(/^ /, '');
    return name + ':' + value;
}

function canonBodySimple(body) {
    body = body.replace(/(\r\n)*$/, '');
    return body + '\r\n';
}

function canonBodyRelaxed(body) {
    if (!body.length) return '';
    let lines = body.split('\r\n');
    if (lines[lines.length - 1] === '') lines.pop();
    lines = lines.map(l => l.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
    while (lines.length && lines[lines.length - 1] === '') lines.pop();
    return lines.map(l => l + '\r\n').join('');
}

function parseTagList(value) {
    let specs = value.split(';');
    if (specs.length > 1 && /^(?:(?:[ \t]*\r\n)?[ \t]+)?$/.test(specs[specs.length - 1])) specs.pop();
    let tags = {};
    let errors = [];
    for (let spec of specs) {
        let m = spec.match(TAG_SPEC_RE);
        if (!m) {
            errors.push(`bad tag-spec ${JSON.stringify(spec)}`);
            continue;
        }
        if (!TAG_VALUE_RE.test(m[2])) errors.push(`bad tag-value for ${m[1]}: ${JSON.stringify(m[2])}`);
        if (m[1] in tags) errors.push(`duplicate tag ${m[1]}`);
        tags[m[1]] = m[2];
    }
    return { tags, errors };
}

const stripFWS = s => s.replace(/[ \t\r\n]+/g, '');

// Removes the value of the b= tag of a raw DKIM-Signature field (and whitespace around it)
function emptyB(raw) {
    let c = raw.indexOf(':');
    let head = raw.slice(0, c + 1);
    let value = raw.slice(c + 1);
    let specs = value.split(';');
    let found = 0;
    specs = specs.map(spec => {
        let m = spec.match(/^((?:(?:[ \t]*\r\n)?[ \t]+)?b(?:(?:[ \t]*\r\n)?[ \t]+)?=)([\s\S]*)$/);
        if (m) {
            found++;
            return m[1];
        }
        return spec;
    });
    if (found !== 1) throw new Error('b= tag found ' + found + ' times');
    return head + specs.join(';');
}

function validateSig(tags) {
    let e = [];
    for (let req of ['v', 'a', 'b', 'bh', 'd', 'h', 's']) if (!(req in tags)) e.push(`missing required ${req}=`);
    if ('v' in tags && tags.v !== '1') e.push(`v=${tags.v}`);
    if ('a' in tags && !['rsa-sha256', 'ed25519-sha256'].includes(tags.a)) e.push(`a=${tags.a} is not allowed for signing (RFC 8301)`);
    if ('b' in tags && !B64_RE.test(tags.b)) e.push('b= not base64string');
    if ('bh' in tags && !B64_RE.test(tags.bh)) e.push('bh= not base64string');
    if ('c' in tags && !/^(simple|relaxed)(\/(simple|relaxed))?$/.test(tags.c)) e.push(`c=${tags.c}`);
    if ('d' in tags && !DOMAIN_NAME_RE.test(tags.d)) e.push(`d=${JSON.stringify(tags.d)} is not domain-name`);
    if ('s' in tags && !SELECTOR_RE.test(tags.s)) e.push(`s=${JSON.stringify(tags.s)} is not selector`);
    if ('h' in tags) {
        if (!H_RE.test(tags.h)) e.push(`h=${JSON.stringify(tags.h)} is not sig-h-tag`);
        let names = tags.h.split(':').map(n => stripFWS(n).toLowerCase());
        if (!names.includes('from')) e.push('h= does not include from');
    }
    if ('l' in tags && !/^[0-9]{1,76}$/.test(tags.l)) e.push(`l=${tags.l}`);
    if ('t' in tags && !/^[0-9]{1,12}$/.test(tags.t)) e.push(`t=${tags.t} not 1*12DIGIT`);
    if ('x' in tags && !/^[0-9]{1,12}$/.test(tags.x)) e.push(`x=${tags.x} not 1*12DIGIT`);
    if ('t' in tags && 'x' in tags && !(Number(tags.x) > Number(tags.t))) e.push(`x=${tags.x} is not greater than t=${tags.t}`);
    if ('q' in tags && tags.q !== 'dns/txt') e.push(`q=${tags.q}`);
    if ('i' in tags) {
        let at = tags.i.lastIndexOf('@');
        if (at < 0) e.push(`i=${tags.i} has no @`);
        else {
            let dom = tags.i.slice(at + 1).toLowerCase();
            let d = (tags.d || '').toLowerCase();
            if (!(dom === d || dom.endsWith('.' + d))) e.push(`i= domain ${dom} not same as or subdomain of d=${d}`);
        }
    }
    return e;
}

// returns {ok, errors, details}
function verify(message, publicKey, opts = {}) {
    let errors = [];
    let { header, body } = splitMessage(message);
    let fields = parseFields(header);
    let sigIndex = opts.sigIndex || 0;
    let sigs = fields.filter(f => f.lname === 'dkim-signature');
    let sigField = sigs[sigIndex];
    if (!sigField) return { ok: false, errors: ['no DKIM-Signature'] };

    // RFC 5322 line length limit
    for (let line of message.split('\r\n')) {
        if (line.length > 998) errors.push(`line longer than 998 octets (${line.length})`);
    }

    let { tags, errors: tagErrors } = parseTagList(sigField.raw.slice(sigField.raw.indexOf(':') + 1));
    errors.push(...tagErrors);
    errors.push(...validateSig(tags, opts));

    let [hc, bc] = (tags.c || 'simple/simple').split('/');
    bc = bc || 'simple';

    let canonBody = bc === 'relaxed' ? canonBodyRelaxed(body) : canonBodySimple(body);
    if ('l' in tags) {
        let l = Number(tags.l);
        if (l > canonBody.length) errors.push(`l=${l} larger than canonicalized body ${canonBody.length}`);
        canonBody = canonBody.slice(0, l);
    }
    let hashAlg = 'sha256';
    let bh = crypto.createHash(hashAlg).update(Buffer.from(canonBody, 'latin1')).digest('base64');
    let bhOk = bh === stripFWS(tags.bh || '');
    if (!bhOk) errors.push(`bh mismatch: computed ${bh} header ${stripFWS(tags.bh || '')}`);

    // select headers
    let names = (tags.h || '').split(':').map(n => stripFWS(n).toLowerCase());
    let used = new Set();
    let data = '';
    for (let n of names) {
        for (let i = fields.length - 1; i >= 0; i--) {
            if (used.has(i) || fields[i].lname !== n) continue;
            if (fields[i] === sigField) continue;
            used.add(i);
            data += (hc === 'relaxed' ? canonHeaderRelaxed(fields[i].raw) : fields[i].raw) + '\r\n';
            break;
        }
    }
    let emptied = emptyB(sigField.raw);
    data += hc === 'relaxed' ? canonHeaderRelaxed(emptied) : emptied;

    let sig = Buffer.from(stripFWS(tags.b || ''), 'base64');
    let key = publicKey && publicKey.type === 'public' ? publicKey : crypto.createPublicKey(publicKey);
    let sigOk;
    if (key.asymmetricKeyType === 'rsa') {
        if (key.asymmetricKeyDetails.modulusLength < 1024) errors.push(`RSA key ${key.asymmetricKeyDetails.modulusLength} bits < 1024 (RFC 8301)`);
        sigOk = crypto.verify(tags.a === 'rsa-sha1' ? 'sha1' : 'sha256', Buffer.from(data, 'latin1'), key, sig);
    } else {
        sigOk = crypto.verify(null, crypto.createHash('sha256').update(Buffer.from(data, 'latin1')).digest(), key, sig);
    }
    if (!sigOk) errors.push('signature does not verify');
    return { ok: bhOk && sigOk && !errors.length, sigOk, bhOk, errors, tags, data, canonBody };
}

function signerCanonHeaderRelaxed(line) {
    let idx = line.indexOf(':');
    let name = line
        .slice(0, idx)
        .replace(/[ \t]+$/, '')
        .toLowerCase();
    let value = line
        .slice(idx + 1)
        .replace(/\r\n/g, '')
        .replace(/[ \t]+/g, ' ')
        .replace(/^ /, '')
        .replace(/ $/, '');
    return name + ':' + value;
}
function selectHeaders(headerLines, hList) {
    let used = new Set();
    let out = [];
    for (let name of hList) {
        for (let i = headerLines.length - 1; i >= 0; i--) {
            if (used.has(i)) continue;
            let n = headerLines[i].slice(0, headerLines[i].indexOf(':')).trim().toLowerCase();
            if (n === name.trim().toLowerCase()) {
                used.add(i);
                out.push(headerLines[i]);
                break;
            }
        }
    }
    return out;
}

/**
 * opts: headers (array of raw header lines, CRLF folded allowed, no trailing CRLF), body (string),
 * c ('relaxed/relaxed'), algo ('rsa-sha256'), key (private KeyObject), sigPrefix (string before b= value,
 * must contain bh=%BH% placeholder), sigSuffix (string after b= value), hList (array), l (number|undefined)
 * bodyHashAlgo override, headerHashAlgo override (for ed25519 prehash)
 */
function sign(opts) {
    let c = opts.c || 'simple/simple';
    let [hc, bc] = c.split('/');
    bc = bc || 'simple';
    let algo = opts.algo || 'rsa-sha256';
    let [signAlgo, hashAlgo] = algo.split('-');
    let body = opts.body;
    let cb = bc === 'relaxed' ? canonBodyRelaxed(body) : canonBodySimple(body);
    if (typeof opts.l === 'number') cb = cb.slice(0, opts.l);
    let bh = crypto
        .createHash(opts.bodyHashAlgo || hashAlgo)
        .update(Buffer.from(cb, 'binary'))
        .digest('base64');
    let prefix = opts.sigPrefix.replace('%BH%', bh);
    let suffix = opts.sigSuffix || '';
    let sigHeaderNoB = prefix + suffix;
    let signed = selectHeaders(opts.headers, opts.hList);
    let data = '';
    for (let h of signed) data += (hc === 'relaxed' ? signerCanonHeaderRelaxed(h) : h) + '\r\n';
    data += hc === 'relaxed' ? signerCanonHeaderRelaxed(sigHeaderNoB) : sigHeaderNoB;
    let buf = Buffer.from(data, 'binary');
    let sig;
    if (signAlgo === 'ed25519') {
        let h = crypto
            .createHash(opts.headerHashAlgo || 'sha256')
            .update(buf)
            .digest();
        sig = crypto.sign(null, h, opts.key);
    } else {
        sig = crypto.sign(opts.rsaHash || hashAlgo, buf, opts.key);
    }
    let b = sig.toString('base64');
    let sigHeader = prefix + b + suffix;
    let msg = sigHeader + '\r\n' + opts.headers.join('\r\n') + '\r\n\r\n' + body;
    return { msg, bh, b, canonData: data };
}

// A dns.promises.resolve compatible resolver for { name: [txt, ...] | Error }, logging queries
const resolverFrom = (records, log) => async (name, type) => {
    if (log) {
        log.push(`${type} ${name}`);
    }
    if (Object.prototype.hasOwnProperty.call(records, name)) {
        let value = records[name];
        if (value instanceof Error) {
            throw value;
        }
        return value.map(record => (Array.isArray(record) ? record : [record]));
    }
    let err = new Error('queryTxt ENOTFOUND ' + name);
    err.code = 'ENOTFOUND';
    throw err;
};

const spkiB64 = pub => pub.export({ type: 'spki', format: 'der' }).toString('base64');
const pkcs1B64 = pub => pub.export({ type: 'pkcs1', format: 'der' }).toString('base64');
const edRawB64 = pub => pub.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64');

module.exports = {
    sign,
    verify,
    resolverFrom,
    spkiB64,
    pkcs1B64,
    edRawB64,
    canonBodyRelaxed,
    canonBodySimple,
    canonHeaderRelaxed,
    parseTagList,
    emptyB
};
