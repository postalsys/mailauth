'use strict';

// An independent, deliberately simple reading of draft-ietf-dkim-dkim2-spec-06, used as a test
// oracle for lib/dkim2. It works on whole strings, shares no code with the library and follows
// the steps of sections 5, 6 and 9.6 literally.

const crypto = require('node:crypto');

// section 4.1, typed in again from the draft
const UNSIGNED = [
    'apparently-to',
    'arc-authentication-results',
    'arc-message-signature',
    'arc-seal',
    'authentication-results',
    'auto-submitted',
    'delivered-to',
    'dkim-signature',
    'dl-expansion-history',
    'original-recipient',
    'received',
    'return-path',
    'sio-label-history',
    'vbr-info',
    'x400-received',
    'x400-trace'
];

const isIgnored = name => UNSIGNED.includes(name) || /^received-/.test(name) || /^x-/.test(name) || name === 'message-instance' || name === 'dkim2-signature';

// Splits a message ('binary' string with CRLF line endings) into unfolded header fields and the body
const splitMessage = message => {
    let pos = message.indexOf('\r\n\r\n');
    let head = pos >= 0 ? message.slice(0, pos) : message;
    let body = pos >= 0 ? message.slice(pos + 4) : '';
    let fields = head
        .replace(/\r\n(?=[ \t])/g, '')
        .split('\r\n')
        .filter(line => line)
        .map(line => {
            let colon = line.indexOf(':');
            return { name: line.slice(0, colon).trim().toLowerCase(), value: line.slice(colon + 1) };
        });
    return { fields, body };
};

// section 6.2 for one field: lower case name, WSP runs to one SP, no WSP at the end or around the colon
const canonicalField = (name, value) => `${name}:${value.replace(/[ \t]+/g, ' ').replace(/^ | $/g, '')}\r\n`;

// fields: [{ name, value }] top down. Returns the concatenation section 6.2 hashes
const headerHashInput = fields => {
    let kept = fields.filter(field => !isIgnored(field.name)).map(field => ({ name: field.name, canonical: canonicalField(field.name, field.value) }));
    let names = Array.from(new Set(kept.map(field => field.name))).sort();
    let output = '';
    for (let name of names) {
        // same name: the last one in the header first
        let sameName = kept.filter(field => field.name === name).reverse();
        for (let field of sameName) {
            output += field.canonical;
        }
    }
    return output;
};

const headerHash = (fields, algorithm) =>
    crypto
        .createHash(algorithm)
        .update(Buffer.from(headerHashInput(fields), 'binary'))
        .digest('base64');

// section 6.1: "*CRLF" at the end becomes a single CRLF, an empty body is one CRLF
const bodyHash = (body, algorithm) =>
    crypto
        .createHash(algorithm)
        .update(Buffer.from(body.replace(/(\r\n)*$/, '') + '\r\n', 'binary'))
        .digest('base64');

// section 9.6 for one field: lower case name, no WSP at all
const signatureField = (name, value) => `${name}:${value.replace(/[ \t]/g, '')}\r\n`;

const getTag = (value, tag) => {
    for (let part of value.replace(/[ \t]/g, '').split(';')) {
        let eq = part.indexOf('=');
        if (eq > 0 && part.slice(0, eq).toLowerCase() === tag) {
            return part.slice(eq + 1);
        }
    }
    return null;
};

// The signature input for DKIM2-Signature i=<i> of a message
const signatureInput = (message, i) => {
    let { fields } = splitMessage(message);
    let instances = fields.filter(field => field.name === 'message-instance');
    let signatures = fields.filter(field => field.name === 'dkim2-signature');
    let target = signatures.find(field => Number(getTag(field.value, 'i')) === i);
    let m = Number(getTag(target.value, 'm'));

    let output = '';
    instances
        .filter(field => Number(getTag(field.value, 'm')) <= m)
        .sort((a, b) => Number(getTag(a.value, 'm')) - Number(getTag(b.value, 'm')))
        .forEach(field => (output += signatureField(field.name, field.value)));
    signatures
        .filter(field => Number(getTag(field.value, 'i')) < i)
        .sort((a, b) => Number(getTag(a.value, 'i')) - Number(getTag(b.value, 'i')))
        .forEach(field => (output += signatureField(field.name, field.value)));

    // the signature values of s= emptied
    let blanked = target.value
        .replace(/[ \t]/g, '')
        .split(';')
        .map(part => (/^s=/i.test(part) ? part.replace(/:[A-Za-z0-9+/=]+(?=,|$)/g, ':') : part))
        .join(';');
    output += `dkim2-signature:${blanked}\r\n`;
    return Buffer.from(output, 'binary');
};

// Checks one signature value with a public key
const verifySignatureValue = (message, i, selector, publicKey) => {
    let { fields } = splitMessage(message);
    let target = fields.find(field => field.name === 'dkim2-signature' && Number(getTag(field.value, 'i')) === i);
    let set = getTag(target.value, 's')
        .split(',')
        .map(entry => entry.split(':'))
        .find(entry => entry[0] === selector);
    let input = signatureInput(message, i);
    let signature = Buffer.from(set[2], 'base64');
    if (set[1] === 'ed25519-sha256') {
        return crypto.verify(null, crypto.createHash('sha256').update(input).digest(), publicKey, signature);
    }
    return crypto.verify('sha256', input, publicKey, signature);
};

// Section 5: recreates the previous message from a Recipe. Header fields of one name are numbered
// from the bottom, body lines from the top. Returns { fields, body }, body null when unrecoverable
const applyRecipe = ({ fields, body }, recipe) => {
    let previousFields = fields.slice();
    for (let name of Object.keys(recipe.h || {})) {
        let current = fields.filter(field => field.name === name).reverse();
        let emitted = [];
        for (let step of recipe.h[name]) {
            if (step.c) {
                emitted.push(...current.slice(step.c[0] - 1, step.c[1]));
            } else {
                emitted.push(...step.d.map(value => ({ name, value })));
            }
        }
        // later output goes above earlier output, so reverse it into top down order
        previousFields = previousFields.filter(field => field.name !== name).concat(emitted.reverse());
    }

    let previousBody = body;
    if (recipe.b === null) {
        previousBody = null;
    } else if (recipe.b) {
        let lines = body.split('\r\n');
        if (body.endsWith('\r\n')) {
            lines.pop();
        }
        let out = [];
        for (let step of recipe.b) {
            if (step.c) {
                out.push(...lines.slice(step.c[0] - 1, step.c[1]));
            } else {
                out.push(...step.d);
            }
        }
        previousBody = out.map(line => line + '\r\n').join('');
    }

    return { fields: previousFields, body: previousBody };
};

module.exports = { splitMessage, headerHashInput, headerHash, bodyHash, signatureInput, verifySignatureValue, applyRecipe, getTag };
