'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { expect } = require('chai');

const { dkimSign, dkimVerify } = require('../../lib/mailauth');
const parseDkimHeaders = require('../../lib/parse-dkim-headers');
const { canonBodyRelaxed, resolverFrom, spkiB64, edRawB64 } = require('../helpers/dkim-reference');
const { fc, check, timeout, bytesFrom } = require('./helper');

const fixture = file => fs.readFileSync(`${__dirname}/../fixtures/${file}`);

// PEM, the privateKey option takes a string or a Buffer
const KEYS = {
    'rsa-sha256': fixture('private-rsa.pem'),
    'ed25519-sha256': fixture('private-ed25519.pem')
};

const DOMAIN = 'example.com';
const SELECTOR = 'sel';
const records = {
    'rsa-sha256': { [`${SELECTOR}._domainkey.${DOMAIN}`]: [`v=DKIM1; k=rsa; p=${spkiB64(crypto.createPublicKey(KEYS['rsa-sha256']))}`] },
    'ed25519-sha256': { [`${SELECTOR}._domainkey.${DOMAIN}`]: [`v=DKIM1; k=ed25519; p=${edRawB64(crypto.createPublicKey(KEYS['ed25519-sha256']))}`] }
};

const SIGN_TIME = new Date('2024-01-01T00:00:00Z');

// Header field names that are in the default list of signed fields, and one that is not
const SIGNED_FIELDS = ['To', 'Subject', 'Date', 'Message-ID', 'Cc', 'Reply-To'];
const UNSIGNED_FIELDS = ['X-Mailer', 'X-Spam-Score', 'x-custom'];
const isSigned = field => !UNSIGNED_FIELDS.some(name => name.toLowerCase() === field.name.toLowerCase());

// A header value: text with 8-bit bytes and specials, runs of whitespace, trailing whitespace,
// and folds (CRLF or a bare LF followed by whitespace). It always starts with a visible
// character, so the field is never empty
const headerValue = fc
    .tuple(
        bytesFrom('aZ09.@<>"(),;:\\\xe9\xff'),
        fc.array(fc.tuple(fc.constantFrom(' ', '\t', '  ', ' \t ', '\r\n ', '\r\n\t', '\n '), bytesFrom('aZ09.@<>"()\xe9', { minLength: 1, maxLength: 20 })), {
            maxLength: 6
        }),
        fc.constantFrom('', ' ', '\t', ' \t')
    )
    .map(([first, rest, trailing]) => 'v' + first + rest.map(([ws, word]) => ws + word).join('') + trailing);

const headerName = fc.constantFrom(...SIGNED_FIELDS, ...UNSIGNED_FIELDS, 'subject', 'TO');

// Header section: From first, then fields with unique names (in any case), so that each signed
// name has one instance and mutating it always changes what the signature covers
const headerFields = fc
    .tuple(
        headerValue,
        fc.uniqueArray(fc.tuple(headerName, headerValue, fc.constantFrom(': ', ':', ' : ', ':\t')), {
            maxLength: 6,
            selector: ([name]) => name.toLowerCase()
        })
    )
    .map(([fromValue, fields]) => [{ name: 'From', value: fromValue, sep: ': ' }, ...fields.map(([name, value, sep]) => ({ name, value, sep }))]);

// Body bytes: bare LF, bare CR, trailing whitespace, empty lines at the end, 8-bit bytes, and
// sometimes a line much longer than 998 octets
const body = fc.oneof(
    { weight: 4, arbitrary: bytesFrom('ab \t\r\n\xe9\x00', { maxLength: 300 }) },
    { weight: 1, arbitrary: fc.constant('') },
    { weight: 1, arbitrary: fc.tuple(bytesFrom('ab \t\r\n'), fc.integer({ min: 990, max: 1100 })).map(([s, n]) => 'x'.repeat(n) + s) }
);

const canonicalization = fc.constantFrom('simple/simple', 'simple/relaxed', 'relaxed/simple', 'relaxed/relaxed');
const algorithm = fc.constantFrom('rsa-sha256', 'ed25519-sha256');
const maxBodyLength = fc.option(fc.nat({ max: 400 }), { nil: undefined });

const signedMessage = fc.record({ fields: headerFields, body, canonicalization, algorithm, maxBodyLength });

const buildMessage = ({ fields, body }) => fields.map(field => `${field.name}${field.sep}${field.value}\r\n`).join('') + '\r\n' + body;

const sign = async opts => {
    let message = Buffer.from(buildMessage(opts), 'latin1');
    let { signatures, errors } = await dkimSign(message, {
        canonicalization: opts.canonicalization,
        signTime: SIGN_TIME,
        signatureData: [
            {
                signingDomain: DOMAIN,
                selector: SELECTOR,
                privateKey: KEYS[opts.algorithm],
                algorithm: opts.algorithm,
                maxBodyLength: opts.maxBodyLength
            }
        ]
    });
    expect(errors).to.deep.equal([]);
    expect(signatures).to.match(/^DKIM-Signature: /);
    return signatures;
};

const verify = async (signatures, rawMessage, algorithm, strict) => {
    let result = await dkimVerify(Buffer.concat([Buffer.from(signatures), Buffer.from(rawMessage, 'latin1')]), {
        resolver: resolverFrom(records[algorithm]),
        curTime: SIGN_TIME,
        strict
    });
    expect(result.results).to.have.lengthOf(1);
    return result.results[0];
};

// The canonicalized body as RFC 6376 section 3.4 defines it, after the message parser has
// turned every bare LF into a CRLF (which it does for signing and verifying alike)
const canonicalBody = (canon, raw) => {
    let normalized = raw.replace(/\r?\n/g, '\r\n');
    return canon.split('/')[1] === 'relaxed' ? canonBodyRelaxed(normalized) : normalized.replace(/(?:\r\n)*$/, '') + '\r\n';
};

const signedBodyLength = signatures => {
    let l = parseDkimHeaders(signatures.replace(/\r\n$/, '')).parsed.l;
    return l ? l.value : undefined;
};

describe('Property: DKIM sign and verify round trip', function () {
    this.timeout(timeout(100, 60));

    it('verifies its own signature for any message, canonicalization, algorithm and l=', () =>
        check(
            fc.asyncProperty(signedMessage, async opts => {
                let signatures = await sign(opts);
                let raw = buildMessage(opts);

                let result = await verify(signatures, raw, opts.algorithm, false);
                expect(result.status.result, result.status.comment).to.equal('pass');

                let l = signedBodyLength(signatures);
                if (opts.maxBodyLength === undefined) {
                    expect(l).to.equal(undefined);
                } else {
                    expect(l).to.be.at.most(opts.maxBodyLength);
                }
            }),
            100
        ));

    it('verifies its own signature in the strict mode', () =>
        check(
            fc.asyncProperty(signedMessage, async opts => {
                let signatures = await sign(opts);
                let result = await verify(signatures, buildMessage(opts), opts.algorithm, true);
                expect(result.status.result, result.status.comment).to.equal('pass');
            }),
            50
        ));

    it('does not pass once a byte of the signed body changes', () =>
        check(
            fc.asyncProperty(signedMessage, fc.nat(), fc.constantFrom(...'aZ0 \t\r\n\xe9.'.split('')), async (opts, pos, replacement) => {
                fc.pre(opts.body.length > 0);
                pos = pos % opts.body.length;
                fc.pre(opts.body.charAt(pos) !== replacement);

                let signatures = await sign(opts);
                let mutatedBody = opts.body.slice(0, pos) + replacement + opts.body.slice(pos + 1);
                let mutated = buildMessage({ fields: opts.fields, body: mutatedBody });

                // whether the change is visible in the signed part of the canonicalized body
                let l = signedBodyLength(signatures);
                let before = canonicalBody(opts.canonicalization, opts.body);
                let after = canonicalBody(opts.canonicalization, mutatedBody);
                let covered = l === undefined ? before !== after : before.slice(0, l) !== after.slice(0, l);

                let result = await verify(signatures, mutated, opts.algorithm, false);
                if (covered) {
                    expect(result.status.result).to.not.equal('pass');
                } else {
                    // whitespace that the canonicalization removes, or a change after l=
                    expect(result.status.result, result.status.comment).to.equal('pass');
                }
            }),
            150
        ));

    it('does not pass once a visible character of a signed header field changes', () =>
        check(
            fc.asyncProperty(signedMessage, fc.nat(), fc.nat(), fc.constantFrom(...'aZ0.@<>"\xe9'.split('')), async (opts, fieldPos, charPos, replacement) => {
                let signedFields = opts.fields.filter(isSigned);
                let field = signedFields[fieldPos % signedFields.length];

                // the visible characters of the value, whitespace and folds are not touched
                let positions = [];
                for (let i = 0; i < field.value.length; i++) {
                    if (!/[\s]/.test(field.value.charAt(i)) && field.value.charAt(i) !== replacement) {
                        positions.push(i);
                    }
                }
                fc.pre(positions.length > 0);
                let pos = positions[charPos % positions.length];

                let signatures = await sign(opts);
                let mutatedFields = opts.fields.map(entry =>
                    entry === field ? Object.assign({}, entry, { value: entry.value.slice(0, pos) + replacement + entry.value.slice(pos + 1) }) : entry
                );

                let result = await verify(signatures, buildMessage({ fields: mutatedFields, body: opts.body }), opts.algorithm, false);
                expect(result.status.result).to.not.equal('pass');
            }),
            150
        ));

    it('still passes when an unsigned header field changes', () =>
        check(
            fc.asyncProperty(signedMessage, headerValue, async (opts, value) => {
                let signatures = await sign(opts);
                let fields = opts.fields.filter(isSigned).concat({ name: 'X-Mailer', value, sep: ': ' });
                let result = await verify(signatures, buildMessage({ fields, body: opts.body }), opts.algorithm, false);
                expect(result.status.result, result.status.comment).to.equal('pass');
            }),
            50
        ));
});
