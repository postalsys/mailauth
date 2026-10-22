/* eslint @typescript-eslint/no-unused-expressions:0 */
import { describe, it } from 'node:test';
import { expect, config } from 'chai';
import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { dkimSign } from '../../src/dkim/sign.js';
import { dkimVerify } from '../../src/dkim/verify.js';
import { sign, resolverFrom, spkiB64, pkcs1B64, edRawB64, canonBodyRelaxed } from '../helpers/dkim-reference.js';
import { privateKey } from '../helpers/keys.js';
import { opendkimBin, opendkimSign, opendkimVerify } from '../helpers/opendkim.js';
import type { OpendkimSignOptions } from '../helpers/opendkim.js';

config.includeStack = true;

// Compares mailauth with OpenDKIM (libopendkim 2.11, run through test/helpers/opendkim.ts): what
// one signs the other verifies, and both verify the same crafted and damaged messages. The two
// agree on everything here except the cases in "where OpenDKIM differs", where each test says
// which side follows RFC 6376. None of those differences is a mailauth defect.
//
// Skipped when OpenDKIM is not installed. `OPENDKIM=test/helpers/opendkim-docker.sh` runs it in
// a container, `OPENDKIM_REQUIRED=1` turns the skip into a failure (CI installs OpenDKIM). The
// messages and signatures are built inside the suite, so a skipped suite costs nothing.

if (!opendkimBin && process.env.OPENDKIM_REQUIRED) {
    throw new Error('OpenDKIM not found and OPENDKIM_REQUIRED is set');
}

const skip = opendkimBin ? false : 'OpenDKIM not found, set OPENDKIM=test/helpers/opendkim-docker.sh to run it in a container';

const rsaPem = privateKey('private-rsa.pem');
const edPem = privateKey('private-ed25519.pem');
const rsa = crypto.createPrivateKey(rsaPem);
const ed = crypto.createPrivateKey(edPem);
const rsaPub = crypto.createPublicKey(rsa);

const P = spkiB64(rsaPub);
const rsaRec = `v=DKIM1; k=rsa; p=${P}`;
const edRec = `v=DKIM1; k=ed25519; p=${edRawB64(crypto.createPublicKey(ed))}`;
const KEYS: Record<string, string> = {
    'rsa._domainkey.example.com': rsaRec,
    'ed._domainkey.example.com': edRec,
    'rsa._domainkey.sub.example.com': rsaRec
};
const SEL_KEYS = { 'sel._domainkey.example.com': rsaRec };

const verifyResults = async (message: Buffer, keys: Record<string, string>, strict = false) => {
    let resolver = resolverFrom(Object.fromEntries(Object.entries(keys).map(([name, record]) => [name, [record]])));
    // DNS names are case-insensitive, d= and s= are queried as written
    return (await dkimVerify(message, { resolver: (name, type) => resolver(name.toLowerCase(), type), strict })).results;
};

// A message as a latin1 string, so that every character is one octet
const bin = (message: string) => Buffer.from(message, 'binary');

// Header fields (each ending with CRLF) put on top of a message
const prepend = (fields: string, message: Buffer) => Buffer.concat([Buffer.from(fields), message]);

// Signs with OpenDKIM as rsa._domainkey.example.com unless told otherwise, the signature ends with CRLF
const odSign = async (message: Buffer, opts: Partial<OpendkimSignOptions> = {}) =>
    (await opendkimSign(message, Object.assign({ domain: 'example.com', selector: 'rsa', privateKey: rsaPem }, opts))) + '\r\n';

const HEADERS = [
    'From: Joe <joe@example.com>',
    'To: suzie@example.net',
    'Subject: Is dinner ready?',
    'Date: Fri, 11 Jul 2003 21:00:37 -0700',
    'Message-ID: <1@example.com>'
];
const BODY = 'Hi.\r\n\r\nWe lost the game.  Are you hungry yet?\r\n\r\nJoe.\r\n';
const message = (headers: string[], body: string) => headers.join('\r\n') + '\r\n\r\n' + body;

// A real message, without its own signatures, line endings normalized
const stripSignatures = (raw: string) => {
    let [header, ...body] = raw.replace(/\r?\n/g, '\r\n').split('\r\n\r\n');
    let lines: string[] = [];
    let skipField = false;
    for (let line of header.split('\r\n')) {
        if (!/^[ \t]/.test(line)) {
            skipField = /^(dkim-signature|arc-|authentication-results|x-google-dkim)/i.test(line);
        }
        if (!skipField) {
            lines.push(line);
        }
    }
    return lines.join('\r\n') + '\r\n\r\n' + body.join('\r\n\r\n');
};

// Messages both implementations canonicalize the same way. Every line ends with CRLF and every
// header colon is followed by one space, as the OpenDKIM test mode would change anything else
const buildMessages = (): Record<string, string> => ({
    basic: message(HEADERS, BODY),
    'trailing whitespace': message(HEADERS, 'trailing spaces   \r\n\tleading tab\t \r\n  \r\n\t\r\nend\t\t \r\n \r\n\r\n\r\n'),
    'empty body': message(HEADERS, ''),
    'body of one empty line': message(HEADERS, '\r\n'),
    'body of empty lines': message(HEADERS, '\r\n\r\n\r\n\r\n'),
    'body of whitespace lines': message(HEADERS, '   \r\n\t\r\n'),
    'folded headers': message(
        [
            'From: Joe\r\n  <joe@example.com>',
            'To: a@example.net,\r\n\tb@example.net,\r\n    c@example.net',
            'SUBJECT: tabs\tand   spaces  \t',
            'date: Fri, 11 Jul 2003 21:00:37 -0700'
        ],
        'x\r\n'
    ),
    '8-bit': message(
        ['From: J\u00c3\u00b5gi <joe@example.com>', 'To: s\u00c3\u00bczie@example.net', 'Subject: tere \u00c3\u00b1', 'Date: Fri, 11 Jul 2003 21:00:37 -0700'],
        'Tere, maailm! \u00e2\u009c\u0093\r\n'
    ),
    'repeated headers': message(
        ['From: Joe <joe@example.com>', 'To: a@example.net', 'Subject: first', 'To: b@example.net', 'Subject: second', 'Date: Fri, 11 Jul 2003 21:00:37 -0700'],
        'x\r\n'
    ),
    'long lines': message(HEADERS, 'a'.repeat(998) + '\r\n' + 'b '.repeat(499) + '\r\n'),
    'many trailing empty lines': message(HEADERS, 'x\r\n' + '\r\n'.repeat(100000)),
    'many whitespace lines': message(HEADERS, '  \t \r\n'.repeat(40000) + 'end\r\n' + ' \r\n'.repeat(40000)),
    'long whitespace runs': message(HEADERS, 'a' + ' '.repeat(200000) + 'b\r\n' + '\t'.repeat(70000) + '\r\n'),
    'real message': stripSignatures(fs.readFileSync(new URL('../fixtures/message3.eml', import.meta.url)).toString('binary'))
});

const CANONICALIZATIONS = ['simple/simple', 'relaxed/relaxed', 'simple/relaxed', 'relaxed/simple'];

const ALGORITHMS = [
    { algorithm: 'rsa-sha256', selector: 'rsa', privateKey: rsaPem },
    { algorithm: 'rsa-sha1', selector: 'rsa', privateKey: rsaPem },
    { algorithm: 'ed25519-sha256', selector: 'ed', privateKey: edPem }
];

// A signed message made with the reference signer from a literal tag list, for the cases that
// need tags mailauth would not write. `extra` goes before h=
interface CraftOptions {
    algo?: string;
    signAlgo?: string;
    c?: string;
    signC?: string;
    d?: string;
    s?: string;
    h?: string;
    extra?: string;
    rawTags?: string;
    suffix?: string;
    headers?: string[];
    body?: string;
    key?: crypto.KeyObject;
    l?: number;
}

const craft = (o: CraftOptions = {}) => {
    let a = o.algo || 'rsa-sha256';
    let c = o.c || 'relaxed/relaxed';
    let h = o.h || 'from:to:subject:date';
    let tags = o.rawTags || `v=1; a=${a}; c=${c}; d=${o.d ?? 'example.com'}; s=${o.s || 'sel'};${o.extra || ''} h=${h}; bh=%BH%; b=`;
    return sign({
        headers: o.headers || HEADERS,
        body: o.body ?? BODY,
        c: o.signC || c,
        algo: o.signAlgo || a,
        key: o.key || rsa,
        sigPrefix: 'DKIM-Signature: ' + tags,
        sigSuffix: o.suffix || '',
        hList: (tags.match(/(?:^|;)\s*h\s*=([^;]*)/)?.[1] || h).split(':').map(name => name.trim()),
        l: o.l
    }).msg;
};

const NOW = Math.floor(Date.now() / 1000);
const BODY_LENGTH = canonBodyRelaxed(BODY).length;

interface DifferentialCase {
    name: string;
    message: string;
    keys?: Record<string, string>;
    // the results of mailauth (default mode), mailauth (strict mode) and OpenDKIM, one per
    // signature, separated by spaces. "-" is OpenDKIM accepting the message without a verdict
    expected: string;
}

// Key record variations, the signature is the baseline relaxed/relaxed one
const keyCase = (name: string, record: string, expected: string, o?: CraftOptions): DifferentialCase => ({
    name: `key record: ${name}`,
    message: craft(o),
    keys: { 'sel._domainkey.example.com': record },
    expected
});

// Changes in transit after a baseline signature: [name, change, simple/simple result, relaxed/relaxed result]
const CHANGES: Array<[string, (m: string) => string, string, string]> = [
    ['body appended', m => m + 'more\r\n', 'neutral fail fail', 'neutral fail fail'],
    ['empty line appended to the body', m => m + '\r\n', 'pass pass pass', 'pass pass pass'],
    ['trailing whitespace in the body', m => m.replace('Joe.\r\n', 'Joe.  \r\n'), 'neutral fail fail', 'pass pass pass'],
    ['whitespace in a body line', m => m.replace('the game', 'the  game'), 'neutral fail fail', 'pass pass pass'],
    ['tab for space in the body', m => m.replace('the game', 'the\tgame'), 'neutral fail fail', 'pass pass pass'],
    ['whitespace on an empty body line', m => m.replace('Hi.\r\n\r\n', 'Hi.\r\n \r\n'), 'neutral fail fail', 'pass pass pass'],
    ['Subject changed', m => m.replace('Is dinner ready?', 'Is dinner ready!'), 'fail fail fail', 'fail fail fail'],
    ['Subject name in upper case', m => m.replace('Subject:', 'SUBJECT:'), 'fail fail fail', 'pass pass pass'],
    ['whitespace in Subject', m => m.replace('Subject: Is dinner', 'Subject: Is  dinner'), 'fail fail fail', 'pass pass pass'],
    ['Subject refolded', m => m.replace('Subject: Is dinner', 'Subject: Is\r\n dinner'), 'fail fail fail', 'pass pass pass'],
    ['trailing whitespace in Subject', m => m.replace('ready?', 'ready? '), 'fail fail fail', 'pass pass pass'],
    ['From added above', m => m.replace('From: Joe', 'From: Evil <evil@example.org>\r\nFrom: Joe'), 'pass pass pass', 'pass pass pass'],
    ['From added below', m => m.replace('\r\n\r\n', '\r\nFrom: Evil <evil@example.org>\r\n\r\n'), 'fail fail fail', 'fail fail fail'],
    ['Subject added above', m => m.replace('From: Joe', 'Subject: other\r\nFrom: Joe'), 'pass pass pass', 'pass pass pass'],
    ['Subject added below', m => m.replace('\r\n\r\n', '\r\nSubject: other\r\n\r\n'), 'fail fail fail', 'fail fail fail'],
    ['unsigned header added', m => m.replace('\r\n\r\n', '\r\nX-Foo: bar\r\n\r\n'), 'pass pass pass', 'pass pass pass'],
    [
        'headers reordered',
        m => m.replace('To: suzie@example.net\r\nSubject: Is dinner ready?', 'Subject: Is dinner ready?\r\nTo: suzie@example.net'),
        'pass pass pass',
        'pass pass pass'
    ],
    ['signed header removed', m => m.replace('To: suzie@example.net\r\n', ''), 'fail fail fail', 'fail fail fail'],
    ['signature refolded', m => m.replace('; d=', ';\r\n d='), 'fail fail fail', 'pass pass pass'],
    ['whitespace in the signature', m => m.replace('; d=', ';  d='), 'fail fail fail', 'pass pass pass'],
    ['signature header name in lower case', m => m.replace(/^DKIM-Signature:/, 'dkim-signature:'), 'fail fail fail', 'pass pass pass']
];

// Cases where mailauth and OpenDKIM agree. mailauth reports some failures as neutral where
// OpenDKIM uses fail or permerror, the default mode reports a body hash mismatch as neutral and
// skips a signature it can not process (none)
const buildAgreeingCases = (): DifferentialCase[] => {
    let small = crypto.createPrivateKey(privateKey('private-small.pem'));
    let rsa1024 = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;

    return [
        ...CANONICALIZATIONS.map(c => ({ name: `baseline ${c}`, message: craft({ c }), expected: 'pass pass pass' })),
        { name: 'c=relaxed, the body defaults to simple', message: craft({ c: 'relaxed', signC: 'relaxed/simple' }), expected: 'pass pass pass' },
        {
            name: 'c missing, simple/simple',
            message: craft({ rawTags: 'v=1; a=rsa-sha256; d=example.com; s=sel; h=from:to:subject:date; bh=%BH%; b=', signC: 'simple/simple' }),
            expected: 'pass pass pass'
        },
        { name: 'c=foo/bar', message: craft({ c: 'foo/bar', signC: 'relaxed/relaxed' }), expected: 'none neutral permerror' },
        { name: 'c in upper case', message: craft({ c: 'Relaxed/Relaxed', signC: 'relaxed/relaxed' }), expected: 'pass pass pass' },
        { name: 'a=rsa-sha512', message: craft({ algo: 'rsa-sha512' }), expected: 'none neutral permerror' },
        { name: 'a in upper case', message: craft({ algo: 'RSA-SHA256', signAlgo: 'rsa-sha256' }), expected: 'pass pass pass' },
        { name: 'ed25519', message: craft({ algo: 'ed25519-sha256', key: ed }), keys: { 'sel._domainkey.example.com': edRec }, expected: 'pass pass pass' },
        { name: 'ed25519 signature, RSA key', message: craft({ algo: 'ed25519-sha256', key: ed }), expected: 'neutral neutral permerror' },
        { name: 'RSA signature, ed25519 key', message: craft(), keys: { 'sel._domainkey.example.com': edRec }, expected: 'neutral neutral permerror' },
        {
            name: '512-bit key',
            message: craft({ key: small }),
            keys: { 'sel._domainkey.example.com': `v=DKIM1; k=rsa; p=${spkiB64(crypto.createPublicKey(small))}` },
            expected: 'policy policy policy'
        },
        {
            name: '1024-bit key',
            message: craft({ key: rsa1024 }),
            keys: { 'sel._domainkey.example.com': `v=DKIM1; k=rsa; p=${spkiB64(crypto.createPublicKey(rsa1024))}` },
            expected: 'pass pass pass'
        },
        {
            name: 'v not the first tag',
            message: craft({ rawTags: 'a=rsa-sha256; v=1; c=relaxed/relaxed; d=example.com; s=sel; h=from:to:subject:date; bh=%BH%; b=' }),
            expected: 'pass pass pass'
        },
        { name: 'unknown tag', message: craft({ extra: ' zz=foo bar;' }), expected: 'pass pass pass' },
        { name: 'trailing semicolon', message: craft({ suffix: ';' }), expected: 'pass pass pass' },
        {
            name: 'tags after b=',
            message: craft({ rawTags: 'v=1; a=rsa-sha256; b=', suffix: '; c=relaxed/relaxed; d=example.com; s=sel; h=from:to:subject:date; bh=%BH%' }),
            expected: 'neutral fail fail'
        },
        {
            name: 'whitespace around = of other tags',
            message: craft({ rawTags: 'v = 1; a = rsa-sha256; c = relaxed/relaxed; d = example.com ; s = sel ; h=from : to : subject : date; bh = %BH% ; b=' }),
            expected: 'pass pass pass'
        },
        {
            name: 'whitespace around the = of h=',
            message: craft({ rawTags: 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; h = from:to; bh=%BH%; b=' }),
            expected: 'pass pass pass'
        },
        {
            name: 'folded tag list',
            message: craft({
                rawTags: 'v=1;\r\n\ta=rsa-sha256;\r\n c=relaxed/relaxed; d=example.com;\r\n\ts=sel; h=from:\r\n\tto:subject:date; bh=%BH%;\r\n\tb='
            }),
            expected: 'pass pass pass'
        },
        { name: 'd= in upper case', message: craft({ d: 'EXAMPLE.COM' }), expected: 'pass pass pass' },
        { name: 's= in upper case', message: craft({ s: 'SEL' }), expected: 'pass pass pass' },
        { name: 's= with a dot', message: craft({ s: 'a.b' }), keys: { 'a.b._domainkey.example.com': rsaRec }, expected: 'pass pass pass' },
        { name: 'b= empty', message: craft().replace(/b=[A-Za-z0-9+/=]+/, 'b='), expected: 'fail fail permerror' },
        { name: 'b= changed', message: craft().replace(/b=[A-Za-z0-9+/=]{4}/, 'b=AAAA'), expected: 'fail fail fail' },
        { name: 'b= not base64', message: craft().replace(/b=[A-Za-z0-9+/=]{4}/, 'b=!!!!'), expected: 'fail fail fail' },
        { name: 'bh= changed', message: craft().replace(/bh=[A-Za-z0-9+/=]{4}/, 'bh=AAAA'), expected: 'neutral fail fail' },
        {
            name: 'bh missing',
            message: craft({ rawTags: 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; h=from:to:subject:date; b=' }),
            expected: 'neutral neutral permerror'
        },
        { name: 'h without from', message: craft({ h: 'to:subject:date' }), expected: 'neutral neutral permerror' },
        { name: 'h from only', message: craft({ h: 'from' }), expected: 'pass pass pass' },
        { name: 'h in upper case', message: craft({ h: 'FROM:To:SUBJECT' }), expected: 'pass pass pass' },
        { name: 'h lists an absent header', message: craft({ h: 'from:to:subject:date:reply-to' }), expected: 'pass pass pass' },
        { name: 'h over-signs from', message: craft({ h: 'from:from:to:subject:date' }), expected: 'pass pass pass' },
        { name: 'h lists DKIM-Signature', message: craft({ h: 'from:dkim-signature' }), expected: 'fail fail fail' },
        { name: 'h with an empty name', message: craft({ h: 'from::to' }), expected: 'pass pass pass' },
        { name: 'q=dns/txt', message: craft({ extra: ' q=dns/txt;' }), expected: 'pass pass pass' },
        { name: 'q=foo:dns/txt', message: craft({ extra: ' q=foo:dns/txt;' }), expected: 'pass pass pass' },
        { name: 'i=@example.com', message: craft({ extra: ' i=@example.com;' }), expected: 'pass pass pass' },
        { name: 'i= in a subdomain', message: craft({ extra: ' i=user@sub.example.com;' }), expected: 'pass pass pass' },
        { name: 'i= in upper case', message: craft({ extra: ' i=@EXAMPLE.COM;' }), expected: 'pass pass pass' },
        { name: 'i= quoted-printable', message: craft({ extra: ' i=j=C3=B5gi@example.com;' }), expected: 'pass pass pass' },
        { name: 't= in the past', message: craft({ extra: ` t=${NOW - 3600};` }), expected: 'pass pass pass' },
        { name: 'x= in the future', message: craft({ extra: ` t=${NOW - 3600}; x=${NOW + 3600};` }), expected: 'pass pass pass' },
        { name: 'x= expired', message: craft({ extra: ` t=${NOW - 7200}; x=${NOW - 3600};` }), expected: 'neutral neutral permerror' },
        { name: 'x= before t=', message: craft({ extra: ` t=${NOW - 3600}; x=${NOW - 7200};` }), expected: 'neutral neutral permerror' },
        { name: 'x= without t=', message: craft({ extra: ` x=${NOW + 3600};` }), expected: 'pass pass pass' },
        { name: 'l=0', message: craft({ l: 0, extra: ' l=0;' }), expected: 'pass pass pass' },
        { name: 'l= the body length', message: craft({ l: BODY_LENGTH, extra: ` l=${BODY_LENGTH};` }), expected: 'pass pass pass' },
        { name: 'l= a part of the body', message: craft({ l: 10, extra: ' l=10;' }), expected: 'pass pass pass' },
        { name: 'l= a part of the body, more appended', message: craft({ l: 10, extra: ' l=10;' }) + 'APPENDED\r\n', expected: 'pass pass pass' },
        { name: 'l= with leading zeros', message: craft({ l: 10, extra: ' l=010;' }), expected: 'pass pass pass' },
        { name: 'l= not a number', message: craft({ l: 10, extra: ' l=abc;' }), expected: 'neutral neutral permerror' },
        {
            name: 'two signatures, the first one bad',
            message:
                craft()
                    .split('\r\n')[0]
                    .replace(/b=[A-Za-z0-9+/=]{4}/, 'b=AAAA') +
                '\r\n' +
                craft(),
            expected: 'fail,pass fail,pass fail,pass'
        },

        keyCase('no v=', `k=rsa; p=${P}`, 'pass pass pass'),
        keyCase('v=DKIM2', `v=DKIM2; k=rsa; p=${P}`, 'neutral neutral fail'),
        keyCase('no k=', `v=DKIM1; p=${P}`, 'pass pass pass'),
        keyCase('k=foo', `v=DKIM1; k=foo; p=${P}`, 'neutral neutral fail'),
        keyCase('k= in upper case', `v=DKIM1; k=RSA; p=${P}`, 'pass pass pass'),
        keyCase('p= empty (revoked)', 'v=DKIM1; k=rsa; p=', 'neutral neutral fail'),
        keyCase('p= missing', 'v=DKIM1; k=rsa', 'neutral neutral temperror'),
        keyCase('p= not base64', `v=DKIM1; k=rsa; p=!!!!${P.slice(4)}`, 'neutral neutral permerror'),
        keyCase('p= truncated', `v=DKIM1; k=rsa; p=${P.slice(0, 100)}`, 'neutral neutral permerror'),
        keyCase('p= with spaces', `v=DKIM1; k=rsa; p=${P.replace(/(.{40})/g, '$1 ')}`, 'pass pass pass'),
        keyCase('h=sha256', `v=DKIM1; k=rsa; h=sha256; p=${P}`, 'pass pass pass'),
        keyCase('h=sha1, the signature uses sha256', `v=DKIM1; k=rsa; h=sha1; p=${P}`, 'neutral neutral fail'),
        keyCase('h=sha1:sha256', `v=DKIM1; k=rsa; h=sha1:sha256; p=${P}`, 'pass pass pass'),
        keyCase('h=foo', `v=DKIM1; k=rsa; h=foo; p=${P}`, 'neutral neutral fail'),
        keyCase('s=email', `v=DKIM1; k=rsa; s=email; p=${P}`, 'pass pass pass'),
        keyCase('s=*', `v=DKIM1; k=rsa; s=*; p=${P}`, 'pass pass pass'),
        keyCase('s=other', `v=DKIM1; k=rsa; s=other; p=${P}`, 'neutral neutral fail'),
        keyCase('s=other:email', `v=DKIM1; k=rsa; s=other:email; p=${P}`, 'pass pass pass'),
        keyCase('t=y', `v=DKIM1; k=rsa; t=y; p=${P}`, 'pass pass pass'),
        keyCase('t=s, no i=', `v=DKIM1; k=rsa; t=s; p=${P}`, 'pass pass pass'),
        keyCase('t=s, i= in d=', `v=DKIM1; k=rsa; t=s; p=${P}`, 'pass pass pass', { extra: ' i=u@example.com;' }),
        keyCase('unknown tag', `v=DKIM1; k=rsa; zz=1; p=${P}`, 'pass pass pass'),
        keyCase('n= notes', `v=DKIM1; k=rsa; n=hello; p=${P}`, 'pass pass pass'),
        keyCase('trailing semicolon', `v=DKIM1; k=rsa; p=${P};`, 'pass pass pass'),
        keyCase('whitespace around =', `v = DKIM1 ; k = rsa ; p = ${P}`, 'pass pass pass'),
        keyCase('not a key record', 'hello world', 'neutral neutral temperror'),
        { name: 'key record: not found', message: craft(), keys: {}, expected: 'neutral neutral fail' },

        ...CHANGES.flatMap(([name, change, simpleResult, relaxedResult]) => [
            { name: `simple/simple: ${name}`, message: change(craft({ c: 'simple/simple' })), expected: simpleResult },
            { name: `relaxed/relaxed: ${name}`, message: change(craft({ c: 'relaxed/relaxed' })), expected: relaxedResult }
        ]),
        ...CANONICALIZATIONS.slice(0, 2).map(c => ({
            name: `${c}: a header h= listed as absent added`,
            message: craft({ c, h: 'from:to:subject:date:reply-to' }).replace('\r\n\r\n', '\r\nReply-To: x@example.org\r\n\r\n'),
            expected: 'fail fail fail'
        })),

        {
            name: 'two From fields, both signed',
            message: craft({ headers: ['From: Evil <evil@example.org>', ...HEADERS], h: 'from:from:to' }),
            expected: 'pass pass pass'
        },
        {
            name: 'two From fields, one signed',
            message: craft({ headers: ['From: Evil <evil@example.org>', ...HEADERS], h: 'from:to' }),
            expected: 'pass pass pass'
        },
        {
            name: 'over-signed From, another From added',
            message: craft({ h: 'from:from:to' }).replace('From: Joe', 'From: Evil <evil@example.org>\r\nFrom: Joe'),
            expected: 'fail fail fail'
        },
        {
            name: 'header name with a space before the colon',
            message: craft({ headers: [...HEADERS.slice(0, 2), 'Subject : x', ...HEADERS.slice(3)] }),
            expected: 'pass pass pass'
        },
        {
            name: 'header name with a space before the colon, simple',
            message: craft({ c: 'simple/simple', headers: [...HEADERS.slice(0, 2), 'Subject : x', ...HEADERS.slice(3)] }),
            expected: 'pass pass pass'
        },
        {
            name: '8-bit header value',
            message: craft({ headers: ['From: J\u00c3\u00b5gi <joe@example.com>', ...HEADERS.slice(1)] }),
            expected: 'pass pass pass'
        },
        {
            name: 'bare CR in a header value, simple',
            message: craft({ c: 'simple/simple', headers: [...HEADERS.slice(0, 2), 'Subject: a\rb', ...HEADERS.slice(3)] }),
            expected: 'pass pass pass'
        }
    ];
};

// The default mode of mailauth accepts these with a warning, the strict mode and OpenDKIM do
// not. OpenDKIM gives no verdict for a signature libopendkim can not parse
const buildLenientCases = (): DifferentialCase[] => [
    {
        name: 'v=2',
        message: craft({ rawTags: 'v=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; h=from:to:subject:date; bh=%BH%; b=' }),
        expected: 'pass neutral permerror'
    },
    {
        name: 'v missing',
        message: craft({ rawTags: 'a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; h=from:to:subject:date; bh=%BH%; b=' }),
        expected: 'pass neutral -'
    },
    { name: 'i= without @', message: craft({ extra: ' i=example.com;' }), expected: 'pass neutral permerror' },
    { name: 'i= in another domain', message: craft({ extra: ' i=@other.com;' }), expected: 'pass neutral permerror' },
    { name: 'i= in a domain that ends with d=', message: craft({ extra: ' i=@notexample.com;' }), expected: 'pass neutral permerror' },
    { name: 'q=dns', message: craft({ extra: ' q=dns;' }), expected: 'pass neutral permerror' },
    { name: 'q=foo', message: craft({ extra: ' q=foo;' }), expected: 'pass neutral permerror' },
    { name: 't= not a number', message: craft({ extra: ' t=abc;' }), expected: 'pass neutral -' },
    { name: 't= too large', message: craft({ extra: ' t=99999999999999999999;' }), expected: 'pass neutral -' },
    { name: 'l= larger than the body', message: craft({ l: BODY_LENGTH, extra: ` l=${BODY_LENGTH + 1};` }), expected: 'pass neutral fail' },
    keyCase('t=s, i= in a subdomain', `v=DKIM1; k=rsa; t=s; p=${P}`, 'pass neutral fail', { extra: ' i=u@sub.example.com;' }),
    keyCase('t=y:s, i= in a subdomain', `v=DKIM1; k=rsa; t=y:s; p=${P}`, 'pass neutral fail', { extra: ' i=u@sub.example.com;' })
];

const parseExpected = (expected: string) => {
    let [lax, strict, opendkim] = expected.split(' ').map(list => (list === '-' ? [] : list.split(',')));
    return { lax, strict, opendkim };
};

// Verifies with both modes of mailauth and with OpenDKIM, resolves with the default mode results
const checkCase = async (testCase: DifferentialCase) => {
    let keys = testCase.keys || SEL_KEYS;
    let msg = bin(testCase.message);
    let [lax, strict, opendkim] = await Promise.all([verifyResults(msg, keys), verifyResults(msg, keys, true), opendkimVerify(msg, { keys })]);
    expect({
        lax: lax.map(r => r.status.result),
        strict: strict.map(r => r.status.result),
        opendkim
    }).to.deep.equal(parseExpected(testCase.expected));
    return lax;
};

describe('OpenDKIM interoperability', { skip }, () => {
    let messages = buildMessages();

    describe('mailauth signs, OpenDKIM verifies', { concurrency: 8 }, () => {
        for (let [name, raw] of Object.entries(messages)) {
            for (let canonicalization of CANONICALIZATIONS) {
                for (let { algorithm, selector, privateKey } of ALGORITHMS) {
                    it(`${name}, ${canonicalization}, ${algorithm}`, { timeout: 60000 }, async () => {
                        let msg = bin(raw);
                        let signed = await dkimSign(msg, {
                            canonicalization,
                            algorithm,
                            signatureData: [{ signingDomain: 'example.com', selector, privateKey }]
                        });
                        expect(signed.errors).to.deep.equal([]);
                        expect(await opendkimVerify(prepend(signed.signatures, msg), { keys: KEYS })).to.deep.equal(['pass']);
                    });
                }
            }
        }
    });

    describe('OpenDKIM signs, mailauth verifies', { concurrency: 8 }, () => {
        for (let [name, raw] of Object.entries(messages)) {
            for (let canonicalization of CANONICALIZATIONS) {
                for (let { algorithm, selector, privateKey } of ALGORITHMS) {
                    if (algorithm === 'ed25519-sha256' && canonicalization.startsWith('simple/')) {
                        // OpenDKIM writes a different signature header than it signs, see below
                        continue;
                    }
                    it(`${name}, ${canonicalization}, ${algorithm}`, { timeout: 60000 }, async () => {
                        let msg = bin(raw);
                        let signed = prepend(await odSign(msg, { selector, privateKey, canonicalization, algorithm }), msg);
                        let [lax] = await verifyResults(signed, KEYS);
                        expect(lax.bodyHash).to.equal(lax.bodyHashExpecting);
                        expect(lax.status.result).to.equal('pass');
                        let [strict] = await verifyResults(signed, KEYS, true);
                        // RFC 8301: rsa-sha1 is not valid
                        expect(strict.status.result).to.equal(algorithm === 'rsa-sha1' ? 'policy' : 'pass');
                    });
                }
            }
        }
    });

    describe('OpenDKIM signing options', { concurrency: 8 }, () => {
        for (let [name, raw] of Object.entries(messages)) {
            for (let canonicalization of CANONICALIZATIONS) {
                it(`l= of ${name}, ${canonicalization}`, { timeout: 60000 }, async () => {
                    let msg = bin(raw);
                    let signature = await odSign(msg, { canonicalization, bodyLength: true });
                    let bodyLength = Number(signature.match(/[\s;]l=(\d+)/)?.[1]);
                    let [result] = await verifyResults(prepend(signature, msg), KEYS, true);
                    expect(result.status.result).to.equal('pass');
                    // the same canonicalized body length
                    expect(result.canonBodyLengthTotal).to.equal(bodyLength);
                    expect(result.canonBodyLength).to.equal(bodyLength);
                });
            }
        }

        it('z= copied header fields', async () => {
            let msg = bin(messages.basic);
            let signature = await odSign(msg, { diagnostics: true });
            expect(signature).to.match(/[\s;]z=/);
            let [result] = await verifyResults(prepend(signature, msg), KEYS, true);
            expect(result.status.result).to.equal('pass');
        });

        it('over-signed header fields', async () => {
            let msg = bin(messages.basic);
            let signature = await odSign(msg, { signHeaders: ['From', 'To', 'Subject', 'Reply-To'], oversignHeaders: ['From', 'Subject', 'Reply-To'] });
            expect(signature.replace(/\s+/g, '')).to.include('h=From:To:Subject:From:Subject:Reply-To;');
            let signed = prepend(signature, msg);
            let [result] = await verifyResults(signed, KEYS, true);
            expect(result.status.result).to.equal('pass');

            // a From field added above the signed one breaks the over-signed signature
            let [added] = await verifyResults(bin(signed.toString('binary').replace('From: Joe', 'From: Evil <evil@example.org>\r\nFrom: Joe')), KEYS, true);
            expect(added.status.result).to.equal('fail');
        });
    });

    describe('mailauth signing options', { concurrency: 8 }, () => {
        let cases: Array<[string, any]> = [
            ['maxBodyLength', { signatureData: [{ maxBodyLength: 7 }] }],
            ['identity', { signatureData: [{ identity: 'j\u00f5gi@sub.example.com' }] }],
            ['subdomain d=', { signatureData: [{ signingDomain: 'sub.example.com' }] }],
            ['over-signing', { headerList: 'From:From:Subject:Subject:Reply-To:To' }],
            ['expiration', { expires: new Date(Date.now() + 3600 * 1000) }],
            ['two signatures', { signatureData: [{}, { selector: 'ed', privateKey: edPem }] }]
        ];
        for (let canonicalization of CANONICALIZATIONS) {
            for (let [name, options] of cases) {
                it(`${name}, ${canonicalization}`, async () => {
                    let msg = bin(messages.basic);
                    let signatureData = (options.signatureData || [{}]).map((entry: any) =>
                        Object.assign({ signingDomain: 'example.com', selector: 'rsa', privateKey: rsaPem }, entry)
                    );
                    let signed = await dkimSign(msg, Object.assign({}, options, { canonicalization, signatureData }));
                    expect(signed.errors).to.deep.equal([]);
                    expect(await opendkimVerify(prepend(signed.signatures, msg), { keys: KEYS })).to.deep.equal(signatureData.map(() => 'pass'));
                });
            }
        }
    });

    describe('both verify the same message', { concurrency: 8 }, () => {
        for (let testCase of buildAgreeingCases()) {
            it(`${testCase.name}: ${testCase.expected}`, async () => {
                await checkCase(testCase);
            });
        }
    });

    describe('where OpenDKIM differs', { concurrency: 8 }, () => {
        // OpenDKIM bugs, mailauth follows RFC 6376

        it('OpenDKIM signs ed25519 with simple header canonicalization over a differently folded signature', async () => {
            // dkim_getsighdr_d() in libopendkim/dkim.c only reserves room for the b= value of an
            // RSA key when it folds the signature header. With ed25519 "b=" fits at the end of a
            // line while signing, but the header it writes has the value moved to the next line.
            // Simple header canonicalization keeps that line break, so the signature can never
            // verify, by OpenDKIM either
            let msg = bin(message(HEADERS.slice(0, 3), 'x\r\n'));
            let signature = await odSign(msg, { selector: 'ed', privateKey: edPem, canonicalization: 'simple/simple', algorithm: 'ed25519-sha256' });
            expect(signature).to.match(/;\r\n\tb=/);
            let signed = prepend(signature, msg);
            expect((await verifyResults(signed, KEYS, true)).map(r => r.status.result)).to.deep.equal(['fail']);
            expect(await opendkimVerify(signed, { keys: KEYS })).to.deep.equal(['fail']);

            // the header OpenDKIM signed has b= on the h= line
            let refolded = prepend(signature.replace(/;\r\n\tb=/, '; b='), msg);
            expect((await verifyResults(refolded, KEYS, true)).map(r => r.status.result)).to.deep.equal(['pass']);
        });

        // [body, the relaxed canonicalized body OpenDKIM hashes]
        for (let [body, opendkimCanonical] of [
            ['a\rb\r\n', 'ab\r\n'],
            ['x\r y\r\n', 'x y\r\n'],
            ['c \r\r\n', 'c\r\r\n']
        ]) {
            it(`OpenDKIM drops a bare CR or the whitespace before it from the relaxed body: ${JSON.stringify(body)}`, async () => {
                // RFC 6376 section 3.4.4 reduces WSP (SP and HTAB) only, and a line ends with
                // CRLF, so a CR without LF is an ordinary character. dkim_canon_bodychunk() in
                // libopendkim/dkim-canon.c holds a CR back as a possible line end and drops it
                // when the next character is anything but LF or CR, and it drops the whitespace
                // before a CR as trailing whitespace
                let msg = bin(message(HEADERS, body));
                let hash = (canonical: string) => crypto.createHash('sha256').update(bin(canonical)).digest('base64');
                let expectedHash = hash(canonBodyRelaxed(body));

                let signed = await dkimSign(msg, {
                    canonicalization: 'relaxed/relaxed',
                    signatureData: [{ signingDomain: 'example.com', selector: 'rsa', privateKey: rsaPem }]
                });
                expect(signed.signatures).to.include(`bh=${expectedHash}`);
                expect(await opendkimVerify(prepend(signed.signatures, msg), { keys: KEYS })).to.deep.equal(['fail']);

                let signature = await odSign(msg, { canonicalization: 'relaxed/relaxed' });
                expect(signature.replace(/\s+/g, '')).to.include(`bh=${hash(opendkimCanonical)};`);
                let [result] = await verifyResults(prepend(signature, msg), KEYS, true);
                expect(result.status.result).to.equal('fail');
                expect(result.bodyHash).to.equal(expectedHash);
            });
        }

        it('both keep a bare CR in the simple body', async () => {
            let msg = bin(message(HEADERS, 'a\rb\r\nc \r \r\n'));
            let [result] = await verifyResults(prepend(await odSign(msg, { canonicalization: 'relaxed/simple' }), msg), KEYS, true);
            expect(result.status.result).to.equal('pass');
        });

        for (let [name, char] of [
            ['CR', '\r'],
            ['VT', '\v'],
            ['FF', '\f']
        ]) {
            it(`OpenDKIM collapses a ${name} in a header value as whitespace (relaxed)`, async () => {
                // RFC 6376 section 3.4.2 reduces WSP (SP and HTAB) only. The relaxed header
                // canonicalization in libopendkim/dkim-canon.c uses isspace(), which also matches
                // CR, VT and FF, and turns them into a space
                await checkCase({
                    name,
                    message: craft({ headers: [...HEADERS.slice(0, 2), `Subject: a${char}b`, ...HEADERS.slice(3)] }),
                    expected: 'pass pass fail'
                });
            });
        }

        it('OpenDKIM does not remove the b= value when there is whitespace before the =', async () => {
            // RFC 6376 section 3.2: tag-spec = [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS].
            // libopendkim/dkim-canon.c recognizes the b= tag by the character right before "=",
            // so "b =" is hashed with its value
            await Promise.all([
                checkCase({
                    name: 'b =',
                    message: craft({ rawTags: 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; h=from:to; bh=%BH%; b = ' }),
                    expected: 'pass pass fail'
                }),
                checkCase({
                    name: 'b =, simple',
                    message: craft({ c: 'simple/simple', rawTags: 'v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=sel; h=from:to; bh=%BH%; b =' }),
                    expected: 'pass pass fail'
                })
            ]);
        });

        it('OpenDKIM does not verify a message without a From field it recognizes', async () => {
            // The filter (not libopendkim) looks for a field named exactly "From" to find the
            // sender, and without one it reports "permerror (bad message/signature format)"
            // without verifying anything. "From :" is the obsolete syntax of RFC 5322 section
            // 4.5.6, which receivers must accept
            await Promise.all([
                checkCase({
                    name: 'From :',
                    message: craft({ headers: ['From : Joe <joe@example.com>', ...HEADERS.slice(1)] }),
                    expected: 'pass pass permerror'
                }),
                checkCase({ name: 'no From', message: craft({ headers: HEADERS.slice(1), h: 'from:to' }), expected: 'pass pass permerror' })
            ]);
        });

        it('OpenDKIM does not accept a p= that is an RSAPublicKey', async () => {
            // RFC 6376 section 3.6.1 defines p= of an RSA key as an RSAPublicKey. The key that
            // section 3.6.1 and Appendix C produce is a SubjectPublicKeyInfo, and OpenDKIM only
            // accepts that form, mailauth accepts both
            await checkCase(keyCase('RSAPublicKey', `v=DKIM1; k=rsa; p=${pkcs1B64(rsaPub)}`, 'pass pass permerror'));
        });

        // OpenDKIM accepts what RFC 6376 and RFC 8301 do not, only the strict mode of mailauth
        // refuses it (the default mode accepts it too, with a warning)

        it('OpenDKIM accepts rsa-sha1', async () => {
            // RFC 8301 section 3.1: rsa-sha1 MUST NOT be used for verifying
            await checkCase({ name: 'rsa-sha1', message: craft({ algo: 'rsa-sha1' }), expected: 'pass policy pass' });
        });

        it('OpenDKIM accepts a tag list with a repeated tag', async () => {
            // RFC 6376 section 3.2: "if a tag name does occur more than once, the entire tag-list is invalid"
            await Promise.all([
                checkCase({ name: 'd= twice', message: craft({ extra: ' d=example.com;' }), expected: 'pass neutral pass' }),
                checkCase({ name: 'unknown tag twice', message: craft({ extra: ' zz=1; zz=2;' }), expected: 'pass neutral pass' }),
                checkCase(keyCase('p= twice', `v=DKIM1; k=rsa; p=${P}; p=${P}`, 'pass neutral pass'))
            ]);
        });

        it('OpenDKIM accepts a key record with v= after another tag', async () => {
            // RFC 6376 section 3.6.1: v= "MUST be the first tag in the record"
            await checkCase(keyCase('v= not first', `k=rsa; v=DKIM1; p=${P}`, 'pass neutral pass'));
        });

        it('OpenDKIM accepts a d= of one label', async () => {
            // RFC 6376 section 3.5: d= is a domain-name, sub-domain 1*("." sub-domain)
            await checkCase({ name: 'd=com', message: craft({ d: 'com' }), keys: { 'sel._domainkey.com': rsaRec }, expected: 'pass neutral pass' });
        });

        // Both are allowed

        it('OpenDKIM refuses a signature made in the future', async () => {
            // RFC 6376 section 3.5 t=: "Verifiers MAY ignore signatures with a timestamp in the future"
            await checkCase({ name: 't= +1h', message: craft({ extra: ` t=${NOW + 3600};` }), expected: 'pass pass permerror' });
        });

        for (let testCase of buildLenientCases()) {
            it(`mailauth accepts by default, with a warning: ${testCase.name}`, async () => {
                let [result] = await checkCase(testCase);
                expect(result.status.warnings).to.be.an('array').that.is.not.empty;
            });
        }
    });
});
