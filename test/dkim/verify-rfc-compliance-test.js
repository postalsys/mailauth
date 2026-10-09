/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const fs = require('node:fs');
const chai = require('chai');
const expect = chai.expect;

const { dkimVerify } = require('../../lib/dkim/verify');
const { sign, resolverFrom, spkiB64, pkcs1B64, edRawB64 } = require('../helpers/dkim-reference');

chai.config.includeStack = true;

// Signatures are made with the independent reference signer in test/helpers/dkim-reference.js,
// from a literal tag list, so that every case can use exactly the tags it is about, including
// invalid ones. Each case lists what the lenient default and the strict mode report.

const fixture = file => fs.readFileSync(`${__dirname}/../fixtures/${file}`);

const rsa2048 = { privateKey: crypto.createPrivateKey(fixture('private-rsa.pem')) };
rsa2048.publicKey = crypto.createPublicKey(rsa2048.privateKey);
const rsa512 = { privateKey: crypto.createPrivateKey(fixture('private-small.pem')) };
rsa512.publicKey = crypto.createPublicKey(rsa512.privateKey);
const ed = { privateKey: crypto.createPrivateKey(fixture('private-ed25519.pem')) };
ed.publicKey = crypto.createPublicKey(ed.privateKey);

const D = 'example.com';
const SEL = 'sel';
const KEYNAME = `${SEL}._domainkey.${D}`;
const HDRS = ['From: Joe <joe@example.com>', 'To: suzie@example.net', 'Subject: Is dinner ready?', 'Date: Fri, 11 Jul 2003 21:00:37 -0700'];
const BODY = 'Hi.\r\n\r\nWe lost the game.  Are you hungry yet?\r\n\r\nJoe.\r\n';
const rsaRec = `v=DKIM1; k=rsa; p=${spkiB64(rsa2048.publicKey)}`;
const edRec = `v=DKIM1; k=ed25519; p=${edRawB64(ed.publicKey)}`;

// a signed message with the standard headers, `extraTags` go before h=
const std = (extraTags, o) => {
    o = o || {};
    let a = o.algo || 'rsa-sha256';
    let c = o.c || 'relaxed/relaxed';
    let h = o.h || 'from:to:subject:date';
    let tags = o.rawTags || `v=1; a=${a}; c=${c}; d=${o.d || D}; s=${o.s || SEL};${extraTags || ''} h=${h}; bh=%BH%; b=`;
    return sign({
        headers: o.headers || HDRS,
        body: o.body === undefined ? BODY : o.body,
        c,
        algo: a,
        key: o.key || rsa2048.privateKey,
        sigPrefix: 'DKIM-Signature: ' + tags,
        sigSuffix: o.suffix || '',
        hList: (o.hsel || h).split(':'),
        l: o.l,
        bodyHashAlgo: o.bodyHashAlgo,
        headerHashAlgo: o.headerHashAlgo,
        rsaHash: o.rsaHash
    }).msg;
};

const verify = async (msg, records, extra) => {
    let log = [];
    let res = await dkimVerify(Buffer.from(msg, 'binary'), Object.assign({ resolver: resolverFrom(records, log) }, extra || {}));
    return { log, res, result: res.results[0] };
};

// checks one mode of a case: { result, comment, warnings, info, policy, noDns }
const check = (outcome, expected) => {
    let { result, log } = outcome;
    expect(result.status.result).to.equal(expected.result);
    if ('comment' in expected) {
        expect(result.status.comment).to.equal(expected.comment);
    }
    if ('warnings' in expected) {
        if (expected.warnings) {
            expect(result.status.warnings).to.deep.equal(expected.warnings);
        } else {
            expect(result.status.warnings).to.be.undefined;
        }
    }
    if ('policy' in expected) {
        expect(result.status.policy).to.deep.equal(expected.policy);
    }
    if ('info' in expected) {
        expect(result.info).to.equal(expected.info);
    }
    if (expected.noDns) {
        expect(log).to.deep.equal([]);
    }
    // what the lenient mode accepted is never written into the Authentication-Results text
    expect(result.info).to.not.match(/warning/);
};

const cases = [
    {
        title: 'a valid rsa-sha256 signature',
        msg: () => std(),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: false },
        strict: { result: 'pass', warnings: false }
    },
    {
        title: 'a valid ed25519-sha256 signature',
        msg: () => std('', { algo: 'ed25519-sha256', key: ed.privateKey }),
        records: { [KEYNAME]: [edRec] },
        lax: { result: 'pass', warnings: false },
        strict: { result: 'pass', warnings: false }
    },
    {
        // RFC 8301 section 3.1: rsa-sha1 MUST NOT be used for verifying
        title: 'an rsa-sha1 signature',
        msg: () => std('', { algo: 'rsa-sha1' }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['rsa-sha1'] },
        strict: {
            result: 'policy',
            comment: 'weak algorithm',
            policy: { 'dkim-rules': 'weak-algorithm' },
            noDns: true,
            info: /^dkim=policy \(weak algorithm\) policy\.dkim-rules=weak-algorithm /
        }
    },
    {
        // RFC 6376 section 6.1.2 step 6: the key owner can refuse rsa-sha1, in both modes
        title: 'an rsa-sha1 signature with a key that only allows sha256',
        msg: () => std('', { algo: 'rsa-sha1' }),
        records: { [KEYNAME]: [`v=DKIM1; h=sha256; k=rsa; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'neutral', comment: 'inappropriate hash algorithm' },
        strict: { result: 'policy', comment: 'weak algorithm' }
    },
    {
        title: 'a signature with a hash the key h= tag does not list',
        msg: () => std(),
        records: { [KEYNAME]: [`v=DKIM1; h=sha1; k=rsa; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'neutral', comment: 'inappropriate hash algorithm' },
        strict: { result: 'neutral', comment: 'inappropriate hash algorithm' }
    },
    {
        title: 'a signature with a key h= tag that lists the hash',
        msg: () => std(),
        records: { [KEYNAME]: [`v=DKIM1; h=sha1:sha256; k=rsa; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass' },
        strict: { result: 'pass' }
    },
    {
        // RFC 6376 section 3.6.1 s=
        title: 'a key that is not meant for email',
        msg: () => std(),
        records: { [KEYNAME]: [`v=DKIM1; s=foo; k=rsa; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'neutral', comment: 'key not for email' },
        strict: { result: 'neutral', comment: 'key not for email' }
    },
    {
        title: 'a key with s=email',
        msg: () => std(),
        records: { [KEYNAME]: [`v=DKIM1; s=email; k=rsa; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass' },
        strict: { result: 'pass' }
    },
    {
        // RFC 6376 section 6.1.1: h= must include From
        title: 'a signature that does not sign From',
        msg: () => std('', { h: 'to:subject:date' }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'neutral', comment: 'From field not signed', noDns: true },
        strict: { result: 'neutral', comment: 'From field not signed', noDns: true }
    },
    {
        title: 'a signature that does not sign From, with From replaced after signing',
        msg: () => std('', { h: 'to:subject:date' }).replace('From: Joe <joe@example.com>', 'From: CEO <ceo@example.com>'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'neutral', comment: 'From field not signed' },
        strict: { result: 'neutral', comment: 'From field not signed' }
    },
    {
        title: 'a signature with an empty h= tag',
        msg: () => std('', { rawTags: `v=1; a=rsa-sha256; c=relaxed/relaxed; d=${D}; s=${SEL}; h=; bh=%BH%; b=`, hsel: '' }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'neutral', comment: 'From field not signed' },
        strict: { result: 'neutral', comment: 'signature syntax error' }
    },
    {
        // RFC 6376 section 6.1.1: the i= domain must be d= or a subdomain of it
        title: 'an i= domain that is not under d=',
        msg: () => std(' i=user@evil.test;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['identity-domain'] },
        strict: { result: 'neutral', comment: 'domain mismatch', noDns: true }
    },
    {
        title: 'an i= domain that is a subdomain of d=',
        msg: () => std(' i=joe@sub.example.com;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: false, info: /header\.i=@example\.com / },
        // RFC 8601 section 2.7.1, header.i is the AUID and header.d the SDID
        strict: { result: 'pass', warnings: false, info: /header\.d=example\.com header\.i=joe@sub\.example\.com / }
    },
    {
        // RFC 6376 section 3.6.1 key t=s
        title: 'a subdomain i= with a key that has t=s',
        msg: () => std(' i=user@sub.example.com;'),
        records: { [KEYNAME]: [`v=DKIM1; t=s; k=rsa; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass', warnings: ['identity-domain'] },
        strict: { result: 'neutral', comment: 'domain mismatch' }
    },
    {
        title: 'the d= domain in i= with a key that has t=s',
        msg: () => std(' i=user@example.com;'),
        records: { [KEYNAME]: [`v=DKIM1; t=s; k=rsa; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass', warnings: false },
        strict: { result: 'pass', warnings: false }
    },
    {
        title: 'a signature without v=',
        msg: () => std('', { rawTags: `a=rsa-sha256; c=relaxed/relaxed; d=${D}; s=${SEL}; h=from:to:subject:date; bh=%BH%; b=` }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['missing-v'] },
        strict: { result: 'neutral', comment: 'signature missing required tag', noDns: true }
    },
    {
        title: 'a signature with v=2',
        msg: () => std('', { rawTags: `v=2; a=rsa-sha256; c=relaxed/relaxed; d=${D}; s=${SEL}; h=from:to:subject:date; bh=%BH%; b=` }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['invalid-v'] },
        strict: { result: 'neutral', comment: 'incompatible version' }
    },
    {
        // without h= the lenient mode uses its default header list, which includes From
        title: 'a signature without h=',
        msg: () =>
            std('', {
                rawTags: `v=1; a=rsa-sha256; c=relaxed/relaxed; d=${D}; s=${SEL}; bh=%BH%; b=`,
                hsel: require('../../lib/tools').defaultDKIMFieldNames
            }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['missing-h'] },
        strict: { result: 'neutral', comment: 'signature missing required tag' }
    },
    {
        // RFC 6376 section 3.2: a duplicate tag makes the whole tag-list invalid
        title: 'a signature with a duplicate tag',
        msg: () => std('', { rawTags: `v=1; a=rsa-sha256; c=relaxed/relaxed; d=evil.test; d=${D}; s=${SEL}; h=from:to:subject:date; bh=%BH%; b=` }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['tag-syntax'] },
        strict: { result: 'neutral', comment: 'signature syntax error' }
    },
    {
        // RFC 6376 section 3.2: tag names are case-sensitive, "D=" is not d=
        title: 'a signature with upper case tag names',
        msg: () => std('', { rawTags: `v=1; a=rsa-sha256; c=relaxed/relaxed; D=${D}; S=${SEL}; h=from:to:subject:date; bh=%BH%; b=` }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['tag-syntax'] },
        strict: { result: 'neutral', comment: 'signature missing required tag' }
    },
    {
        title: 'a key with a duplicate tag',
        msg: () => std(),
        records: { [KEYNAME]: [`v=DKIM1; k=rsa; p=; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass', warnings: ['key-syntax'] },
        strict: { result: 'neutral', comment: 'invalid public key' }
    },
    {
        // RFC 6376 section 3.6.1: v= "MUST be the first tag in the record"
        title: 'a key with v= that is not the first tag',
        msg: () => std(),
        records: { [KEYNAME]: [`k=rsa; v=DKIM1; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass', warnings: ['key-v-syntax'] },
        strict: { result: 'neutral', comment: 'unknown key version' }
    },
    {
        // key-v-tag is %x44.4B.49.4D.31, a case-sensitive string
        title: 'a key with v=dkim1 in lower case',
        msg: () => std(),
        records: { [KEYNAME]: [`v=dkim1; k=rsa; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass', warnings: ['key-v-syntax'] },
        strict: { result: 'neutral', comment: 'unknown key version' }
    },
    {
        // k= defaults to rsa, the lenient mode finds an ed25519 key from its length
        title: 'an ed25519 key without k=',
        msg: () => std('', { algo: 'ed25519-sha256', key: ed.privateKey }),
        records: { [KEYNAME]: [`v=DKIM1; p=${edRawB64(ed.publicKey)}`] },
        lax: { result: 'pass', warnings: ['key-type-inferred'] },
        strict: { result: 'neutral', comment: 'unknown key type' }
    },
    {
        title: 'an rsa signature with an ed25519 key',
        msg: () => std(),
        records: { [KEYNAME]: [edRec] },
        lax: { result: 'neutral' },
        strict: { result: 'neutral', comment: 'inappropriate key algorithm' }
    },
    {
        // RFC 8463 defines ed25519-sha256 only
        title: 'an ed25519-sha1 signature',
        msg: () => std('', { algo: 'ed25519-sha1', key: ed.privateKey, bodyHashAlgo: 'sha1', headerHashAlgo: 'sha256' }),
        records: { [KEYNAME]: [edRec] },
        lax: { result: 'none', comment: 'message not signed' },
        strict: { result: 'neutral', comment: 'unknown algorithm', noDns: true }
    },
    {
        title: 'a 512 bit RSA key',
        msg: () => std('', { key: rsa512.privateKey }),
        records: { [KEYNAME]: [`v=DKIM1; k=rsa; p=${spkiB64(rsa512.publicKey)}`] },
        lax: { result: 'policy', policy: { 'dkim-rules': 'weak-key' } },
        strict: { result: 'policy', policy: { 'dkim-rules': 'weak-key' } }
    },
    {
        // RFC 6376 section 3.6.1: k=rsa is a bare RSAPublicKey
        title: 'a key published as a bare RSAPublicKey',
        msg: () => std(),
        records: { [KEYNAME]: [`v=DKIM1; k=rsa; p=${pkcs1B64(rsa2048.publicKey)}`] },
        lax: { result: 'pass' },
        strict: { result: 'pass' }
    },
    {
        // RFC 6376 section 3.2: quotes, parentheses and backslashes are value characters
        title: 'a key with an apostrophe in n=',
        msg: () => std(),
        records: { [KEYNAME]: [`v=DKIM1; k=rsa; n=it's; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass', warnings: false },
        strict: { result: 'pass' }
    },
    {
        title: 'a key with a parenthesis in n=',
        msg: () => std(),
        records: { [KEYNAME]: [`v=DKIM1; k=rsa; n=see(below; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass' },
        strict: { result: 'pass' }
    },
    {
        title: 'a key with a backslash in n=',
        msg: () => std(),
        records: { [KEYNAME]: [`v=DKIM1; k=rsa; n=a\\b; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass' },
        strict: { result: 'pass' }
    },
    {
        title: 'a signature with an apostrophe in z=',
        msg: () => std(" z=From:O'Brien=20<ob@example.com>;"),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: false },
        strict: { result: 'pass' }
    },
    {
        title: 'a signature with a parenthesis in z=',
        msg: () => std(' z=Subject:(hi;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass' },
        strict: { result: 'pass' }
    },
    {
        title: 'a signature with a backslash in z=',
        msg: () => std(' z=Subject:a\\b;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass' },
        strict: { result: 'pass' }
    },
    {
        // RFC 6376 section 3.7: only the value of the b= tag itself is emptied
        title: 'a signature with ":b=" inside z=',
        msg: () => std(' z=Subject:b=3Dx;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass' },
        strict: { result: 'pass' }
    },
    {
        title: 'a signature with an unknown tag that holds " b="',
        msg: () => std(' xnote=see b=here;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: false },
        strict: { result: 'pass' }
    },
    {
        // tag-spec = [FWS] tag-name [FWS] "=" ...
        title: 'a signature with whitespace between b and "="',
        msg: () => std('', { rawTags: `v=1; a=rsa-sha256; c=relaxed/relaxed; d=${D}; s=${SEL}; h=from:to:subject:date; bh=%BH%; b =` }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass' },
        strict: { result: 'pass' }
    },
    {
        title: 'a signature where b= is not the last tag',
        msg: () => std('', { rawTags: `v=1; a=rsa-sha256; c=relaxed/relaxed; d=${D}; s=${SEL}; h=from:to:subject:date; bh=%BH%; b=`, suffix: '; xfoo=bar' }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass' },
        strict: { result: 'pass' }
    },
    {
        // RFC 6376 section 3.5: "The value of the x= tag MUST be greater than the value of the t= tag"
        title: 'an x= that is equal to t=',
        msg: () => std(' t=1700000000; x=1700000000;'),
        records: { [KEYNAME]: [rsaRec] },
        extra: { curTime: new Date(1600000000000) },
        lax: { result: 'pass', warnings: ['invalid-expiration'] },
        strict: { result: 'neutral', comment: 'invalid expiration' }
    },
    {
        title: 'an x= that is before t=',
        msg: () => std(' t=1700000000; x=1690000000;'),
        records: { [KEYNAME]: [rsaRec] },
        extra: { curTime: new Date(1600000000000) },
        lax: { result: 'neutral', comment: 'invalid expiration' },
        strict: { result: 'neutral', comment: 'invalid expiration' }
    },
    {
        title: 'an expired signature',
        msg: () => std(' t=1000000000; x=1000000100;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'neutral', comment: 'expired' },
        strict: { result: 'neutral', comment: 'expired' }
    },
    {
        // sig-t-tag is 1*12DIGIT
        title: 'a hexadecimal t=',
        msg: () => std(' t=0x10;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['tag-syntax'] },
        strict: { result: 'neutral', comment: 'signature syntax error' }
    },
    {
        title: 'a non-numeric x=',
        msg: () => std(' x=abc;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['tag-syntax'] },
        strict: { result: 'neutral', comment: 'signature syntax error' }
    },
    {
        // a negative l= is not a limit, the whole body is hashed, so nothing is left unsigned
        title: 'a negative l=',
        msg: () => std(' l=-1;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['tag-syntax'] },
        strict: { result: 'neutral', comment: 'signature syntax error' }
    },
    {
        title: 'a hexadecimal l=',
        msg: () => std(' l=0x10;', { l: 16 }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['tag-syntax'] },
        strict: { result: 'neutral', comment: 'signature syntax error' }
    },
    {
        // RFC 6376 section 6.1.3 step 3, PERMFAIL (body hash did not verify)
        title: 'a body hash mismatch',
        msg: () => std().replace('Joe.', 'Bob.'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'neutral', comment: 'body hash did not verify' },
        strict: { result: 'fail', comment: 'body hash did not verify' }
    },
    {
        title: 'a header hash mismatch',
        msg: () => std().replace('Is dinner ready?', 'Is lunch ready?'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'fail', comment: 'bad signature' },
        strict: { result: 'fail', comment: 'bad signature' }
    },
    {
        // RFC 8601 section 2.7.1: "none" means that the message was not signed
        title: 'a signature without d=',
        msg: () => std('', { rawTags: `v=1; a=rsa-sha256; c=relaxed/relaxed; s=${SEL}; h=from:to:subject:date; bh=%BH%; b=` }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'none', comment: 'message not signed' },
        strict: { result: 'neutral', comment: 'signature missing required tag' }
    },
    {
        title: 'a signature with an unknown algorithm',
        msg: () => std('', { algo: 'rsa-sha512', rsaHash: 'sha512' }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'none', comment: 'message not signed' },
        strict: { result: 'neutral', comment: 'unknown algorithm' }
    },
    {
        title: 'a signature with an unknown canonicalization',
        msg: () => std('', { c: 'foo/relaxed' }),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'none', comment: 'message not signed' },
        strict: { result: 'neutral', comment: 'unknown canonicalization' }
    },
    {
        title: 'a signature with an unknown query method',
        msg: () => std(' q=foo/bar;'),
        records: { [KEYNAME]: [rsaRec] },
        lax: { result: 'pass', warnings: ['query-method'] },
        strict: { result: 'neutral', comment: 'unsupported query method' }
    },
    {
        title: 'a d= that is not a domain name',
        msg: () => std('', { d: 'exa_mple..com' }),
        records: { [`${SEL}._domainkey.exa_mple..com`]: [rsaRec] },
        lax: { result: 'pass', warnings: ['tag-syntax'] },
        strict: { result: 'neutral', comment: 'signature syntax error' }
    },
    {
        // RFC 6376 section 3.6.1 key t=y, surfaced as a flag in both modes
        title: 'a key in testing mode',
        msg: () => std(),
        records: { [KEYNAME]: [`v=DKIM1; t=y; k=rsa; p=${spkiB64(rsa2048.publicKey)}`] },
        lax: { result: 'pass', warnings: false },
        strict: { result: 'pass', warnings: false },
        testing: true
    }
];

describe('DKIM verification RFC compliance', () => {
    for (let testCase of cases) {
        describe(testCase.title, () => {
            for (let mode of ['lax', 'strict']) {
                it(`${mode === 'lax' ? 'default' : 'strict'} mode`, async () => {
                    let msg = testCase.msg();
                    let outcome = await verify(msg, testCase.records, Object.assign({}, testCase.extra || {}, mode === 'strict' ? { strict: true } : {}));
                    let expected = Object.assign({}, testCase[mode]);
                    let info = expected.info;
                    if (info instanceof RegExp) {
                        delete expected.info;
                        expect(outcome.result.info).to.match(info);
                    }
                    check(outcome, expected);

                    if (testCase.testing) {
                        expect(outcome.result.status.testing).to.be.true;
                    } else {
                        expect(outcome.result.status.testing).to.be.undefined;
                    }
                });
            }
        });
    }

    describe('A d= that is not a host name', () => {
        // RFC 6376 section 3.5: "The SDID MUST correspond to a valid DNS name under which the
        // DKIM key record is published", a signature that does not is invalid in every mode.
        // The key would otherwise be looked up in the zone after the delimiter, while the
        // Public Suffix List lookup read the value as a URL and aligned it with the part before
        for (let sep of ['/', '?', '#', '\\', '@', ':', ' ']) {
            let d = `${D}${sep}x.attacker.test`;
            for (let strict of [false, true]) {
                it(`Should reject d=${d} without a key query (${strict ? 'strict' : 'default'} mode)`, async () => {
                    let outcome = await verify(std('', { d }), { [`${SEL}._domainkey.${d}`]: [rsaRec] }, { strict });
                    check(outcome, { result: 'neutral', comment: 'signature syntax error', noDns: true });
                    expect(outcome.result.status.aligned).to.be.false;
                });
            }
        }
    });

    describe('EAI (RFC 8616)', () => {
        const u = x => Buffer.from(x, 'utf8').toString('binary');
        const eaiMessage = () =>
            sign({
                headers: ['From: Joe <joe@bücher.example>', ...HDRS.slice(1)].map(u),
                body: BODY,
                c: 'relaxed/relaxed',
                algo: 'rsa-sha256',
                key: rsa2048.privateKey,
                sigPrefix: 'DKIM-Signature: ' + u(`v=1; a=rsa-sha256; c=relaxed/relaxed; d=bücher.example; s=${SEL}; h=from:to:subject:date; bh=%BH%; b=`),
                hList: ['from', 'to', 'subject', 'date']
            }).msg;

        it('Should look up the key of a U-label d= under its A-label', async () => {
            let { result, log } = await verify(eaiMessage(), { [`${SEL}._domainkey.xn--bcher-kva.example`]: [rsaRec] });
            expect(log).to.deep.equal([`TXT ${SEL}._domainkey.xn--bcher-kva.example`]);
            expect(result.status.result).to.equal('pass');
            // the U-label is kept in the result, it is what the signature says
            expect(result.signingDomain).to.equal('bücher.example');
            expect(result.info).to.include('header.i="@bücher.example"');
        });

        it('Should report A-labels in strict mode (RFC 8601 section 2.2 domain-name)', async () => {
            let { result } = await verify(eaiMessage(), { [`${SEL}._domainkey.xn--bcher-kva.example`]: [rsaRec] }, { strict: true });
            expect(result.status.result).to.equal('pass');
            expect(result.info).to.include('header.d=xn--bcher-kva.example header.i=@xn--bcher-kva.example ');
        });
    });

    describe('rejectRsaSha1', () => {
        it('Should reject an rsa-sha1 signature as in strict mode, without a key query', async () => {
            let outcome = await verify(std('', { algo: 'rsa-sha1' }), { [KEYNAME]: [rsaRec] }, { rejectRsaSha1: true });
            check(outcome, { result: 'policy', comment: 'weak algorithm', policy: { 'dkim-rules': 'weak-algorithm' }, warnings: ['rsa-sha1'], noDns: true });
        });

        it('Should keep the other lenient defaults for the same signature', async () => {
            // a body hash mismatch is neutral by default and fail in strict mode
            let outcome = await verify(std('', { algo: 'rsa-sha1' }).replace('Joe.', 'Bob.'), { [KEYNAME]: [rsaRec] }, { rejectRsaSha1: true });
            check(outcome, { result: 'neutral', comment: 'body hash did not verify' });
        });
    });

    describe('Body length (l=)', () => {
        it('Should report the content after l=0 as unsigned', async () => {
            let msg = std(' l=0;', { l: 0 }) + 'APPENDED\r\n';
            for (let strict of [false, true]) {
                let { result } = await verify(msg, { [KEYNAME]: [rsaRec] }, { strict });
                expect(result.status.result).to.equal('pass');
                expect(result.canonBodyLength).to.equal(0);
                expect(result.status.underSized).to.be.above(0);
                expect(result.status.underSized).to.equal(result.canonBodyLengthTotal);
                expect(result.info).to.match(/\(undersized signature: \d+ bytes unsigned\)/);
            }
        });

        it('Should count the content after l= when the body arrives in pieces', async () => {
            for (let c of ['relaxed/relaxed', 'simple/simple']) {
                let signed = std(' l=5;', { l: 5, c, body: 'Hi.\r\n' });
                // the bare LFs make the message parser hand the body over line by line
                let appended = signed + 'LINE ONE\nLINE TWO\n';
                let { result } = await verify(appended, { [KEYNAME]: [rsaRec] });
                expect(result.status.result, c).to.equal('pass');
                expect(result.canonBodyLength, c).to.equal(5);
                expect(result.canonBodyLengthTotal, c).to.equal(25);
                expect(result.status.underSized, c).to.equal(20);
            }
        });
    });

    describe('Header section', () => {
        it('Should read a message that starts with an empty line as having no header fields', async () => {
            // RFC 5322 section 2.1: the From that follows the empty line is body, not a header
            let msg = '\r\n' + std();
            let { res } = await dkimVerify(Buffer.from(msg, 'binary'), { resolver: resolverFrom({ [KEYNAME]: [rsaRec] }) }).then(res => ({ res }));
            expect(res.headerFrom).to.deep.equal([]);
            expect(res.results[0].status.result).to.equal('none');
        });

        it('Should verify a simple body with an LF right after a CRLF', async () => {
            // the bare LF is a line break of its own and becomes a CRLF, on both sides
            let body = 'x\r\n\ny\r\n';
            let signed = sign({
                headers: HDRS,
                body: 'x\r\n\r\ny\r\n',
                c: 'simple/simple',
                algo: 'rsa-sha256',
                key: rsa2048.privateKey,
                sigPrefix: `DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=${D}; s=${SEL}; h=from:to:subject:date; bh=%BH%; b=`,
                hList: ['from', 'to', 'subject', 'date']
            }).msg;
            let msg = signed.replace('x\r\n\r\ny\r\n', body);
            let { result } = await verify(msg, { [KEYNAME]: [rsaRec] });
            expect(result.status.result).to.equal('pass');
        });
    });

    describe('From extraction', () => {
        const fromOf = async from => (await dkimVerify(Buffer.from(`From: ${from}\r\nSubject: x\r\n\r\nhi\r\n`), { resolver: resolverFrom({}) })).headerFrom;

        it('Should include the mailboxes of a group (RFC 6854)', async () => {
            expect(await fromOf('Bank: CEO <ceo@bank.example>;')).to.deep.equal(['ceo@bank.example']);
            expect(await fromOf('Bank: CEO <ceo@bank.example>, b@x.example;, c@y.example')).to.deep.equal(['ceo@bank.example', 'b@x.example', 'c@y.example']);
            expect(await fromOf('Undisclosed:;')).to.deep.equal([]);
        });

        it('Should keep the full addr-spec', async () => {
            // the domain is after the last "@", the DMARC module reads it from there
            expect(await fromOf('"a@good.example"@evil.example')).to.deep.equal(['"a@good.example"@evil.example']);
            // an addr-spec used as a display name is an address a reader may take for the author
            expect(await fromOf('a@good.example <b@evil.example>')).to.deep.equal(['a@good.example', 'b@evil.example']);
        });
    });

    describe('ARC-Message-Signature', () => {
        // RFC 8617 section 4.1.2: the AMS has the syntax and semantics of a DKIM-Signature
        const amsMessage = h =>
            sign({
                headers: [
                    'ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; t=1; b=AAAA',
                    'ARC-Authentication-Results: i=1; mx.example.com; none'
                ].concat(HDRS),
                body: BODY,
                c: 'relaxed/relaxed',
                algo: 'rsa-sha256',
                key: rsa2048.privateKey,
                sigPrefix: `ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=${D}; s=${SEL}; h=${h}; bh=%BH%; b=`,
                hList: h.split(':')
            }).msg;

        it('Should verify an ARC-Message-Signature that signs From', async () => {
            let res = await dkimVerify(Buffer.from(amsMessage('from:to:subject:date'), 'binary'), { resolver: resolverFrom({ [KEYNAME]: [rsaRec] }) });
            expect(res.arc.lastEntry.messageSignature.status.result).to.equal('pass');
        });

        it('Should not accept an ARC-Message-Signature that does not sign From', async () => {
            let log = [];
            let res = await dkimVerify(Buffer.from(amsMessage('to:subject:date'), 'binary'), { resolver: resolverFrom({ [KEYNAME]: [rsaRec] }, log) });
            expect(res.arc.lastEntry.messageSignature.status.result).to.equal('neutral');
            expect(res.arc.lastEntry.messageSignature.status.comment).to.equal('From field not signed');
            expect(log).to.deep.equal([]);
        });

        it('Should not report the ARC-Seal as a DKIM signature', async () => {
            // an ARC-Seal with a c= tag used to be verified as a DKIM-Signature too
            let msg = amsMessage('from:to:subject:date').replace('ARC-Seal: i=1; a=rsa-sha256;', 'ARC-Seal: i=1; a=rsa-sha256; c=relaxed/relaxed;');
            let res = await dkimVerify(Buffer.from(msg, 'binary'), { resolver: resolverFrom({ [KEYNAME]: [rsaRec] }) });
            expect(res.results).to.have.lengthOf(1);
            expect(res.results[0].status.result).to.equal('none');
        });
    });
});
