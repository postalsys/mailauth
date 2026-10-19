import { describe, it } from 'node:test';
import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { expect } from 'chai';

import { authenticate } from '../../src/mailauth.js';
import { dkimSign } from '../../src/dkim/sign.js';
import { sealMessage } from '../../src/arc/index.js';
import { unfold } from '../helpers/auth-results-reference.js';
import { privateKey } from '../helpers/keys.js';
import { spkiB64, edRawB64 } from '../helpers/dkim-reference.js';
import { fc, check, timeout, chunkBuffer } from './helper.js';

// End-to-end fuzzing of authenticate(). The other property tests drive one component each, or
// the whole pipeline with every DNS query failing. Here a correctly DKIM signed and ARC sealed
// message is mutated, and every DNS answer comes from a generated zone: the published keys and
// policies are valid, slightly wrong, or hostile (oversized, truncated, looping, temporary
// failures). Whatever the input, authenticate() must
//
//   - settle with a result instead of rejecting, and within a bounded number of DNS queries
//   - report only the result values the RFCs define
//   - produce header fields that are well-formed and free of control characters
//   - give the same answer when the message arrives as a stream in arbitrary chunks, so no
//     state leaks between calls and the parsers do not depend on how the input is split
//
// Runs as part of npm test with a fixed seed, see helper.ts for FC_SEED and FC_NUM_RUNS.

const rsaKey = privateKey('private-rsa.pem');
const rsaPublic = spkiB64(crypto.createPublicKey(rsaKey));
const edKey = privateKey('private-ed25519.pem');
const edPublic = edRawB64(crypto.createPublicKey(edKey));

const DOMAIN = 'example.com';
const ALLOWED = {
    dkim: ['pass', 'fail', 'neutral', 'none', 'policy', 'temperror', 'permerror'],
    spf: ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'],
    dmarc: ['pass', 'fail', 'none', 'temperror', 'permerror'],
    arc: ['pass', 'fail', 'none'],
    bimi: ['pass', 'fail', 'none', 'skipped', 'temperror', 'declined']
};

// Most queries a single authenticate() call may make: DKIM keys for the signatures, the SPF
// lookup limits of RFC 7208 4.6.4 for the MAIL FROM and HELO identities, the DMARC Tree Walks
// (RFC 9989 4.10), the ARC keys and BIMI. Far above what a legitimate message needs, far below
// what an amplification loop would make
const MAX_QUERIES = 200;

const base64Noise = fc.string({ unit: fc.constantFrom(...'ABCDEFabcdef0123456789+/='.split('')), maxLength: 40 });
const junk = fc.string({ unit: fc.constantFrom(...'az09 ;=:,.-_@%{}()<>"\\\t\x00\x7fé'.split('')), maxLength: 60 });

// TXT answers, as lists of character-strings the way dns.resolveTxt returns them
const txt = (record: string, split: number) => {
    let parts: string[] = [];
    for (let i = 0; i < record.length; i += split) {
        parts.push(record.slice(i, i + split));
    }
    return parts.length ? parts : [''];
};

const dkimRecord = (publicKey: string, keyType: string) =>
    fc.oneof(
        { weight: 6, arbitrary: fc.constant(`v=DKIM1; k=${keyType}; p=${publicKey}`) },
        fc.constant(`v=DKIM1; p=${publicKey}`),
        fc.constant(`v=DKIM1; k=${keyType}; p=`),
        fc.constant(`v=DKIM1; k=${keyType}; t=y; p=${publicKey}`),
        fc.constant(`v=DKIM1; k=${keyType}; h=sha1; p=${publicKey}`),
        fc.constant(`v=DKIM2; k=${keyType}; p=${publicKey}`),
        fc.tuple(fc.nat(publicKey.length), base64Noise).map(([pos, noise]) => `v=DKIM1; k=${keyType}; p=${publicKey.slice(0, pos)}${noise}`),
        junk
    );

const spfMechanism = fc.oneof(
    {
        weight: 6,
        arbitrary: fc.constantFrom('ip4:192.0.2.1', 'ip4:192.0.2.0/24', 'ip6:2001:db8::/32', '-ip4:192.0.2.1', '~all', '-all', '?all', '+all', 'mx', 'a', 'ptr')
    },
    {
        weight: 3,
        arbitrary: fc.constantFrom(
            'include:spf1.example.com',
            'include:spf2.example.com',
            'include:example.com',
            'exists:%{i}.%{d}',
            'a:%{l}.%{o}',
            'mx:missing.example.com'
        )
    },
    fc.constantFrom('redirect=spf1.example.com', 'redirect=example.com', 'exp=exp.example.com', 'ip4:999.1.1.1', 'include:', 'a/129', 'all:'),
    junk
);
const spfRecord = fc.array(spfMechanism, { maxLength: 8 }).map(terms => ['v=spf1', ...terms].join(' '));

const dmarcRecord = fc.oneof(
    { weight: 4, arbitrary: fc.constantFrom('v=DMARC1; p=reject', 'v=DMARC1; p=quarantine; pct=50', 'v=DMARC1; p=none; adkim=s; aspf=s') },
    fc
        .array(
            fc.oneof(
                fc.constantFrom(
                    'p=reject',
                    'p=bogus',
                    'sp=none',
                    'np=reject',
                    'adkim=r',
                    'aspf=x',
                    'pct=101',
                    'pct=-1',
                    't=y',
                    'psd=y',
                    'psd=n',
                    'rua=mailto:a@b'
                ),
                junk
            ),
            { maxLength: 8 }
        )
        .map(tags => ['v=DMARC1', ...tags].join('; ')),
    junk
);

const bimiRecord = fc.oneof(
    fc.constant('v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'),
    fc.constant('v=BIMI1; l=; a='),
    fc.constant('v=BIMI1; l=http://127.0.0.1/logo.svg'),
    junk
);

// An answer is a record, a DNS error, or nothing (NXDOMAIN)
const answer = <T>(record: fc.Arbitrary<T>) =>
    fc.oneof(
        { weight: 8, arbitrary: record.map(value => ({ value })) },
        fc.constantFrom('ENOTFOUND', 'ENODATA', 'ESERVFAIL', 'ETIMEOUT', 'ECONNREFUSED', 'EREFUSED').map(code => ({ error: code })),
        fc.constant({ error: 'ENOTFOUND' })
    );

const zone = fc.record({
    rsaKey: answer(dkimRecord(rsaPublic, 'rsa')),
    edKey: answer(dkimRecord(edPublic, 'ed25519')),
    spf: answer(spfRecord),
    spf1: answer(spfRecord),
    spf2: answer(spfRecord),
    dmarc: answer(dmarcRecord),
    bimi: answer(bimiRecord),
    // splits long TXT records into character-strings of this length
    split: fc.integer({ min: 1, max: 300 }),
    mx: fc.constantFrom([{ exchange: 'mx.example.com', priority: 10 }], [], [{ exchange: '', priority: 0 }]),
    a: fc.constantFrom(['192.0.2.1'], ['198.51.100.7'], [], ['not-an-ip'])
});

type Zone = typeof zone extends fc.Arbitrary<infer T> ? T : never;

const createResolver = (z: Zone) => {
    let queries = 0;
    let txtAnswers: Record<string, any> = {
        [`rsa._domainkey.${DOMAIN}`]: z.rsaKey,
        [`ed._domainkey.${DOMAIN}`]: z.edKey,
        [`arc._domainkey.${DOMAIN}`]: z.rsaKey,
        [DOMAIN]: z.spf,
        [`spf1.${DOMAIN}`]: z.spf1,
        [`spf2.${DOMAIN}`]: z.spf2,
        [`_dmarc.${DOMAIN}`]: z.dmarc,
        [`default._bimi.${DOMAIN}`]: z.bimi
    };
    let resolver = async (name: string, type: string): Promise<any> => {
        queries++;
        let key = String(name).toLowerCase().replace(/\.$/, '');
        let fail = (code: string) => {
            let err: any = new Error(`${code} ${name}`);
            err.code = code;
            throw err;
        };
        switch (type) {
            case 'TXT': {
                let entry = txtAnswers[key];
                if (!entry) {
                    return fail('ENOTFOUND');
                }
                if (entry.error) {
                    return fail(entry.error);
                }
                return [txt(entry.value, z.split)];
            }
            case 'MX':
                return key.endsWith(DOMAIN) ? z.mx : fail('ENOTFOUND');
            case 'A':
                return key.endsWith(DOMAIN) ? z.a : fail('ENOTFOUND');
            default:
                return fail('ENODATA');
        }
    };
    return { resolver, count: () => queries };
};

// Positions anywhere in the message. fast-check biases integers toward small values, which
// would put nearly every change into the first header field
const position = fc.noBias(fc.integer({ min: 0, max: 1000000 }));

// Changes to the signed and sealed message: none, or one of the ways a message is damaged or
// rewritten in transit
const mutation = fc.oneof(
    { weight: 3, arbitrary: fc.constant({ kind: 'none' as const }) },
    fc.record({ kind: fc.constant('flip' as const), pos: position, byte: fc.integer({ min: 0, max: 255 }) }),
    fc.record({ kind: fc.constant('truncate' as const), pos: position }),
    fc.record({
        kind: fc.constant('insert' as const),
        pos: position,
        text: fc.constantFrom('\r\n', '\n', '\r', ' ', '\t', '\r\n\r\n', 'X-Added: 1\r\n', ':', '\x00', ';')
    }),
    fc.record({ kind: fc.constant('lf' as const) }),
    fc.record({
        kind: fc.constant('prepend' as const),
        header: fc.oneof(
            fc.constantFrom('From: other@evil.example', 'From: ', 'DKIM-Signature: v=1; d=example.com; s=rsa', 'ARC-Seal: i=1', 'Received: from x by y; z'),
            junk.map(value => `X-Junk: ${value}`)
        )
    })
);

const applyMutation = (message: Buffer, m: any): Buffer => {
    switch (m.kind) {
        case 'flip': {
            let copy = Buffer.from(message);
            copy[m.pos % copy.length] = m.byte;
            return copy;
        }
        case 'truncate':
            return message.subarray(0, m.pos % (message.length + 1));
        case 'insert': {
            let pos = m.pos % (message.length + 1);
            return Buffer.concat([message.subarray(0, pos), Buffer.from(m.text, 'binary'), message.subarray(pos)]);
        }
        case 'lf':
            return Buffer.from(message.toString('binary').replace(/\r\n/g, '\n'), 'binary');
        case 'prepend':
            return Buffer.concat([Buffer.from(m.header + '\r\n', 'binary'), message]);
        default:
            return message;
    }
};

const messageInput = fc.record({
    subject: junk,
    body: fc.string({ maxLength: 300 }),
    fromLocal: fc.constantFrom('user', 'a.b', '"quoted local"'),
    fromDomain: fc.constantFrom(DOMAIN, 'sub.example.com', 'other.example', 'EXAMPLE.COM'),
    canonicalization: fc.constantFrom('relaxed/relaxed', 'simple/simple', 'relaxed/simple', 'simple/relaxed'),
    keys: fc.constantFrom(['rsa'], ['ed'], ['rsa', 'ed']),
    seal: fc.boolean()
});

const signedMessages = new Map<string, Buffer>();

// Signing is deterministic for a given input and time, so a message is signed once per input
const buildMessage = async (input: any): Promise<Buffer> => {
    let cacheKey = JSON.stringify(input);
    if (signedMessages.has(cacheKey)) {
        return signedMessages.get(cacheKey)!;
    }
    let message = Buffer.from(
        `From: ${input.fromLocal}@${input.fromDomain}\r\nTo: rcpt@example.net\r\nSubject: ${input.subject}\r\n` +
            `Date: Mon, 19 Oct 2026 10:00:00 +0000\r\nMessage-ID: <fuzz@example.com>\r\n\r\n${input.body}\r\n`
    );
    let signed = await dkimSign(message, {
        canonicalization: input.canonicalization,
        signTime: new Date('2026-10-19T10:00:00Z'),
        signatureData: input.keys.map((key: string) => ({ signingDomain: DOMAIN, selector: key, privateKey: key === 'rsa' ? rsaKey : edKey }))
    });
    message = Buffer.concat([Buffer.from(signed.signatures), message]);
    if (input.seal) {
        // sealMessage() returns the ARC header fields to prepend
        let arcHeaders = await sealMessage(message, {
            signingDomain: DOMAIN,
            selector: 'arc',
            privateKey: rsaKey,
            authResults: `mx.${DOMAIN}; dkim=pass header.d=${DOMAIN}; spf=pass smtp.mailfrom=${DOMAIN}`,
            cv: 'none',
            signTime: new Date('2026-10-19T10:00:00Z')
        });
        message = Buffer.concat([arcHeaders, message]);
    }
    signedMessages.set(cacheKey, message);
    return message;
};

// Each header field starts at the beginning of a line, continuation lines start with WSP,
// lines stay within 998 octets and no control character other than HTAB survives unfolding
const assertWellFormed = (headers: string) => {
    expect(headers.endsWith('\r\n')).to.equal(true);
    let fields: string[] = [];
    for (let line of headers.slice(0, -2).split('\r\n')) {
        expect(Buffer.byteLength(line), line.slice(0, 80)).to.be.at.most(998);
        if (/^[ \t]/.test(line)) {
            expect(fields.length).to.be.above(0);
            fields[fields.length - 1] += '\r\n' + line;
        } else {
            expect(line, line.slice(0, 80)).to.match(/^[A-Za-z][A-Za-z0-9-]*: /);
            fields.push(line);
        }
    }
    for (let field of fields) {
        expect(unfold(field), field.slice(0, 80)).to.not.match(/[\x00-\x08\x0a-\x1f\x7f]/);
    }
};

// Everything of the result that depends on the input, for comparing two runs
const summary = (res: any) =>
    JSON.stringify({
        headers: res.headers,
        dkim: res.dkim.results.map((r: any) => [r.status.result, r.status.comment, r.signingDomain, r.selector]),
        spf: res.spf && [res.spf.status.result, res.spf.status.comment],
        dmarc: res.dmarc && [res.dmarc.status.result, res.dmarc.policy, res.dmarc.p],
        arc: res.arc && [res.arc.status.result, res.arc.i],
        bimi: res.bimi && res.bimi.status.result
    });

const withTimeLimit = <T>(promise: Promise<T>, ms: number): Promise<T> => {
    let timer: NodeJS.Timeout;
    return Promise.race([
        promise,
        new Promise<T>((_, reject) => {
            timer = setTimeout(() => reject(new Error(`did not settle within ${ms} ms`)), ms);
        })
    ]).finally(() => clearTimeout(timer));
};

describe('Property: authenticate() against generated DNS zones and damaged messages', { timeout: timeout(150, 60) }, () => {
    for (let strict of [false, true]) {
        it(`settles with well-formed, stream-independent results${strict ? ' (strict)' : ''}`, () =>
            check(
                fc.asyncProperty(messageInput, mutation, zone, fc.array(fc.nat(), { minLength: 1, maxLength: 4 }), async (input, m, z, cuts) => {
                    let message = applyMutation(await buildMessage(input), m);
                    let opts = { ip: '192.0.2.1', helo: `mx.${DOMAIN}`, sender: `user@${DOMAIN}`, mta: 'mx.example.net', strict };

                    let first = createResolver(z);
                    let res: any = await withTimeLimit(authenticate(message, { ...opts, resolver: first.resolver }), 10000);
                    expect(first.count()).to.be.at.most(MAX_QUERIES);

                    for (let row of res.dkim.results) {
                        expect(ALLOWED.dkim).to.include(row.status.result);
                    }
                    expect(ALLOWED.spf).to.include(res.spf.status.result);
                    if (res.dmarc) {
                        expect(ALLOWED.dmarc).to.include(res.dmarc.status.result);
                    }
                    if (res.arc) {
                        expect(ALLOWED.arc).to.include(res.arc.status.result);
                    }
                    if (res.bimi) {
                        expect(ALLOWED.bimi).to.include(res.bimi.status.result);
                    }
                    assertWellFormed(res.headers);

                    // the same message as a stream in arbitrary chunks gives the same answer
                    let second = createResolver(z);
                    let stream = Readable.from(chunkBuffer(message, cuts));
                    let again: any = await withTimeLimit(authenticate(stream, { ...opts, resolver: second.resolver }), 10000);
                    expect(summary(again)).to.equal(summary(res));
                }),
                150
            ));
    }
});
