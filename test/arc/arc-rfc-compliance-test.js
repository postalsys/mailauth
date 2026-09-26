/* eslint no-unused-expressions:0 */
'use strict';

// RFC 8617 compliance of the ARC validator and sealer. The chains are built and checked with the
// independent reference implementation in test/helpers/arc-reference.js, so every expectation
// here is also confirmed by code that shares nothing with mailauth.

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const chai = require('chai');
const expect = chai.expect;

const { authenticate, sealMessage, verifyASChain, getARChain } = require('../../lib/mailauth');
const { createSeal } = require('../../lib/arc');
const { parseHeaders } = require('../../lib/tools');
const { privateKey } = require('../helpers/keys');
const ref = require('../helpers/arc-reference');

const MODES = [
    { name: 'lax', strict: false },
    { name: 'strict', strict: true }
];

const pem = name => ref.key(name).privateKey.export({ type: 'pkcs8', format: 'pem' });

const check = async (msg, records, opts) =>
    authenticate(
        Buffer.from(msg),
        Object.assign(
            {
                resolver: ref.resolver(records),
                disableDmarc: true,
                disableBimi: true,
                ip: '192.0.2.1',
                helo: 'mx.example',
                sender: 'alice@example.com',
                mta: 'mx.test'
            },
            opts || {}
        )
    );

// a single set sealed by one.example with selector "s" and key "k1"
const RECORDS = { 's._domainkey.one.example': 'k1' };
const singleSet = opts => ref.seal(ref.baseMessage(), [], Object.assign({ i: 1, cv: 'none', d: 'one.example', s: 's', keyName: 'k1' }, opts || {}));

// a message with one set whose ARC-Seal has the literal tag list `rawTags`
const withSealTags = rawTags => singleSet({ rawTags }).msg;

// a message with one set whose ARC-Message-Signature has `extraTags` in it
const withAmsTags = extraTags => singleSet({ amsOpts: { extraTags } }).msg;

describe('ARC RFC 8617 compliance', function () {
    this.timeout(60000);

    before(() => {
        ref.key('k1');
        ref.key('k2');
        ref.key('att');
        ref.key('victim');
        ref.key('ed1', 'ed25519');
    });

    describe('cv values are case-insensitive (RFC 8617 section 3.9, F1)', () => {
        // the attacker seals i=2 with cv=PASS over a forged i=1 set, signing only its own set
        const forgedChain = () => {
            let aar = 'ARC-Authentication-Results: i=1; mx.victim.example; dkim=pass header.i=@victim.example; spf=pass smtp.mailfrom=victim.example';
            let ams = 'ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=victim.example; s=sel; h=from:to:subject; bh=AAAA; b=AAAA';
            let as = 'ARC-Seal: i=1; a=rsa-sha256; cv=none; d=victim.example; s=sel; t=1; b=AAAAAAAA';
            let msg = `${as}\r\n${ams}\r\n${aar}\r\n${ref.baseMessage()}`;
            return ref.seal(msg, [{ aar, ams, as }], { i: 2, cv: 'PASS', d: 'att.example', s: 'sel', keyName: 'att', ownScope: true }).msg;
        };
        const forgedRecords = { 'sel._domainkey.att.example': 'att', 'sel._domainkey.victim.example': 'victim' };

        for (let mode of MODES) {
            it(`Should validate every seal behind a cv=PASS seal (${mode.name})`, async () => {
                let msg = forgedChain();
                expect(ref.validate(msg, forgedRecords).cv).to.equal('fail');

                let res = await check(msg, forgedRecords, { strict: mode.strict });
                expect(res.arc.status.result).to.equal('fail');
                expect(res.arc.status.comment).to.equal('i=2 seal signature validation failed');
                expect(res.headers).to.not.match(/arc=pass/);
            });

            it(`Should accept a valid chain that writes cv=Pass and cv=None (${mode.name})`, async () => {
                let records = { 's._domainkey.one.example': 'k1', 's._domainkey.two.example': 'k2' };
                let a = ref.seal(ref.baseMessage(), [], { i: 1, cv: 'None', d: 'one.example', s: 's', keyName: 'k1' });
                let b = ref.seal(a.msg, a.sets, { i: 2, cv: 'Pass', d: 'two.example', s: 's', keyName: 'k2' });
                expect(ref.validate(b.msg, records).cv).to.equal('pass');

                let res = await check(b.msg, records, { strict: mode.strict });
                expect(res.arc.status.result).to.equal('pass');
            });
        }

        it('Should never return true from verifyASChain for a chain whose newest seal is cv=fail', async () => {
            let a = singleSet();
            // an invalid i=1 seal, and an i=2 seal with cv=fail that only signs its own set
            let forged = a.msg.replace(/(ARC-Seal: i=1;[\s\S]*?b=)[A-Za-z0-9+/]{10}/, '$1AAAAAAAAAA');
            let forgedSet = Object.assign({}, a.set, { as: forged.split('\r\n')[0] });
            let f = ref.seal(forged, [forgedSet], { i: 2, cv: 'fail', d: 'one.example', s: 's', keyName: 'k1' });

            let headers = parseHeaders(Buffer.from(f.msg.split('\r\n\r\n')[0] + '\r\n'));
            // getARChain rejects this chain, so build the sets by hand the way a caller could
            let parse = require('../../lib/parse-dkim-headers');
            let sets = new Map();
            for (let row of headers.parsed.filter(row => /^arc-/.test(row.key))) {
                let value = parse(row.line);
                let i = value.parsed.i.value;
                sets.set(i, Object.assign(sets.get(i) || { i }, { [row.key]: value }));
            }
            let chain = [...sets.values()].sort((x, y) => x.i - y.i);

            let err = await verifyASChain({ chain }, { resolver: ref.resolver(RECORDS) }).catch(err => err);
            expect(err).to.be.an('error');
            expect(err.code).to.equal('invalid_cv_value');
        });

        it('Should never return true from verifyASChain when an older seal is invalid', async () => {
            let records = { 's._domainkey.one.example': 'k1' };
            let a = singleSet();
            let b = ref.seal(a.msg, a.sets, { i: 2, cv: 'pass', d: 'one.example', s: 's', keyName: 'k1' });
            // change the sealed i=1 AAR, the i=2 seal is re-created over the changed set
            let aar = a.set.aar.replace('spf=pass', 'spf=fail');
            let changed = b.msg.replace(a.set.aar, aar);
            let set1 = Object.assign({}, a.set, { aar });
            let sealed = ref.makeAS([set1], b.set, { i: 2, cv: 'pass', d: 'one.example', s: 's', keyName: 'k1' });
            changed = changed.replace(b.set.as, sealed);
            expect(ref.validate(changed, records)).to.deep.equal({ cv: 'fail', reason: 'seal signature i=1' });

            let chain = getARChain(parseHeaders(Buffer.from(changed.split('\r\n\r\n')[0] + '\r\n')));
            let err = await verifyASChain({ chain }, { resolver: ref.resolver(records) }).catch(err => err);
            expect(err).to.be.an('error');
            expect(err.code).to.equal('failing_arc_seal');
        });
    });

    describe('Ed25519 seals (RFC 8463, F2)', () => {
        const records = { 'rsa._domainkey.one.example': 'k1', 'ed._domainkey.one.example': 'ed1' };

        const edSealed = hashed => {
            let aar = 'ARC-Authentication-Results: i=1; one.example; spf=pass smtp.mailfrom=example.com';
            let ams = ref.makeAMS(ref.baseMessage(), { i: 1, d: 'one.example', s: 'rsa', keyName: 'k1' });
            let as = ref.makeAS([], { aar, ams }, { i: 1, cv: 'none', d: 'one.example', s: 'ed', keyName: 'ed1', alg: 'ed25519-sha256' });
            if (!hashed) {
                // signed over the canonicalized data itself instead of its SHA-256 hash
                let field = as.slice(0, as.lastIndexOf('b=') + 2);
                let data = ref.relaxedHeader(aar) + '\r\n' + ref.relaxedHeader(ams) + '\r\n' + ref.relaxedHeader(field);
                as = field + crypto.sign(null, Buffer.from(data, 'binary'), ref.key('ed1').privateKey).toString('base64');
            }
            return `${as}\r\n${ams}\r\n${aar}\r\n${ref.baseMessage()}`;
        };

        for (let mode of MODES) {
            it(`Should verify an RFC 8463 ed25519-sha256 ARC-Seal (${mode.name})`, async () => {
                let msg = edSealed(true);
                expect(ref.validate(msg, records).cv).to.equal('pass');
                let res = await check(msg, records, { strict: mode.strict });
                expect(res.arc.status.result).to.equal('pass');
            });

            it(`Should reject an ed25519 ARC-Seal made without the SHA-256 pre-hash (${mode.name})`, async () => {
                let msg = edSealed(false);
                expect(ref.validate(msg, records).cv).to.equal('fail');
                let res = await check(msg, records, { strict: mode.strict });
                expect(res.arc.status.result).to.equal('fail');
            });
        }

        for (let algorithm of [undefined, 'ed25519-sha256', 'ED25519-SHA256']) {
            it(`Should seal with an ed25519 key (algorithm ${algorithm || 'not set'})`, async () => {
                let { headers, errors } = await createSeal(Buffer.from(ref.baseMessage()), {
                    seal: {
                        signingDomain: 'one.example',
                        selector: 'ed',
                        privateKey: pem('ed1'),
                        algorithm,
                        authResults: 'mx.one.example; spf=pass smtp.mailfrom=example.com'
                    }
                });
                expect(errors).to.deep.equal([]);
                expect(headers).to.have.lengthOf(3);
                expect(headers[0]).to.match(/^ARC-Seal: i=1; a=ed25519-sha256;/);
                expect(headers[1]).to.match(/^ARC-Message-Signature: i=1; a=ed25519-sha256;/);

                let msg = headers.join('\r\n') + '\r\n' + ref.baseMessage();
                expect(ref.validate(msg, records).cv).to.equal('pass');
                let res = await check(msg, records);
                expect(res.arc.status.result).to.equal('pass');
            });
        }

        it('Should seal with an ed25519 key from authenticate()', async () => {
            let res = await check(ref.baseMessage(), records, {
                seal: { signingDomain: 'one.example', selector: 'ed', privateKey: pem('ed1') }
            });
            expect(res.arc.sealErrors).to.not.exist;
            let msg = res.headers + ref.baseMessage();
            expect(msg).to.match(/^ARC-Seal: i=1; a=ed25519-sha256;/m);
            expect(ref.validate(msg, records).cv).to.equal('pass');
        });

        it('Should refuse an algorithm that does not match the key', async () => {
            let { headers, errors } = await createSeal(Buffer.from(ref.baseMessage()), {
                seal: { signingDomain: 'one.example', selector: 'rsa', privateKey: pem('k1'), algorithm: 'ed25519-sha256', authResults: 'x; none' }
            });
            expect(headers).to.deep.equal([]);
            expect(errors[0].err.code).to.equal('EINVALIDTYPE');
        });

        it('Should refuse rsa-sha1, which no ARC validator accepts', async () => {
            let { headers, errors } = await createSeal(Buffer.from(ref.baseMessage()), {
                seal: { signingDomain: 'one.example', selector: 'rsa', privateKey: pem('k1'), algorithm: 'rsa-sha1', authResults: 'x; none' }
            });
            expect(headers).to.deep.equal([]);
            expect(errors[0].err.code).to.equal('EINVALIDALGO');
        });
    });

    describe('ARC-Seal and ARC-Message-Signature tag syntax (RFC 6376 section 3.2, F4)', () => {
        const invalid = [
            ['a duplicate tag', () => withSealTags('i=1; a=rsa-sha256; cv=none; d=one.example; s=s; s=s; b='), 'i=1 as duplicate tag: s'],
            ['a duplicate cv tag', () => withSealTags('i=1; a=rsa-sha256; cv=pass; d=one.example; s=s; cv=none; b='), 'i=1 as duplicate tag: cv'],
            ['an upper case tag name', () => withSealTags('i=1; a=rsa-sha256; cv=none; d=one.example; S=s; b='), 'i=1 as missing s='],
            ['an empty tag-spec', () => withSealTags('i=1; a=rsa-sha256; cv=none; d=one.example; s=s;; b='), 'i=1 as empty tag-spec'],
            ['an invalid tag name', () => withSealTags('i=1; a=rsa-sha256; cv=none; d=one.example; s=s; _=; b='), 'i=1 as invalid tag name: _'],
            ['a t= that is not a number', () => withSealTags('i=1; a=rsa-sha256; cv=none; d=one.example; s=s; t=1 2; b='), 'i=1 as invalid t='],
            ['a duplicate tag in the AMS', () => withAmsTags('s=s; '), 'i=1 ams duplicate tag: s'],
            ['an upper case tag name in the AMS', () => withAmsTags('BH=AAAA; '), null]
        ];

        for (let [title, build, comment] of invalid) {
            it(`Should accept ${title} with a warning (lax)`, async () => {
                let res = await check(build(), RECORDS);
                expect(res.arc.status.result).to.equal('pass');
                expect(res.arc.warnings).to.include('arc-tag-syntax');
                expect(res.headers).to.not.include('arc-tag-syntax');
            });

            it(`Should reject ${title} (strict)`, async () => {
                let msg = build();
                let res = await check(msg, RECORDS, { strict: true });
                if (comment) {
                    expect(ref.validate(msg, RECORDS).cv).to.equal('fail');
                    expect(res.arc.status.result).to.equal('fail');
                    expect(res.arc.status.comment).to.equal(comment);
                } else {
                    // "BH" is an unknown tag in strict mode, so it is ignored
                    expect(res.arc.status.result).to.equal('pass');
                }
            });
        }

        for (let mode of MODES) {
            it(`Should ignore an unknown tag (${mode.name})`, async () => {
                let msg = withSealTags('i=1; a=rsa-sha256; cv=none; d=one.example; s=s; x9=abc; b=');
                expect(ref.validate(msg, RECORDS).cv).to.equal('pass');
                let res = await check(msg, RECORDS, { strict: mode.strict });
                expect(res.arc.status.result).to.equal('pass');
                expect(res.arc.warnings).to.not.exist;
            });
        }

        it('Should read an upper case H= in the ARC-Seal as an unknown tag (strict)', async () => {
            let msg = withSealTags('i=1; a=rsa-sha256; cv=none; d=one.example; s=s; H=from; b=');
            expect(ref.validate(msg, RECORDS).cv).to.equal('pass');
            expect((await check(msg, RECORDS, { strict: true })).arc.status.result).to.equal('pass');
            // the lenient mode folds tag names to lower case, as it always has
            expect((await check(msg, RECORDS)).arc.status.comment).to.equal('i=1 unexpected as h');
        });
    });

    describe('AMS h= without From (RFC 6376 section 6.1.1, F3)', () => {
        for (let mode of MODES) {
            it(`Should fail a chain whose newest AMS does not sign From (${mode.name})`, async () => {
                let msg = singleSet({ amsOpts: { h: ['to', 'subject'] } }).msg.replace('From: Alice <alice@example.com>', 'From: CEO <ceo@bank.example>');
                expect(ref.validate(msg, RECORDS).cv).to.equal('fail');
                let res = await check(msg, RECORDS, { strict: mode.strict });
                expect(res.arc.status.result).to.equal('fail');
                expect(res.arc.signature.status.comment).to.equal('From field not signed');
            });
        }
    });

    describe('Sealing (RFC 8617 section 5.1, F6 and F8)', () => {
        const base = {
            signingDomain: 'one.example',
            selector: 's',
            authResults: 'mx.one.example; spf=pass smtp.mailfrom=example.com',
            signTime: new Date('2024-01-01T00:00:00Z')
        };
        const sealOpts = extra => Object.assign({ privateKey: pem('k1') }, base, extra || {});

        const sealAndValidate = async (msg, extra) => {
            let { headers, errors, warnings } = await createSeal(Buffer.from(msg), { seal: sealOpts(extra) });
            let out = headers.join('\r\n') + (headers.length ? '\r\n' : '') + msg;
            return { headers, errors, warnings, out, independent: ref.validate(out, RECORDS) };
        };

        it('Should use cv=none for the first set when cv is not set', async () => {
            let { headers, independent } = await sealAndValidate(ref.baseMessage(), {});
            expect(headers[0]).to.match(/^ARC-Seal: i=1; a=rsa-sha256; t=\d+; cv=none;/);
            expect(independent.cv).to.equal('pass');
        });

        it('Should require a cv value when extending a chain', async () => {
            let { headers, errors } = await sealAndValidate(singleSet().msg, {});
            expect(headers).to.deep.equal([]);
            expect(errors[0].err.code).to.equal('EINVALIDCV');
        });

        it('Should read the cv value case-insensitively', async () => {
            let { headers, independent } = await sealAndValidate(singleSet().msg, { cv: 'PASS' });
            expect(headers[0]).to.match(/^ARC-Seal: i=2;.* cv=pass;/);
            expect(independent.cv).to.equal('pass');
        });

        it('Should refuse a cv value that is not none, pass or fail', async () => {
            let { headers, errors } = await sealAndValidate(ref.baseMessage(), { cv: 'maybe' });
            expect(headers).to.deep.equal([]);
            expect(errors[0].err.code).to.equal('EINVALIDCV');
        });

        it('Should not seal a chain whose newest seal is cv=fail', async () => {
            let a = singleSet();
            let f = ref.seal(a.msg, a.sets, { i: 2, cv: 'fail', d: 'one.example', s: 's', keyName: 'k1' });
            for (let cv of ['fail', 'pass', 'none']) {
                let { headers, errors } = await sealAndValidate(f.msg, { cv });
                expect(headers, cv).to.deep.equal([]);
                expect(errors[0].err.code, cv).to.equal('EARCCHAINFAILED');
            }
            expect((await sealMessage(Buffer.from(f.msg), sealOpts({ cv: 'fail' }))).length).to.equal(0);
        });

        it('Should seal a broken chain with cv=fail as the next instance, not as a second i=1', async () => {
            let broken = singleSet().msg.replace('\r\nFrom:', '\r\nARC-Authentication-Results: i=1; dup.example; spf=fail\r\nFrom:');
            let { headers } = await sealAndValidate(broken, { cv: 'fail' });
            expect(headers[0]).to.match(/^ARC-Seal: i=2;.* cv=fail;/);
            expect(headers[2]).to.match(/^ARC-Authentication-Results: i=2;/);
        });

        it('Should not claim cv=pass over a chain that could not be parsed', async () => {
            let broken = singleSet().msg.replace('\r\nFrom:', '\r\nARC-Authentication-Results: i=1; dup.example; spf=fail\r\nFrom:');
            let { headers, errors } = await sealAndValidate(broken, { cv: 'pass' });
            expect(headers).to.deep.equal([]);
            expect(errors[0].err.code).to.equal('EINVALIDCV');
        });

        it('Should refuse an instance that already exists', async () => {
            let { headers, errors } = await sealAndValidate(singleSet().msg, { cv: 'pass', i: 1 });
            expect(headers).to.deep.equal([]);
            expect(errors[0].err.code).to.equal('EINVALIDINSTANCE');
        });

        for (let i of [0, 51, 1.5, 'x']) {
            it(`Should refuse the instance ${JSON.stringify(i)}`, async () => {
                let { headers, errors } = await sealAndValidate(ref.baseMessage(), { i });
                expect(headers).to.deep.equal([]);
                expect(errors[0].err.code).to.equal('EINVALIDINSTANCE');
            });
        }

        it('Should seal an instance that leaves a gap only in lax mode', async () => {
            let lax = await sealAndValidate(ref.baseMessage(), { i: 5, cv: 'none' });
            expect(lax.headers[0]).to.match(/^ARC-Seal: i=5;/);
            expect(lax.warnings).to.include('arc-instance-gap');
            expect(lax.warnings).to.include('arc-cv-instance');

            let strict = await sealAndValidate(ref.baseMessage(), { i: 5, cv: 'none', strict: true });
            expect(strict.headers).to.deep.equal([]);
            expect(strict.errors[0].err.code).to.equal('EINVALIDINSTANCE');
        });

        it('Should seal a cv value that does not fit the instance only in lax mode', async () => {
            let lax = await sealAndValidate(ref.baseMessage(), { cv: 'pass' });
            expect(lax.headers[0]).to.match(/^ARC-Seal: i=1;.* cv=pass;/);
            expect(lax.warnings).to.include('arc-cv-instance');
            // what was asked for, which no validator accepts
            expect(lax.independent.cv).to.equal('fail');

            let strict = await sealAndValidate(ref.baseMessage(), { cv: 'pass', strict: true });
            expect(strict.headers).to.deep.equal([]);
            expect(strict.errors[0].err.code).to.equal('EINVALIDCV');

            let strictNone = await sealAndValidate(singleSet().msg, { cv: 'none', strict: true });
            expect(strictNone.headers).to.deep.equal([]);
            expect(strictNone.errors[0].err.code).to.equal('EINVALIDCV');
        });

        it('Should pass the strict option to the ARC-Message-Signature signer', async () => {
            let opts = { privateKey: privateKey('private-small.pem'), cv: 'none' };
            let lax = await createSeal(Buffer.from(ref.baseMessage()), { seal: Object.assign({}, base, opts) });
            expect(lax.headers).to.have.lengthOf(3);
            expect(lax.warnings).to.include('weak-key');

            for (let data of [{ strict: true }, { seal: { strict: true } }]) {
                let strict = await createSeal(Buffer.from(ref.baseMessage()), {
                    strict: data.strict,
                    seal: Object.assign({}, base, opts, data.seal || {})
                });
                expect(strict.headers).to.deep.equal([]);
                expect(strict.errors[0].err.code).to.equal('ESHORTKEY');
            }
        });

        it('Should not add a 51st set', async () => {
            let msg = ref.baseMessage();
            let sets = [];
            for (let i = 1; i <= 50; i++) {
                let r = ref.seal(msg, sets, { i, cv: i === 1 ? 'none' : 'pass', d: 'one.example', s: 's', keyName: 'k1' });
                msg = r.msg;
                sets = r.sets;
            }
            expect(ref.validate(msg, RECORDS).cv).to.equal('pass');

            let { headers, errors } = await sealAndValidate(msg, { cv: 'pass' });
            expect(headers).to.deep.equal([]);
            expect(errors[0].err.code).to.equal('EINVALIDINSTANCE');

            let res = await check(msg, RECORDS, { seal: sealOpts() });
            expect(res.arc.status.result).to.equal('pass');
            expect(res.arc.i).to.equal(50);
            expect(res.headers).to.not.match(/^ARC-/m);
            expect(res.arc.sealErrors[0].err.code).to.equal('EINVALIDINSTANCE');
            expect(res.arc.sealErrors[0].err.message).to.equal('Can not add ARC set i=51, the chain already has 50 sets');
        });

        it('Should extend a chain that validates with the independent validator', async () => {
            let a = singleSet();
            let { headers, independent } = await sealAndValidate(a.msg, { cv: 'pass' });
            expect(headers[0]).to.match(/^ARC-Seal: i=2;/);
            expect(independent.cv).to.equal('pass');
        });
    });

    describe('AMS canonicalization default (RFC 6376 section 3.5, F7)', () => {
        const base =
            'From:   Alice <alice@example.com>\r\nTo: bob@example.net\r\nSubject: hello  there\r\nDate: Thu, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nHello   world  \r\n\r\n';
        const noC = signedWith => ref.seal(base, [], { i: 1, cv: 'none', d: 'one.example', s: 's', keyName: 'k1', amsOpts: { c: null, signedWith } }).msg;

        for (let mode of MODES) {
            it(`Should use simple/simple for an AMS without c= (${mode.name})`, async () => {
                let msg = noC('simple/simple');
                expect(ref.validate(msg, RECORDS).cv).to.equal('pass');
                let res = await check(msg, RECORDS, { strict: mode.strict });
                expect(res.arc.status.result).to.equal('pass');
                expect(res.arc.warnings).to.not.exist;
            });
        }

        it('Should accept an AMS without c= that was signed relaxed/relaxed with a warning (lax)', async () => {
            let msg = noC('relaxed/relaxed');
            expect(ref.validate(msg, RECORDS).cv).to.equal('fail');
            let res = await check(msg, RECORDS);
            expect(res.arc.status.result).to.equal('pass');
            expect(res.arc.warnings).to.include('ams-c-default');
            expect(res.arc.signature.status.warnings).to.include('ams-c-default');
        });

        it('Should look up the shared key record once for the AMS, its fallback and the ARC-Seal', async () => {
            let resolver = ref.resolver(RECORDS);
            let res = await check(noC('relaxed/relaxed'), RECORDS, { resolver });
            expect(res.arc.status.result).to.equal('pass');
            expect(res.arc.signature.format).to.equal('relaxed/relaxed');
            expect(resolver.calls.filter(call => call === 'TXT s._domainkey.one.example')).to.have.lengthOf(1);
        });

        it('Should reject an AMS without c= that was signed relaxed/relaxed (strict)', async () => {
            let res = await check(noC('relaxed/relaxed'), RECORDS, { strict: true });
            expect(res.arc.status.result).to.equal('fail');
            expect(res.arc.status.comment).to.equal('i=1 no valid signature');
        });
    });

    describe('Instance values (RFC 8617 section 3.9, F9)', () => {
        for (let value of ['0x1', '1.0', '+1', '1e0']) {
            it(`Should accept i=${value} with a warning (lax) and reject it (strict)`, async () => {
                let msg = singleSet({ i: value }).msg;
                expect(ref.validate(msg, RECORDS).cv).to.equal('fail');

                let lax = await check(msg, RECORDS);
                expect(lax.arc.status.result).to.equal('pass');
                expect(lax.arc.warnings).to.include('arc-instance-syntax');

                let strict = await check(msg, RECORDS, { strict: true });
                expect(strict.arc.status.result).to.equal('fail');
                expect(strict.arc.status.comment).to.match(/^invalid (as|ams|aar) instance$/);
            });
        }

        for (let mode of MODES) {
            it(`Should accept i=01 (${mode.name})`, async () => {
                let msg = singleSet({ i: '01' }).msg;
                expect(ref.validate(msg, RECORDS).cv).to.equal('pass');
                let res = await check(msg, RECORDS, { strict: mode.strict });
                expect(res.arc.status.result).to.equal('pass');
                expect(res.arc.warnings).to.not.exist;
            });

            it(`Should accept an ARC-Seal whose i= is not the first tag (${mode.name})`, async () => {
                // RFC 8617 puts the instance first, but the tag-list itself is unordered and the
                // ARC test suite uses this layout for every one of its valid chains
                let msg = withSealTags('a=rsa-sha256; cv=none; d=one.example; i=1; s=s; b=');
                let res = await check(msg, RECORDS, { strict: mode.strict });
                expect(res.arc.status.result).to.equal('pass');
            });
        }

        it('Should accept an AAR whose i= is not first with a warning (lax) and reject it (strict)', async () => {
            let msg = singleSet({ aar: 'ARC-Authentication-Results: one.example; i=1; spf=pass smtp.mailfrom=example.com' }).msg;
            expect(ref.validate(msg, RECORDS).cv).to.equal('fail');

            let lax = await check(msg, RECORDS);
            expect(lax.arc.status.result).to.equal('pass');
            expect(lax.arc.warnings).to.include('arc-instance-syntax');

            let strict = await check(msg, RECORDS, { strict: true });
            expect(strict.arc.status.result).to.equal('fail');
            expect(strict.arc.status.comment).to.equal('invalid aar instance');
        });

        for (let stray of ['i=0', 'i=abc', 'i=51']) {
            it(`Should ignore a stray ARC-Seal with ${stray} with a warning (lax) and fail it (strict)`, async () => {
                let a = singleSet();
                let msg = a.msg.replace('\r\nFrom:', `\r\nARC-Seal: ${stray}; a=rsa-sha256; cv=pass; d=x.example; s=s; b=AAAA\r\nFrom:`);

                let lax = await check(msg, RECORDS);
                if (stray === 'i=51') {
                    // read as instance 51 as it always was, which breaks the sequence
                    expect(lax.arc.status.result).to.equal('fail');
                } else {
                    expect(lax.arc.status.result).to.equal('pass');
                    expect(lax.arc.warnings).to.include('arc-instance-syntax');
                }

                let strict = await check(msg, RECORDS, { strict: true });
                expect(strict.arc.status.result).to.equal('fail');
            });
        }

        it('Should report a message with only a malformed ARC header as none (lax) and fail (strict)', async () => {
            let msg = 'ARC-Seal: i=0; a=rsa-sha256; cv=none; d=x.example; s=s; b=AAAA\r\n' + ref.baseMessage();

            let lax = await check(msg, RECORDS);
            expect(lax.arc.status.result).to.equal('none');
            expect(lax.arc.warnings).to.deep.equal(['arc-instance-syntax']);

            let strict = await check(msg, RECORDS, { strict: true });
            expect(strict.arc.status.result).to.equal('fail');
            expect(strict.arc.status.comment).to.equal('invalid as instance');
        });
    });

    describe('Seal verification details (F10, F11, F12, F13)', () => {
        for (let mode of MODES) {
            it(`Should strip b= with FWS around the equals sign (${mode.name})`, async () => {
                let aar = 'ARC-Authentication-Results: i=1; one.example; spf=pass smtp.mailfrom=example.com';
                let ams = ref.makeAMS(ref.baseMessage(), { i: 1, d: 'one.example', s: 's', keyName: 'k1' });
                let field = 'ARC-Seal: i=1; a=rsa-sha256; cv=none; d=one.example; s=s; t=1700000000; b =';
                let data = ref.relaxedHeader(aar) + '\r\n' + ref.relaxedHeader(ams) + '\r\n' + ref.relaxedHeader(field);
                let sig = crypto.sign('sha256', Buffer.from(data, 'binary'), ref.key('k1').privateKey).toString('base64');
                let msg = `${field} ${sig}\r\n${ams}\r\n${aar}\r\n${ref.baseMessage()}`;
                expect(ref.validate(msg, RECORDS).cv).to.equal('pass');
                expect((await check(msg, RECORDS, { strict: mode.strict })).arc.status.result).to.equal('pass');
            });

            it(`Should fail a seal whose a= does not match the key type (${mode.name})`, async () => {
                let aar = 'ARC-Authentication-Results: i=1; one.example; spf=pass smtp.mailfrom=example.com';
                let ams = ref.makeAMS(ref.baseMessage(), { i: 1, d: 'one.example', s: 's', keyName: 'k1' });
                let field = 'ARC-Seal: i=1; a=ed25519-sha256; cv=none; d=one.example; s=s; t=1700000000; b=';
                let data = ref.relaxedHeader(aar) + '\r\n' + ref.relaxedHeader(ams) + '\r\n' + ref.relaxedHeader(field);
                // an RSA signature of the SHA-256 hash, what an ed25519 verification of an RSA key would accept
                let hash = crypto.createHash('sha256').update(Buffer.from(data, 'binary')).digest();
                let sig = crypto.sign('sha256', hash, ref.key('k1').privateKey).toString('base64');
                let msg = `${field}${sig}\r\n${ams}\r\n${aar}\r\n${ref.baseMessage()}`;

                let res = await check(msg, RECORDS, { strict: mode.strict });
                expect(res.arc.status.result).to.equal('fail');
                expect(res.arc.status.comment).to.equal('inappropriate key algorithm for s._domainkey.one.example');
            });

            for (let [title, record, comment] of [
                ['h= that does not list sha256', () => ref.dnsTxt('k1', 'h=sha1; '), 'inappropriate hash algorithm for s._domainkey.one.example'],
                ['s= that does not list email', () => ref.dnsTxt('k1', 's=other; '), 'key not for email for s._domainkey.one.example'],
                ['v= other than DKIM1', () => ref.dnsTxt('k1').replace('v=DKIM1', 'v=DKIM2'), 'unknown key version for s._domainkey.one.example']
            ]) {
                it(`Should apply a key record ${title} to ARC keys (${mode.name})`, async () => {
                    let res = await check(singleSet().msg, { 's._domainkey.one.example': record() }, { strict: mode.strict });
                    expect(res.arc.status.result).to.equal('fail');
                    expect(res.arc.status.comment).to.equal(comment);
                });
            }

            for (let cTag of ['c=relaxed', 'c=relaxed/relaxed', 'c=simple']) {
                it(`Should ignore ${cTag} on an ARC-Seal (${mode.name})`, async () => {
                    let msg = withSealTags(`i=1; a=rsa-sha256; cv=none; ${cTag}; d=one.example; s=s; b=`);
                    expect(ref.validate(msg, RECORDS).cv).to.equal('pass');
                    let res = await check(msg, RECORDS, { strict: mode.strict });
                    expect(res.arc.status.result).to.equal('pass');
                    // the ARC-Seal is not a DKIM signature
                    expect(res.dkim.results.map(r => r.status.result)).to.deep.equal(['none']);
                });
            }
        }
    });

    describe('AMS header list (RFC 8617 section 4.1.2, F14)', () => {
        const msg = ref.baseMessage().replace('\r\n\r\n', '\r\nDKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=x; h=from; bh=AAAA; b=AAAA\r\n\r\n');
        const amsH = headers =>
            headers[1]
                .match(/h=[^;]*/)[0]
                .replace(/\s+/g, '')
                .toLowerCase();
        const seal = headerList =>
            createSeal(Buffer.from(msg), { seal: { signingDomain: 'one.example', selector: 's', privateKey: pem('k1'), headerList, authResults: 'x; none' } });

        it('Should sign DKIM-Signature by default', async () => {
            expect(amsH((await seal()).headers)).to.equal('h=dkim-signature:message-id:date:subject:to:from');
        });

        it('Should accept the header list as an array', async () => {
            expect(amsH((await seal(['from', 'subject'])).headers)).to.equal('h=subject:from');
        });

        it('Should never sign ARC header fields or Authentication-Results', async () => {
            let { headers } = await seal('from:subject:arc-seal:authentication-results:arc-authentication-results:arc-message-signature');
            expect(amsH(headers)).to.equal('h=subject:from');
        });
    });

    describe('Authentication-Results reporting (RFC 8617 section 6, F15)', () => {
        it('Should report arc=none and smtp.remote-ip in strict mode only', async () => {
            let lax = await check(ref.baseMessage(), RECORDS);
            expect(lax.arc.info).to.not.exist;
            expect(lax.headers).to.not.match(/arc=/);

            let strict = await check(ref.baseMessage(), RECORDS, { strict: true });
            expect(strict.arc.info).to.equal('arc=none smtp.remote-ip=192.0.2.1');
            expect(strict.headers).to.include('arc=none smtp.remote-ip=192.0.2.1');
        });

        it('Should quote an IPv6 smtp.remote-ip in strict mode', async () => {
            let res = await check(singleSet().msg, RECORDS, { strict: true, ip: '2001:db8::1' });
            expect(res.arc.info).to.equal('arc=pass (i=1 spf=pass) smtp.remote-ip="2001:db8::1"');
        });

        it('Should not change the lax arc= entry', async () => {
            let res = await check(singleSet().msg, RECORDS);
            expect(res.arc.info).to.equal('arc=pass (i=1 spf=pass)');
        });
    });
});
