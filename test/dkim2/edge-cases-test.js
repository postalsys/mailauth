/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const chai = require('chai');
const expect = chai.expect;

const { dkim2Sign } = require('../../lib/dkim2/sign');
const { dkim2Verify } = require('../../lib/dkim2/verify');
const { parseMessageInstance, parseSignature, parsePath } = require('../../lib/dkim2/fields');
const { parseRecipe } = require('../../lib/dkim2/recipe');
const {
    rsaKey,
    ed25519Key,
    generated,
    keyRecord,
    publicKeyData,
    resolver,
    message,
    originatorOptions,
    signMessage,
    craftSignature,
    b64
} = require('../helpers/dkim2');
const reference = require('../helpers/dkim2-reference');

// the sha256 header and body hashes of a message, as the reference computes them
const instanceHash = input => {
    let { fields, body } = reference.splitMessage(Buffer.from(input).toString('binary'));
    return `${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')}`;
};

chai.config.includeStack = true;

const H = 'AAAA';
const verify = (input, options) => dkim2Verify(input, Object.assign({ resolver: resolver() }, options || {}));
const rsaOnly = extra => originatorOptions(Object.assign({ signatureData: [{ selector: 'rsa', privateKey: rsaKey }] }, extra || {}));

// a hop signed by example.com to an example.com address, so that example.com can sign again
const hop = (rcptTo, extra) => rsaOnly(Object.assign({ mailFrom: 'relay@example.com', rcptTo }, extra || {}));

describe('DKIM2 edge cases', () => {
    describe('field syntax', () => {
        it('rejects invalid selectors, hash names and timestamps', () => {
            const tags = `i=1; m=1; d=example.com; mf=${b64('<a@example.com>')}; rt=${b64('<b@example.net>')};`;
            expect(parseSignature(`DKIM2-Signature: ${tags} t=1; s=se!l:rsa-sha256:${H};`).error).to.equal('syntax error');
            expect(parseSignature(`DKIM2-Signature: ${tags} t=1; s=sel:rsa!sha256:${H};`).error).to.equal('syntax error');
            expect(parseSignature(`DKIM2-Signature: ${tags} t=abc; s=sel:rsa-sha256:${H};`).error).to.equal('syntax error');
            expect(parseMessageInstance(`Message-Instance: m=1; h=sha!256:${H}:${H};`).error).to.equal('syntax error');
        });

        it('rejects repeated tags, bad tag names, bad nd= domains and bad paths in a DKIM2-Signature', () => {
            const tags = `i=1; m=1; t=1; d=example.com; mf=${b64('<a@example.com>')}; rt=${b64('<b@example.net>')}; s=sel:rsa-sha256:${H};`;
            expect(parseSignature(`DKIM2-Signature: ${tags} f=a; f=b;`).error).to.equal('syntax error');
            expect(parseSignature(`DKIM2-Signature: ${tags} 1x=y;`).error).to.equal('syntax error');
            expect(parseSignature(`DKIM2-Signature: i=1; m=1; t=1; d=example.com; nd=bad..domain; s=sel:rsa-sha256:${H};`).error).to.equal('syntax error');
            expect(parseSignature(`DKIM2-Signature: ${tags.replace(/mf=[^;]+/, 'mf=!!!!')}`).error).to.equal('syntax error');
            expect(parseSignature(`DKIM2-Signature: ${tags.replace(/rt=[^;]+/, `rt=${b64('<b@example.net>')},${b64('bad')}`)}`).error).to.equal('syntax error');
        });

        it('reads the m= and i= of a field with a syntax error elsewhere', () => {
            expect(parseMessageInstance('Message-Instance: m=4; h=bad').m).to.equal(4);
            expect(parseSignature('DKIM2-Signature: i=3; m=x').i).to.equal(3);
            expect(parseSignature('DKIM2-Signature: i=3 3; m=x').i).to.be.NaN;
        });

        it('trims whitespace around flags', () => {
            let parsed = parseSignature(`DKIM2-Signature: i=1; m=1; t=1; d=example.com; nd=example.net; f=\r\n exploded ,\tfeedback ; s=sel:rsa-sha256:${H};`);
            expect(parsed.flags).to.deep.equal(['exploded', 'feedback']);
        });

        it('splits SMTP paths, leaving out a source route', () => {
            expect(parsePath('<@relay.example,@other.example:User@Example.COM>')).to.deep.equal({ address: 'User@example.com', domain: 'example.com' });
            expect(parsePath('<postmaster>')).to.deep.equal({ address: 'postmaster', domain: '' });
            expect(parsePath('<>')).to.deep.equal({ address: '', domain: '' });
            expect(parsePath(undefined)).to.deep.equal({ address: '', domain: '' });
        });

        it('rejects a Recipe that is null', () => {
            expect(parseRecipe('null').error).to.equal('not a JSON object');
            expect(parseRecipe('{"b":[{"d":["ok",null]}]}').error).to.equal('"b" Recipe has an invalid "d" step');
        });
    });

    describe('verification details', () => {
        it('reports the key size, the key record and the signing time', async () => {
            let signed = await signMessage(message(), rsaOnly({ signTime: new Date('2026-10-10T10:00:00Z') }));
            let result = await verify(signed, { curTime: new Date('2026-10-10T11:00:00Z') });
            let entry = result.signatures[0];
            expect(entry.signTime).to.equal('2026-10-10T10:00:00.000Z');
            expect(entry.timestamp).to.equal(1791626400);
            expect(entry.values[0].modulusLength).to.equal(2048);
            expect(entry.values[0].rr).to.equal(keyRecord(rsaKey));
            expect(entry.values[0]).to.not.have.property('testing');
        });

        it('expires a signature one second after the maximum age, not at it', async () => {
            let signed = await signMessage(message(), rsaOnly({ signTime: 1000000000000 }));
            expect((await verify(signed, { curTime: 1000000000000 + 1209600 * 1000 })).status.result).to.equal('pass');
            expect((await verify(signed, { curTime: 1000000000000 + 1209601 * 1000 })).status.result).to.equal('permerror');
        });

        it('lists every signature as skipped when the header fields are invalid', async () => {
            let signed = await signMessage(message(), rsaOnly());
            let broken = Buffer.concat([Buffer.from('Message-Instance: m=1; h=sha256:AAAA:AAAA;\r\n'), signed]);
            let result = await verify(broken);
            expect(result.status.comment).to.equal('Message-Instance m=1 appears more than once');
            expect(result.signatures[0].status).to.deep.equal({ result: 'skipped' });
            expect(result.signatures[0].values).to.deep.equal([{ selector: 'rsa', algorithm: 'rsa-sha256' }]);
            expect(result.info).to.equal('dkim2=permerror (i=1 example.com skipped; Message-Instance m=1 appears more than once) header.d=example.com');
            expect(result).to.not.have.property('replay');
        });

        it('limits the number of signatures too', async () => {
            let signed = await signMessage(message(), rsaOnly());
            let many = Buffer.concat([Buffer.from(Array.from({ length: 3 }, (v, i) => `DKIM2-Signature: i=${i + 2}; bad\r\n`).join('')), signed]);
            let result = await verify(many, { maxInstances: 3 });
            expect(result.status.comment).to.equal('Message has more than 3 Message-Instance or DKIM2-Signature header fields');
        });

        it('builds the replay key from the first supported hash of m=1', async () => {
            let signed = await signMessage(message(), rsaOnly({ hashAlgorithms: ['sha512', 'sha256'] }));
            let result = await verify(signed);
            expect(result.replay.key).to.match(/^sha512:/);
        });

        it('attributes a custody error to its hop in the comment', async () => {
            let signed = await signMessage(message(), rsaOnly());
            let result = await verify(signed, { mailFrom: 'x@example.com' });
            expect(result.signatures[0].status).to.deep.equal({ result: 'permerror', comment: undefined });
            expect(result.info).to.match(/^dkim2=permerror \(i=1 example\.com permerror;/);
        });

        it('ignores envelope values that are not strings', async () => {
            let signed = await signMessage(message(), rsaOnly());
            expect((await verify(signed, { mailFrom: null, rcptTo: [null, 5] })).status.result).to.equal('pass');
        });
    });

    describe('multiple hops', () => {
        it('checks donotexplode against every later hop', async () => {
            let first = await signMessage(message(), hop('a@example.com', { flags: ['donotexplode'] }));
            let second = await signMessage(first, hop('b@example.com'));
            let third = await signMessage(second, hop('c@example.com', { flags: ['exploded'] }));
            let result = await verify(third);
            expect(result.status.comment).to.equal('Message has been exploded despite a donotexplode request');
            expect(result.errors).to.have.length(1);

            let quiet = await signMessage(second, hop('c@example.com'));
            expect((await verify(quiet)).status.result).to.equal('pass');
        });

        it('reports a donotmodify failure once, and catches a removed header field', async () => {
            let first = await signMessage(message(['Comments: keep me']), hop('a@example.com', { flags: ['donotmodify'] }));
            let second = await signMessage(first, hop('b@example.com', { flags: ['donotmodify'] }));
            let removed = Buffer.from(second.toString('binary').replace('Comments: keep me\r\n', ''), 'binary');
            let third = await signMessage(removed, hop('c@example.com', { recipe: { h: { comments: [{ d: ['keep me'] }] } } }));
            let result = await verify(third);
            expect(result.status.result).to.equal('fail');
            expect(result.errors.map(error => error.message)).to.deep.equal(['Message has been modified despite a donotmodify request']);
        });

        it('catches a removed copy of a repeated header field despite donotmodify', async () => {
            let first = await signMessage(message(['Comments: same', 'Comments: same']), hop('a@example.com', { flags: ['donotmodify'] }));
            let removed = Buffer.from(first.toString('binary').replace('Comments: same\r\n', ''), 'binary');
            let second = await signMessage(removed, hop('b@example.com', { recipe: { h: { comments: [{ c: [1, 1] }, { d: ['same'] }] } } }));
            expect((await verify(second)).status.comment).to.equal('Message has been modified despite a donotmodify request');
        });

        it('recreates a body that lost its last line and its final line break', async () => {
            let first = await signMessage(message([], 'a\r\nb\r\nc\r\n'), hop('a@example.com'));
            let cut = Buffer.from(
                first
                    .toString('binary')
                    .replace(/c\r\n$/, '')
                    .replace(/\r\n$/, ''),
                'binary'
            );
            let second = await signMessage(cut, hop('b@example.com', { recipe: { b: [{ c: [1, 2] }, { d: ['c'] }] } }));
            let result = await verify(second);
            expect(result.status.result).to.equal('pass');
            expect(result.instances[1].recipe.body).to.equal('recipe');
        });

        it('recreates UTF-8 header values and body lines from Recipe data', async () => {
            let original = Buffer.from('From: sender@example.com\r\nSubject: Héllo wörld\r\n\r\nRésumé\r\nend\r\n', 'utf8');
            let first = await signMessage(original, hop('a@example.com'));
            let changed = Buffer.from(first.toString('utf8').replace('Héllo wörld', 'plain').replace('Résumé', 'Resume'), 'utf8');
            let recipe = { h: { subject: [{ d: ['Héllo wörld'] }] }, b: [{ d: ['Résumé'] }, { c: [2, 2] }] };
            let second = await signMessage(changed, hop('b@example.com', { recipe }));
            expect((await verify(second)).status.result).to.equal('pass');

            let wrong = { h: { subject: [{ d: ['Hello world'] }] }, b: [{ d: ['Résumé'] }, { c: [2, 2] }] };
            let err = await dkim2Sign(changed, hop('b@example.com', { recipe: wrong })).catch(err => err);
            expect(err.code).to.equal('EINVALIDRECIPE');
        });

        it('links a hop with the null MAIL FROM to the hop before it by its signing domain', async () => {
            // example.com received the message, so it can relay a DSN about it with the null sender
            let first = await signMessage(message(), hop('a@example.com'));
            let dsn = await signMessage(first, rsaOnly({ mailFrom: '<>', rcptTo: 'someone@example.org' }));
            let result = await verify(dsn, { mailFrom: '', rcptTo: 'someone@example.org' });
            expect(result.status.result).to.equal('pass');
        });

        it('refuses and reports a null MAIL FROM hop from a domain the message was not sent to (replay)', async () => {
            // example.com sent the message to rcpt@example.net, list.example.org was never a recipient
            let first = await signMessage(message(), originatorOptions());
            let changed = Buffer.from(first.toString('binary').replace('Subject: Hello DKIM2', 'Subject: URGENT wire money now'), 'binary');
            let attacker = {
                signingDomain: 'list.example.org',
                selector: 'lrsa',
                privateKey: generated.rsa,
                mailFrom: '<>',
                rcptTo: 'target@example.org',
                flags: ['exploded'],
                recipe: { h: { subject: [{ d: ['Hello DKIM2'] }] } }
            };

            let err = await dkim2Sign(changed, attacker).catch(err => err);
            expect(err.code).to.equal('ECUSTODY');

            let forged = craftSignature(
                Buffer.concat([
                    Buffer.from(`Message-Instance: m=2; h=sha256:${instanceHash(changed)}; r=${b64(JSON.stringify(attacker.recipe))};\r\n`),
                    changed
                ]),
                `DKIM2-Signature: i=2; m=2; t=${Math.floor(Date.now() / 1000)}; d=list.example.org; mf=${b64('<>')}; rt=${b64('<target@example.org>')}; f=exploded; s=lrsa:rsa-sha256:;`,
                { lrsa: generated.rsa }
            );
            let result = await verify(forged, { mailFrom: '', rcptTo: 'target@example.org' });
            expect(result.errors.map(error => error.message)).to.deep.equal(['DKIM2-Signature i=2 MAIL FROM list.example.org did not match']);
            expect(result.status.result).to.equal('permerror');
            expect(result.status.comment).to.equal('DKIM2-Signature i=2 MAIL FROM list.example.org did not match');
            expect(result.status.header).to.deep.equal({ d: 'example.com', i: 2 });
        });

        it('compares a changed message with a sha512 only instance', async () => {
            let first = await signMessage(message(), originatorOptions({ rcptTo: 'list@list.example.org', hashAlgorithms: ['sha512'] }));
            let options = {
                signingDomain: 'list.example.org',
                selector: 'lrsa',
                privateKey: generated.rsa,
                mailFrom: 'bounce@list.example.org',
                rcptTo: 'member@example.net'
            };

            let unchanged = await dkim2Sign(first, options);
            expect(unchanged.messageInstance).to.equal(null);

            let changed = Buffer.from(first.toString('binary').replace('Subject: Hello DKIM2', 'Subject: changed'), 'binary');
            let err = await dkim2Sign(changed, options).catch(err => err);
            expect(err.code).to.equal('ENORECIPE');

            let revised = await signMessage(changed, Object.assign({ recipe: { h: { subject: [{ d: ['Hello DKIM2'] }] } } }, options));
            expect((await verify(revised)).status.result).to.equal('pass');
        });

        it('refuses to continue a chain whose top instance has no supported hash', async () => {
            let input = Buffer.concat([Buffer.from('Message-Instance: m=1; h=sha3:AAAA:AAAA;\r\n'), message()]);
            let err = await dkim2Sign(input, rsaOnly()).catch(err => err);
            expect(err.code).to.equal('EINVALIDCHAIN');
        });

        it('refuses a repeated DKIM2-Signature on the message', async () => {
            let first = await dkim2Sign(message(), rsaOnly());
            let input = Buffer.concat([Buffer.from(first.signatures + first.signature + '\r\n'), message()]);
            let err = await dkim2Sign(input, rsaOnly()).catch(err => err);
            expect(err.code).to.equal('EINVALIDCHAIN');
            expect(err.message).to.include('duplicate');
        });

        it('ignores Recipes for header fields that are not signed', async () => {
            let first = await signMessage(message(['X-Mailer: one']), originatorOptions({ rcptTo: 'list@list.example.org' }));
            let changed = Buffer.from(
                first.toString('binary').replace('Subject: Hello DKIM2', 'Subject: changed').replace('X-Mailer: one', 'X-Mailer: two'),
                'binary'
            );
            let revised = await signMessage(changed, {
                signingDomain: 'list.example.org',
                selector: 'lrsa',
                privateKey: generated.rsa,
                mailFrom: 'bounce@list.example.org',
                rcptTo: 'member@example.net',
                recipe: { h: { subject: [{ d: ['Hello DKIM2'] }], 'x-mailer': [{ d: ['something else'] }, { d: ['and more'] }] } }
            });
            expect((await verify(revised)).status.result).to.equal('pass');
        });
    });

    describe('key records', () => {
        const zoneFor = txt => ({ 'rsa._domainkey.example.com': { TXT: txt }, 'ed._domainkey.example.com': { TXT: txt } });

        for (let [label, txt, selector, comment] of [
            ['an Ed25519 key that is not 32 bytes', [[`v=DKIM1; k=ed25519; p=${Buffer.alloc(33, 1).toString('base64')}`]], 'ed', 'has a syntax error'],
            [
                'Ed25519 key data under k=rsa',
                [[`v=DKIM1; k=rsa; p=${crypto.createPublicKey(ed25519Key).export({ format: 'der', type: 'spki' }).toString('base64')}`]],
                'rsa',
                'has a syntax error'
            ],
            ['an empty answer', [], 'rsa', 'does not exist']
        ]) {
            it(`reports ${label}`, async () => {
                let signed = await signMessage(
                    message(),
                    originatorOptions({ signatureData: [{ selector, privateKey: selector === 'ed' ? ed25519Key : rsaKey }] })
                );
                let result = await dkim2Verify(signed, { resolver: resolver(zoneFor(txt)) });
                expect(result.status.comment).to.equal(`DKIM2-Signature i=1 public key ${selector} ${comment}`);
            });
        }

        it('reads key record tag names case sensitively, and treats an empty answer as no key', async () => {
            let signed = await signMessage(message(), rsaOnly());
            let upper = await dkim2Verify(signed, { resolver: resolver(zoneFor([[`v=DKIM1; k=rsa; P=${publicKeyData(rsaKey)}`]])) });
            expect(upper.status.comment).to.equal('DKIM2-Signature i=1 public key rsa has a syntax error');

            let empty = await dkim2Verify(signed, { resolver: async () => [] });
            expect(empty.status.comment).to.equal('DKIM2-Signature i=1 public key rsa does not exist');
        });

        it('reads a key record without v= and k=, and a bare RSAPublicKey', async () => {
            let signed = await signMessage(message(), rsaOnly());
            let pkcs1 = crypto.createPublicKey(rsaKey).export({ format: 'der', type: 'pkcs1' }).toString('base64');
            for (let record of [`p=${publicKeyData(rsaKey)}`, `v=DKIM1; p=${pkcs1}`]) {
                let result = await dkim2Verify(signed, { resolver: resolver(zoneFor([[record]])) });
                expect(result.status.result).to.equal('pass');
            }
        });

        it('reports a selector that can not be looked up', async () => {
            let longSelector = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(40)}`;
            let signed = await signMessage(message(), originatorOptions({ signatureData: [{ selector: longSelector, privateKey: rsaKey }] }));
            let result = await verify(signed);
            expect(result.status.comment).to.equal(`DKIM2-Signature i=1 public key ${longSelector} does not exist`);
        });
    });

    describe('signing options', () => {
        it('normalizes SMTP paths', async () => {
            for (let [mailFrom, expected] of [
                ['  sender@example.com ', '<sender@example.com>'],
                ['<sender@example.com>', '<sender@example.com>'],
                [null, '<>'],
                ['<>', '<>']
            ]) {
                let result = await dkim2Sign(message(), rsaOnly({ mailFrom, rcptTo: ' <rcpt@example.net> ' }));
                let parsed = parseSignature(result.signature);
                expect(parsed.mailFrom).to.equal(expected);
                expect(parsed.rcptTo).to.deep.equal(['<rcpt@example.net>']);
            }
        });

        it('rejects bad paths and option combinations', async () => {
            for (let [options, code] of [
                [{ rcptTo: '<>' }, 'EINVALIDPATH'],
                [{ rcptTo: null }, 'EINVALIDPATH'],
                [{ mailFrom: 'a<b@example.com' }, 'EINVALIDPATH'],
                [{ rcptTo: undefined }, 'EINVALIDOPTS'],
                [{ mailFrom: undefined, nextDomain: 'example.net' }, 'EINVALIDOPTS'],
                [{ algorithm: 'rsa-sha256', signatureData: undefined, selector: 'rsa', privateKey: ed25519Key }, 'EINVALIDALGO'],
                [
                    {
                        signatureData: [
                            {
                                selector: 'dsa',
                                privateKey: crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' })
                            }
                        ]
                    },
                    'EINVALIDALGO'
                ]
            ]) {
                let err = await dkim2Sign(message(), rsaOnly(options)).catch(err => err);
                expect(err.code, JSON.stringify(options)).to.equal(code);
            }
        });

        it('allows two keys of one algorithm with different selectors, and lower cases the domain', async () => {
            let result = await dkim2Sign(
                message(),
                originatorOptions({
                    signingDomain: ' Example.COM ',
                    signatureData: [
                        { selector: 'rsa', privateKey: rsaKey, algorithm: 'RSA-SHA256' },
                        { selector: 'rsa2', privateKey: rsaKey }
                    ]
                })
            );
            let parsed = parseSignature(result.signature);
            expect(parsed.signingDomain).to.equal('example.com');
            expect(parsed.signatures.map(entry => entry.selector)).to.deep.equal(['rsa', 'rsa2']);
        });

        it('treats a null recipe as no recipe, and accepts a recipe on the first instance', async () => {
            let plain = await dkim2Sign(message(), rsaOnly({ recipe: null, signTime: 1 }));
            let withoutOption = await dkim2Sign(message(), rsaOnly({ signTime: 1 }));
            expect(plain.messageInstance).to.equal(withoutOption.messageInstance);

            let first = await signMessage(message(), rsaOnly({ recipe: { h: { 'x-entry': [] } } }));
            expect((await verify(first)).instances[0].recipe).to.deep.equal({ headers: ['x-entry'], body: 'unchanged' });
        });

        it('signs with a raw 32 byte Ed25519 key and the next domain lower cased', async () => {
            let raw = crypto.createPrivateKey(ed25519Key).export({ format: 'der', type: 'pkcs8' }).subarray(-32);
            let result = await dkim2Sign(message(), { signingDomain: 'example.com', selector: 'ed', privateKey: raw, nextDomain: 'FWD.example.NET' });
            let parsed = parseSignature(result.signature);
            expect(parsed.nextDomain).to.equal('fwd.example.net');
            expect(parsed.signatures[0].algorithm).to.equal('ed25519-sha256');
        });
    });
});
