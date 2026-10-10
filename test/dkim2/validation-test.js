/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const chai = require('chai');
const expect = chai.expect;

const { dkim2Sign } = require('../../lib/dkim2/sign');
const { dkim2Verify } = require('../../lib/dkim2/verify');
const {
    parseMessageInstance,
    parseSignature,
    canonicalSignatureField,
    formatSignature,
    formatMessageInstance,
    continuesCustody
} = require('../../lib/dkim2/fields');
const { parseRecipe } = require('../../lib/dkim2/recipe');
const { rsaKey, ed25519Key, keyRecord, resolver, message, originatorOptions, signMessage, craftSignature, b64 } = require('../helpers/dkim2');
const reference = require('../helpers/dkim2-reference');

chai.config.includeStack = true;

const verify = (input, options) => dkim2Verify(input, Object.assign({ resolver: resolver() }, options || {}));

const H = 'AAAA';
const sig = tags => `DKIM2-Signature: ${tags}`;
const validTags = `i=1; m=1; t=1; d=example.com; mf=${b64('<a@example.com>')}; rt=${b64('<b@example.net>')}; s=rsa:rsa-sha256:${H};`;

// the Message-Instance of the plain test message
const instanceOf = input => {
    let { fields, body } = reference.splitMessage(Buffer.from(input).toString('binary'));
    return `Message-Instance: m=1; h=sha256:${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')};`;
};

const header = tags => {
    tags = Object.assign(
        {
            i: '1',
            m: '1',
            t: String(Math.floor(Date.now() / 1000)),
            d: 'example.com',
            mf: b64('<sender@example.com>'),
            rt: b64('<rcpt@example.net>'),
            s: 'rsa:rsa-sha256:'
        },
        tags || {}
    );
    return `DKIM2-Signature: ${Object.entries(tags)
        .filter(([, value]) => value !== null)
        .map(([key, value]) => `${key}=${value}`)
        .join('; ')};`;
};

const prepend = (input, ...lines) => Buffer.concat([Buffer.from(lines.join('\r\n') + '\r\n'), Buffer.from(input)]);

describe('DKIM2 validation', () => {
    describe('Message-Instance syntax (sections 7 and 11.2)', () => {
        it('parses the tags in any order and case, ignoring unknown tags', () => {
            let parsed = parseMessageInstance(`Message-Instance: X=unknown value; H = sha256 : ${H}\r\n :${H} , foo:${H}:${H} ; M = 3`);
            expect(parsed.error).to.equal(null);
            expect(parsed.m).to.equal(3);
            expect(parsed.hashes).to.deep.equal([
                { algorithm: 'sha256', headerHash: H, bodyHash: H },
                { algorithm: 'foo', headerHash: H, bodyHash: H }
            ]);
        });

        for (let [value, error] of [
            [`h=sha256:${H}:${H};`, 'tag=m missing'],
            ['m=1;', 'tag=h missing'],
            [`m=0; h=sha256:${H}:${H};`, 'syntax error'],
            [`m=x; h=sha256:${H}:${H};`, 'syntax error'],
            [`m=1; m=2; h=sha256:${H}:${H};`, 'syntax error'],
            [`m=1; h=sha256:${H};`, 'syntax error'],
            [`m=1; h=sha256:AAA:${H};`, 'syntax error'],
            [`m=1; h=sha256:${H}:${H},SHA256:${H}:${H};`, 'has a duplicate hash algorithm'],
            [`m=1; h=sha256:${H}:${H}; r=!!!!;`, 'syntax error'],
            [`m=1; h=sha256:${H}:${H}; r=${b64('{not json')};`, 'contains invalid JSON: not valid JSON'],
            [`m=1; h=sha256:${H}:${H}; r=${b64('{}')};`, 'contains invalid JSON: neither "h" nor "b" is present'],
            [`m=1; h=sha256:${H}:${H};; x=1`, 'syntax error'],
            [`m=1; novalue; h=sha256:${H}:${H}`, 'syntax error']
        ]) {
            it(`reports "${error}" for ${value}`, () => {
                expect(parseMessageInstance(`Message-Instance: ${value}`).error).to.equal(error);
            });
        }
    });

    describe('DKIM2-Signature syntax (sections 8 and 11.2)', () => {
        it('parses every tag', () => {
            let parsed = parseSignature(
                sig(
                    `I=2; m=1; t=1000000000000; d=Example.COM; mf=${b64('<>')}; rt=${b64('<b@example.net>')}, ${b64('<c@example.org>')}; n=abc:123; f=exploded , future-flag; s=sel.one:rsa-sha256:${H},sel2:ed25519-sha256:${H},x:new-algo:${H};`
                )
            );
            expect(parsed).to.deep.include({
                error: null,
                i: 2,
                m: 1,
                t: 1000000000000,
                signingDomain: 'example.com',
                mailFrom: '<>',
                rcptTo: ['<b@example.net>', '<c@example.org>'],
                nonce: 'abc:123',
                flags: ['exploded', 'future-flag']
            });
            expect(parsed.signatures.map(entry => entry.selector)).to.deep.equal(['sel.one', 'sel2', 'x']);
        });

        for (let [value, error] of [
            [validTags.replace('i=1; ', ''), 'tag=i missing'],
            [validTags.replace('m=1; ', ''), 'tag=m missing'],
            [validTags.replace('t=1; ', ''), 'tag=t missing'],
            [validTags.replace('d=example.com; ', ''), 'tag=d missing'],
            [validTags.replace(/s=.*$/, ''), 'tag=s missing'],
            [validTags.replace(/mf=[^;]+; /, ''), 'tag=mf missing'],
            [validTags.replace(/rt=[^;]+; /, ''), 'tag=rt missing'],
            [`nd=fwd.example.net; ${validTags}`, 'tag=mf was unexpected'],
            [`nd=fwd.example.net; ${validTags.replace(/mf=[^;]+; /, '')}`, 'tag=rt was unexpected'],
            [validTags.replace('i=1', 'i=0'), 'syntax error'],
            [validTags.replace('t=1', 't=1 2'), 'syntax error'],
            [validTags.replace('d=example.com', 'd=exa mple.com'), 'syntax error'],
            [validTags.replace('d=example.com', 'd=example..com'), 'syntax error'],
            [validTags.replace(/mf=[^;]+/, `mf=${b64('a@example.com')}`), 'syntax error'],
            [validTags.replace(/rt=[^;]+/, `rt=${b64('<>')}`), 'syntax error'],
            [`n=${'x'.repeat(65)}; ${validTags}`, 'syntax error'],
            [`n=has space; ${validTags}`, 'syntax error'],
            [`f=bad flag; ${validTags}`, 'syntax error'],
            [validTags.replace(/s=.*$/, `s=rsa:rsa-sha256:${H},RSA:ed25519-sha256:${H};`), 'has a duplicate selector'],
            [validTags.replace(/s=.*$/, `s=a:rsa-sha256:${H},b:rsa-sha256:${H},c:rsa-sha256:${H};`), 'has more selectors than allowed'],
            [validTags.replace(/s=.*$/, `s=a:rsa-sha256;`), 'syntax error']
        ]) {
            it(`reports "${error}" for ${value.slice(0, 60)}`, () => {
                expect(parseSignature(sig(value)).error).to.equal(error);
            });
        }
    });

    describe('signature input (section 9.6)', () => {
        it('removes all whitespace, lowercases the name and empties the signature values', () => {
            let line = Buffer.from(`DKIM2-Signature :  i=1; m=1;\r\n\tS = a : rsa-sha256 : AB\r\n CD== , b:ed25519-sha256:EF==; x=s=1`);
            expect(canonicalSignatureField(line, true).toString()).to.equal('dkim2-signature:i=1;m=1;S=a:rsa-sha256:,b:ed25519-sha256:;x=s=1\r\n');
            expect(canonicalSignatureField(line).toString()).to.equal('dkim2-signature:i=1;m=1;S=a:rsa-sha256:ABCD==,b:ed25519-sha256:EF==;x=s=1\r\n');
            // an s= that is not selector:sig-name:value is left as it is, it is a syntax error anyway
            expect(canonicalSignatureField('DKIM2-Signature: i=1; s=', true).toString()).to.equal('dkim2-signature:i=1;s=\r\n');
            expect(canonicalSignatureField('DKIM2-Signature: i=1; s=a:b', true).toString()).to.equal('dkim2-signature:i=1;s=a:b\r\n');
        });

        it('folds long values so that the canonical form does not change', () => {
            let fields = {
                i: 12,
                m: 3,
                t: 1791626400,
                signingDomain: 'a-very-long-signing-domain-name.example.com',
                mailFrom: `<${'x'.repeat(100)}@example.com>`,
                rcptTo: ['<a@example.net>', `<${'y'.repeat(80)}@example.org>`],
                nonce: 'n'.repeat(64),
                flags: ['donotmodify', 'feedback'],
                signatures: [
                    { selector: 'selector-one', algorithm: 'rsa-sha256', signature: crypto.randomBytes(256).toString('base64') },
                    { selector: 'selector-two', algorithm: 'ed25519-sha256', signature: crypto.randomBytes(64).toString('base64') }
                ]
            };
            let folded = formatSignature(fields);
            for (let line of folded.split('\r\n')) {
                expect(line.length).to.be.at.most(76);
            }
            let parsed = parseSignature(folded);
            expect(parsed.error).to.equal(null);
            expect(parsed.mailFrom).to.equal(fields.mailFrom);
            expect(parsed.rcptTo).to.deep.equal(fields.rcptTo);
            expect(parsed.signatures).to.deep.equal(fields.signatures);

            let instance = formatMessageInstance({
                m: 2,
                hashes: [
                    { algorithm: 'sha256', headerHash: crypto.randomBytes(32).toString('base64'), bodyHash: crypto.randomBytes(32).toString('base64') },
                    { algorithm: 'sha512', headerHash: crypto.randomBytes(64).toString('base64'), bodyHash: crypto.randomBytes(64).toString('base64') }
                ],
                recipe: { h: { subject: [{ d: ['x'.repeat(200)] }] } }
            });
            let parsedInstance = parseMessageInstance(instance);
            expect(parsedInstance.error).to.equal(null);
            expect(parsedInstance.hashes).to.have.length(2);
            expect(parsedInstance.recipe.h.get('subject')).to.deep.equal([{ d: ['x'.repeat(200)] }]);
        });
    });

    describe('relaxed domain match (section 9.4)', () => {
        it('removes labels from the left of the MAIL FROM domain until it matches a previous RCPT TO', () => {
            const previous = { rcptTo: ['<list@Example.com>', '<other@example.org>'] };
            expect(continuesCustody(previous, '<bounce@bounces.mail.example.com>', 'x.example')).to.be.true;
            expect(continuesCustody(previous, '<a@example.org>', 'x.example')).to.be.true;
            expect(continuesCustody(previous, '<a@notexample.com>', 'x.example')).to.be.false;
            expect(continuesCustody({ rcptTo: ['<list@mail.example.com>'] }, '<a@example.com>', 'x.example')).to.be.false;
            // a hop with nd= is matched by its signing domain
            expect(continuesCustody(previous, undefined, 'example.org')).to.be.true;
            expect(continuesCustody(previous, undefined, 'example.net')).to.be.false;
            // the null MAIL FROM is matched by the signing domain too
            expect(continuesCustody(previous, '<>', 'example.org')).to.be.true;
            expect(continuesCustody(previous, '<>', 'example.net')).to.be.false;
            // without a previous hop, or after a previous nd= hop, there is nothing to match here
            expect(continuesCustody(undefined, '<a@example.net>', 'example.net')).to.be.true;
            expect(continuesCustody({ nextDomain: 'example.net' }, '<a@example.net>', 'example.net')).to.be.true;
        });
    });

    describe('Recipe JSON (section 5)', () => {
        for (let [json, error] of [
            ['[]', 'not a JSON object'],
            ['{"h":{}}', '"h" is not an object with header field names'],
            ['{"h":{"Subject":[]}}', 'invalid header field name "Subject"'],
            ['{"h":{"sub ject":[]}}', 'invalid header field name "sub ject"'],
            ['{"h":{"subject":{}}}', '"h" Recipe for subject is not an array'],
            ['{"b":[{"c":[1]}]}', '"b" Recipe has an invalid "c" range'],
            ['{"b":[{"c":[0,1]}]}', '"b" Recipe has an invalid "c" range'],
            ['{"b":[{"c":[1.5,2]}]}', '"b" Recipe has an invalid "c" range'],
            ['{"b":[{"c":[2,1]}]}', '"b" Recipe has "c" ranges out of order'],
            ['{"b":[{"c":[1,2]},{"c":[2,3]}]}', '"b" Recipe has "c" ranges out of order'],
            ['{"b":[{"c":[1,2],"d":["x"]}]}', '"b" Recipe has a step that is not a "c" or a "d" step'],
            ['{"b":[{}]}', '"b" Recipe has a step that is not a "c" or a "d" step'],
            ['{"b":[{"d":[]}]}', '"b" Recipe has an invalid "d" step'],
            ['{"b":[{"d":["a\\r\\nb"]}]}', '"b" Recipe has an invalid "d" step'],
            ['{"b":[{"d":[1]}]}', '"b" Recipe has an invalid "d" step'],
            ['{"b":"x"}', '"b" Recipe is not an array']
        ]) {
            it(`rejects ${json}`, () => {
                expect(parseRecipe(json).error).to.equal(error);
            });
        }

        it('ignores unknown fields (section 2)', () => {
            let parsed = parseRecipe('{"h":{"subject":[{"c":[1,1],"note":"x"}]},"b":null,"z":1,"__proto__":{"polluted":true}}');
            expect(parsed.error).to.equal(undefined);
            expect(parsed.value.b).to.equal(null);
            expect({}.polluted).to.equal(undefined);
        });

        it('reports a "c" range past the end of the message as invalid JSON', async () => {
            let input = message();
            let instance1 = instanceOf(input);
            let instance2 = `Message-Instance: m=2; h=sha256:${H}:${H}; r=${b64('{"b":[{"c":[1,99]}]}')};`;
            let crafted = craftSignature(prepend(input, instance2, instance1), header({ m: '2' }), { rsa: rsaKey });
            let result = await verify(crafted);
            expect(result.status.result).to.equal('permerror');
            expect(result.status.comment).to.equal('Message-Instance m=2 contains invalid JSON: "c" range 1-99 is past the last of 3');
            expect(result.status.header.i).to.equal(1);
        });
    });

    describe('header field set (section 11.2)', () => {
        let input = message();
        let instance = instanceOf(input);

        it('passes a message signed by the reference implementation', async () => {
            let crafted = craftSignature(prepend(input, instance), header(), { rsa: rsaKey });
            expect((await verify(crafted)).status.result).to.equal('pass');
        });

        for (let [label, build, comment] of [
            ['a signature without a Message-Instance', () => craftSignature(input, header(), { rsa: rsaKey }), 'Message-Instance m=1 missing'],
            ['a Message-Instance without a signature', () => prepend(input, instance), 'DKIM2-Signature i=1 missing'],
            [
                'a gap in the instances',
                () => craftSignature(prepend(input, instance.replace('m=1', 'm=2')), header({ m: '2' }), { rsa: rsaKey }),
                'Message-Instance m=1 missing'
            ],
            ['a gap in the signatures', () => craftSignature(prepend(input, instance), header({ i: '2' }), { rsa: rsaKey }), 'DKIM2-Signature i=1 missing'],
            [
                'an instance that no signature covers',
                () => prepend(craftSignature(prepend(input, instance), header(), { rsa: rsaKey }), instance.replace('m=1', 'm=2')),
                'Message-Instance m=2 is not signed'
            ],
            [
                'a signature for an instance that does not exist',
                () => craftSignature(prepend(input, instance), header({ m: '2' }), { rsa: rsaKey }),
                'Message-Instance m=2 missing'
            ],
            [
                'a repeated instance',
                () => craftSignature(prepend(input, instance, instance), header(), { rsa: rsaKey }),
                'Message-Instance m=1 appears more than once'
            ],
            [
                'a repeated signature',
                () => prepend(craftSignature(prepend(input, instance), header(), { rsa: rsaKey }), header({ s: `rsa:rsa-sha256:${H}` })),
                'DKIM2-Signature i=1 appears more than once'
            ],
            ['a broken signature', () => prepend(input, instance, header({ d: null })), 'DKIM2-Signature i=1 tag=d missing'],
            ['a broken instance', () => prepend(input, instance.replace(/h=/, 'x='), header()), 'Message-Instance m=1 tag=h missing'],
            [
                'an instance with only unknown hashes',
                () => craftSignature(prepend(input, instance.replace(/sha256/, 'sha3')), header(), { rsa: rsaKey }),
                'Message-Instance m=1 has no supported hash algorithm'
            ]
        ]) {
            it(`reports ${label}`, async () => {
                let result = await verify(build());
                expect(result.status.result).to.equal('permerror');
                expect(result.status.comment).to.equal(comment);
            });
        }

        it('fails a signature with only unknown signature algorithms (section 11.6)', async () => {
            let result = await verify(prepend(input, instance, header({ s: `rsa:rsa-sha3:${H},x:future-sig:${H}` })));
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('DKIM2-Signature i=1 has no supported signature algorithm');
            expect(result.signatures[0].values.map(entry => entry.result)).to.deep.equal(['none', 'none']);
        });

        it('ignores unknown hash and signature algorithms next to known ones (section 3.4)', async () => {
            let mixed = instance.replace(/;$/, `,sha3:${H}:${H};`);
            let crafted = craftSignature(prepend(input, mixed), header({ s: `rsa:rsa-sha256:,new:future-sig:${H}` }), { rsa: rsaKey });
            let result = await verify(crafted);
            expect(result.status.result).to.equal('pass');
            expect(result.signatures[0].values.map(entry => entry.result)).to.deep.equal(['pass', 'none']);
        });

        it('enforces a ceiling on the number of DKIM2 header fields', async () => {
            let crafted = craftSignature(prepend(input, instance), header(), { rsa: rsaKey });
            let result = await verify(crafted, { maxInstances: 0.5 });
            expect(result.status.result).to.equal('permerror');
            expect(result.status.comment).to.equal('Message has more than 0.5 Message-Instance or DKIM2-Signature header fields');

            let many = prepend(input, ...Array.from({ length: 21 }, (v, i) => instance.replace('m=1', `m=${i + 1}`)));
            expect((await verify(many)).status.comment).to.equal('Message has more than 20 Message-Instance or DKIM2-Signature header fields');
        });

        it('does not loop over huge instance numbers', async () => {
            let result = await verify(prepend(input, instance.replace('m=1', 'm=999999999999999'), header({ m: '999999999999999', s: `rsa:rsa-sha256:${H}` })));
            expect(result.status.comment).to.equal('Message-Instance m=1 missing');
        });
    });

    describe('timestamps (section 11.3)', () => {
        it('expires signatures after 14 days', async () => {
            let signed = await signMessage(message(), originatorOptions({ signTime: new Date('2026-09-01T00:00:00Z') }));

            let fresh = await verify(signed, { curTime: new Date('2026-09-14T00:00:00Z') });
            expect(fresh.status.result).to.equal('pass');

            let expired = await verify(signed, { curTime: new Date('2026-09-16T00:00:00Z') });
            expect(expired.status.result).to.equal('permerror');
            expect(expired.status.comment).to.equal('DKIM2-Signature i=1 signature expired');

            expect((await verify(signed, { curTime: new Date('2026-09-16T00:00:00Z'), maxSignatureAge: false })).status.result).to.equal('pass');
            expect((await verify(signed, { curTime: new Date('2026-09-03T00:00:00Z'), maxSignatureAge: 86400 })).status.result).to.equal('permerror');
        });
    });

    describe('public keys (section 11.5 and draft-ietf-dkim-dkim2-dns-00)', () => {
        const rsaOnly = originatorOptions({ signatureData: [{ selector: 'rsa', privateKey: rsaKey }] });
        const record = keyRecord(rsaKey);
        const errorFor = code => async () => {
            let err = new Error(code);
            err.code = code;
            throw err;
        };

        for (let [label, zone, result, comment] of [
            ['a missing key', { 'rsa._domainkey.example.com': { TXT: [] } }, 'permerror', 'public key rsa does not exist'],
            ['multiple records', { 'rsa._domainkey.example.com': { TXT: [[record], [record]] } }, 'permerror', 'public key rsa has multiple records'],
            ['a revoked key', { 'rsa._domainkey.example.com': { TXT: [['v=DKIM1; k=rsa; p=']] } }, 'permerror', 'public key rsa has been revoked'],
            ['a record without p=', { 'rsa._domainkey.example.com': { TXT: [['v=DKIM1; k=rsa']] } }, 'permerror', 'public key rsa has a syntax error'],
            [
                'an unknown version',
                { 'rsa._domainkey.example.com': { TXT: [[record.replace('DKIM1', 'DKIM2')]] } },
                'permerror',
                'public key rsa has a syntax error'
            ],
            [
                'v= that is not first',
                { 'rsa._domainkey.example.com': { TXT: [[record.replace('v=DKIM1; k=rsa', 'k=rsa; v=DKIM1')]] } },
                'permerror',
                'public key rsa has a syntax error'
            ],
            ['a duplicate tag', { 'rsa._domainkey.example.com': { TXT: [[record + '; k=rsa']] } }, 'permerror', 'public key rsa has a syntax error'],
            ['bad key data', { 'rsa._domainkey.example.com': { TXT: [['v=DKIM1; k=rsa; p=AAAA']] } }, 'permerror', 'public key rsa has a syntax error'],
            [
                'an ed25519 key for rsa-sha256',
                { 'rsa._domainkey.example.com': { TXT: [[keyRecord(ed25519Key)]] } },
                'permerror',
                'public key rsa algorithm mismatch'
            ],
            [
                'an unknown key type',
                { 'rsa._domainkey.example.com': { TXT: [[record.replace('k=rsa', 'k=dsa')]] } },
                'permerror',
                'public key rsa algorithm mismatch'
            ]
        ]) {
            it(`reports ${label}`, async () => {
                let signed = await signMessage(message(), rsaOnly);
                let verified = await dkim2Verify(signed, { resolver: resolver(zone) });
                expect(verified.status.result).to.equal(result);
                expect(verified.status.comment).to.equal(`DKIM2-Signature i=1 ${comment}`);
                expect(verified.signatures[0].values[0].comment).to.equal(comment);
            });
        }

        it('reports a DNS failure as TEMPERROR and NXDOMAIN as PERMERROR', async () => {
            let signed = await signMessage(message(), rsaOnly);
            for (let [code, result, comment] of [
                ['ETIMEOUT', 'temperror', 'could not be fetched'],
                ['ESERVFAIL', 'temperror', 'could not be fetched'],
                ['ENOTFOUND', 'permerror', 'does not exist'],
                ['ENODATA', 'permerror', 'does not exist']
            ]) {
                let verified = await dkim2Verify(signed, { resolver: errorFor(code) });
                expect(verified.status.result).to.equal(result);
                expect(verified.status.comment).to.equal(`DKIM2-Signature i=1 public key rsa ${comment}`);
            }
        });

        it('joins the strings of a TXT record and ignores the retired tags', async () => {
            let signed = await signMessage(message(), rsaOnly);
            let half = Math.floor(record.length / 2);
            let zone = { 'rsa._domainkey.example.com': { TXT: [[`${record.slice(0, half)}`, `${record.slice(half)}; h=sha1; s=other; n=note; t=s`]] } };
            expect((await dkim2Verify(signed, { resolver: resolver(zone) })).status.result).to.equal('pass');
        });

        it('passes on the key that works when another key is missing, and reports it', async () => {
            let signed = await signMessage(message(), originatorOptions());
            let verified = await dkim2Verify(signed, { resolver: resolver({ 'ed._domainkey.example.com': { TXT: [] } }) });
            expect(verified.status.result).to.equal('pass');
            expect(verified.signatures[0].values.map(entry => [entry.result, entry.comment])).to.deep.equal([
                ['pass', undefined],
                ['permerror', 'public key ed does not exist']
            ]);
        });

        it('prefers TEMPERROR over PERMERROR when no key could be used, and FAIL over both', async () => {
            let signed = await signMessage(message(), originatorOptions());
            let verified = await dkim2Verify(signed, {
                resolver: async name => {
                    let err = new Error('x');
                    err.code = name.startsWith('rsa.') ? 'ENOTFOUND' : 'ETIMEOUT';
                    throw err;
                }
            });
            expect(verified.status.result).to.equal('temperror');
            expect(verified.status.comment).to.equal('DKIM2-Signature i=1 public key ed could not be fetched');

            let expired = await dkim2Verify(Buffer.from(signed.toString().replace('Hello world', 'Hello there')), {
                resolver: async () => {
                    let err = new Error('x');
                    err.code = 'ETIMEOUT';
                    throw err;
                }
            });
            expect(expired.status.result).to.equal('fail');
        });

        it('reports the t=y testing flag', async () => {
            let signed = await signMessage(message(), rsaOnly);
            let verified = await dkim2Verify(signed, { resolver: resolver({ 'rsa._domainkey.example.com': { TXT: [[keyRecord(rsaKey, 't=y')]] } }) });
            expect(verified.status.result).to.equal('pass');
            expect(verified.signatures[0].values[0].testing).to.be.true;
        });

        it('rejects short RSA keys and other exponents', async () => {
            let short = crypto.generateKeyPairSync('rsa', { modulusLength: 768 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
            let exponent3 = crypto.generateKeyPairSync('rsa', { modulusLength: 1024, publicExponent: 3 }).privateKey.export({ type: 'pkcs8', format: 'pem' });

            for (let [key, code] of [
                [short, 'ESHORTKEY'],
                [exponent3, 'EINVALIDKEY']
            ]) {
                let err = await dkim2Sign(message(), originatorOptions({ signatureData: [{ selector: 'rsa', privateKey: key }] })).catch(err => err);
                expect(err.code).to.equal(code);
            }

            let input = message();
            for (let [key, comment] of [
                [short, 'is too short'],
                [exponent3, 'has an unsupported exponent']
            ]) {
                let crafted = craftSignature(prepend(input, instanceOf(input)), header(), { rsa: key });
                let verified = await dkim2Verify(crafted, { resolver: resolver({ 'rsa._domainkey.example.com': { TXT: [[keyRecord(key)]] } }) });
                expect(verified.status.comment).to.equal(`DKIM2-Signature i=1 public key rsa ${comment}`);
            }
        });

        it('looks up every key record once', async () => {
            let signed = await signMessage(message(), originatorToSelf());
            let zone = resolver();
            await dkim2Verify(await signMessage(signed, originatorOptions({ mailFrom: 'rcpt@example.com', rcptTo: 'x@example.org' })), { resolver: zone });
            expect(zone.calls.filter(call => call.name === 'rsa._domainkey.example.com')).to.have.length(1);
        });
    });

    describe('signing options', () => {
        for (let [label, options, code] of [
            ['a missing domain', { signingDomain: '' }, 'EINVALIDDOMAIN'],
            ['no keys', { signatureData: [] }, 'ENOKEY'],
            ['an invalid selector', { signatureData: [{ selector: 'a b', privateKey: rsaKey }] }, 'EINVALIDSELECTOR'],
            [
                'a repeated selector',
                {
                    signatureData: [
                        { selector: 'rsa', privateKey: rsaKey },
                        { selector: 'RSA', privateKey: rsaKey }
                    ]
                },
                'EINVALIDSELECTOR'
            ],
            ['three keys of one algorithm', { signatureData: ['a', 'b', 'c'].map(selector => ({ selector, privateKey: rsaKey })) }, 'EINVALIDALGO'],
            [
                'an algorithm that does not fit the key',
                { signatureData: [{ selector: 'rsa', privateKey: rsaKey, algorithm: 'ed25519-sha256' }] },
                'EINVALIDALGO'
            ],
            ['no envelope', { mailFrom: undefined }, 'EINVALIDOPTS'],
            ['no recipients', { rcptTo: [] }, 'EINVALIDOPTS'],
            ['an empty recipient', { rcptTo: [''] }, 'EINVALIDPATH'],
            ['a broken path', { mailFrom: '<a@example.com' }, 'EINVALIDPATH'],
            ['a long nonce', { nonce: 'x'.repeat(65) }, 'EINVALIDOPTS'],
            ['a bad flag', { flags: ['do not'] }, 'EINVALIDOPTS'],
            ['an unknown hash algorithm', { hashAlgorithms: ['sha1'] }, 'EINVALIDALGO'],
            ['an invalid recipe', { recipe: { x: 1 } }, 'EINVALIDRECIPE'],
            ['an invalid next domain', { mailFrom: undefined, rcptTo: undefined, nextDomain: 'not a domain' }, 'EINVALIDDOMAIN']
        ]) {
            it(`throws for ${label}`, async () => {
                let err = await dkim2Sign(message(), originatorOptions(options)).catch(err => err);
                expect(err).to.be.an('error');
                expect(err.code).to.equal(code);
            });
        }

        it('refuses to sign over an invalid DKIM2 chain', async () => {
            for (let input of [prepend(message(), 'Message-Instance: m=2; h=sha256:AAAA:AAAA;'), prepend(message(), 'DKIM2-Signature: broken')]) {
                let err = await dkim2Sign(input, originatorOptions()).catch(err => err);
                expect(err.code).to.equal('EINVALIDCHAIN');
            }
        });

        it('writes the nonce and the flags', async () => {
            let result = await dkim2Sign(message(), originatorOptions({ nonce: 'id-42', flags: ['feedback', 'donotmodify'] }));
            let parsed = parseSignature(result.signature);
            expect(parsed.nonce).to.equal('id-42');
            expect(parsed.flags).to.deep.equal(['feedback', 'donotmodify']);
        });
    });
});

// example.com sending to an example.com address, so that example.com can sign the next hop too
function originatorToSelf() {
    return originatorOptions({ rcptTo: 'rcpt@example.com' });
}
