/* eslint @typescript-eslint/no-unused-expressions:0 */
import { describe, it } from 'node:test';
import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { expect, config } from 'chai';

import { dkim2Sign } from '../../src/dkim2/sign.js';
import { dkim2Verify } from '../../src/dkim2/verify.js';
import { parseMessageInstance, parseSignature, canonicalSignatureField, formatSignature, formatMessageInstance } from '../../src/dkim2/fields.js';
import { custodyProblem } from '../../src/dkim2/domains.js';
import { parseRecipe } from '../../src/dkim2/recipe.js';
import { rsaKeyProblem } from '../../src/dkim2/key.js';
import { rsaKey, ed25519Key, keyRecord, resolver, message, originatorOptions, signMessage, craftSignature, b64 } from '../helpers/dkim2.js';
import * as reference from '../helpers/dkim2-reference.js';

config.includeStack = true;

const verify = (input: any, options?: any) => dkim2Verify(input, Object.assign({ resolver: resolver() }, options || {}));

const H = 'AAAA';
const sig = (tags: any) => `DKIM2-Signature: ${tags}`;
const validTags = `i=1; m=1; t=1; d=example.com; mf=${b64('<a@example.com>')}; rt=${b64('<b@example.net>')}; s=rsa:rsa-sha256:${H};`;

// the Message-Instance of the plain test message
const instanceOf = (input: any) => {
    let { fields, body } = reference.splitMessage(Buffer.from(input).toString('binary'));
    return `Message-Instance: m=1; h=sha256:${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')};`;
};

const header = (tags?: any) => {
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

const prepend = (input: any, ...lines: any[]) => Buffer.concat([Buffer.from(lines.join('\r\n') + '\r\n'), Buffer.from(input)]);

describe('DKIM2 validation', () => {
    describe('Message-Instance syntax (sections 8, 9 and 14.2)', () => {
        it('parses the tags in any order, ignoring unknown tags', () => {
            let parsed = parseMessageInstance(`Message-Instance: X=unknown value; h = sha256 :${H}:A\r\n AAA , foo:${H}:${H} ; m = 3`);
            expect(parsed.error).to.equal(null);
            expect(parsed.m).to.equal(3);
            expect(parsed.hashes).to.deep.equal([
                { algorithm: 'sha256', headerHash: H, bodyHash: H, group: 0 },
                { algorithm: 'foo', headerHash: H, bodyHash: H, group: 0 }
            ]);
        });

        it('reads "," groups separated by "|" (section 9.3)', () => {
            let parsed = parseMessageInstance(`Message-Instance: m=1; h=sha256:${H}:${H}, foo:${H}:${H} |\r\n sha512:${H}:${H}|bar:${H}:${H}`);
            expect(parsed.error).to.equal(null);
            expect(parsed.hashes.map(hash => [hash.algorithm, hash.group])).to.deep.equal([
                ['sha256', 0],
                ['foo', 0],
                ['sha512', 1],
                ['bar', 2]
            ]);
        });

        it('treats tag names and algorithm names as case-sensitive (sections 2.14 and 8)', () => {
            // "M=" and "H=" are unknown tags, not m= and h=
            expect(parseMessageInstance(`Message-Instance: M=1; h=sha256:${H}:${H}`).error).to.equal('tag=m missing');
            expect(parseMessageInstance(`Message-Instance: m=1; H=sha256:${H}:${H}`).error).to.equal('tag=h missing');
            // "SHA256" is an algorithm of its own, not a second sha256
            let parsed = parseMessageInstance(`Message-Instance: m=1; h=sha256:${H}:${H},SHA256:${H}:${H}`);
            expect(parsed.error).to.equal(null);
            expect(parsed.hashes.map(hash => hash.algorithm)).to.deep.equal(['sha256', 'SHA256']);
        });

        for (let [value, error] of [
            [`h=sha256:${H}:${H};`, 'tag=m missing'],
            ['m=1;', 'tag=h missing'],
            [`m=0; h=sha256:${H}:${H};`, 'syntax error'],
            [`m=x; h=sha256:${H}:${H};`, 'syntax error'],
            [`m=1; m=2; h=sha256:${H}:${H};`, 'syntax error'],
            [`m=1; h=sha256:${H};`, 'syntax error'],
            [`m=1; h=sha256:AAA:${H};`, 'syntax error'],
            [`m=1; h=sha256:${H}:${H},sha256:${H}:${H};`, 'has a duplicate hash algorithm'],
            // section 9.3: once in the whole field, in any group
            [`m=1; h=sha256:${H}:${H}|sha256:${H}:${H};`, 'has a duplicate hash algorithm'],
            // section 2.14: no FWS at the start or the end of a base64string
            [`m=1; h=sha256: ${H}:${H};`, 'syntax error'],
            [`m=1; h=sha256:${H} :${H};`, 'syntax error'],
            [`m=1; h=sha256:${H}: ${H};`, 'syntax error'],
            [`m=1; h=sha256:${H}:${H},;`, 'syntax error'],
            [`m=1; h=sha256:${H}:${H}||sha512:${H}:${H};`, 'syntax error'],
            [`m=1; h=|sha256:${H}:${H};`, 'syntax error'],
            [`m=1; h=sha 256:${H}:${H};`, 'syntax error'],
            [`m=1; h=sha256:${H}:${H}; r=!!!!;`, 'syntax error'],
            [`m=1; h=sha256:${H}:${H}; r= ${b64('{"b":null}')} x;`, 'syntax error'],
            [`m=1; h=sha256:${H}:${H}; r=${b64('{not json')};`, 'contains invalid JSON'],
            [`m=1; h=sha256:${H}:${H}; r=${b64('{}')};`, 'recipe {} is invalid'],
            [`m=1; h=sha256:${H}:${H};; x=1`, 'syntax error'],
            [`m=1; novalue; h=sha256:${H}:${H}`, 'syntax error']
        ]) {
            it(`reports "${error}" for ${value}`, () => {
                expect(parseMessageInstance(`Message-Instance: ${value}`).error).to.equal(error);
            });
        }
    });

    describe('DKIM2-Signature syntax (sections 8, 10 and 14.2)', () => {
        it('parses every tag', () => {
            let parsed = parseSignature(
                sig(
                    `i=2; m=1; t=1000000000000; d=Example.COM; mf=${b64('<>')}; rt=${b64('<b@example.net>')},${b64('<c@example.org>')}; n=abc:123; f=exploded , future-flag; s=sel.one :rsa-sha256:${H},sel2:ed25519-sha256:${H}|x:new-algo:${H};`
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
            expect(parsed.signatures.map(entry => [entry.selector, entry.algorithm, entry.group])).to.deep.equal([
                ['sel.one', 'rsa-sha256', 0],
                ['sel2', 'ed25519-sha256', 0],
                ['x', 'new-algo', 1]
            ]);
        });

        it('allows FWS around the separators of s= and inside, but not around, a base64string (sections 2.14 and 10.9)', () => {
            let parsed = parseSignature(sig(validTags.replace(/s=.*$/, `s= a \r\n : rsa-sha256 :AA\r\n AA ,\r\n b:ed25519-sha256:${H} | c:mldsa44:${H} ;`)));
            expect(parsed.error).to.equal(null);
            expect(parsed.signatures).to.deep.equal([
                { selector: 'a', algorithm: 'rsa-sha256', signature: H, group: 0 },
                { selector: 'b', algorithm: 'ed25519-sha256', signature: H, group: 0 },
                { selector: 'c', algorithm: 'mldsa44', signature: H, group: 1 }
            ]);
        });

        it('allows several signatures with one algorithm, each with its own selector (section 10.9)', () => {
            let parsed = parseSignature(sig(validTags.replace(/s=.*$/, `s=a:rsa-sha256:${H},b:rsa-sha256:${H},c:rsa-sha256:${H};`)));
            expect(parsed.error).to.equal(null);
            expect(parsed.signatures).to.have.length(3);
        });

        it('treats tag names as case-sensitive (section 8)', () => {
            expect(parseSignature(sig(validTags.replace('i=1', 'I=1'))).error).to.equal('tag=i missing');
            // an unknown tag that only differs in case is not a duplicate
            expect(parseSignature(sig(`D=other.example; ${validTags}`)).error).to.equal(null);
        });

        it('reports the exploded flag on the first signature (section 12.5)', () => {
            expect(parseSignature(sig(`f=feedback,exploded; ${validTags}`)).error).to.equal('has an exploded flag');
            expect(parseSignature(sig(`f=Exploded; ${validTags}`)).error).to.equal(null);
            expect(parseSignature(sig(`f=exploded; ${validTags.replace('i=1', 'i=2')}`)).error).to.equal(null);
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
            // section 10.6: no FWS around the commas of rt=, nor at the edges of a base64string
            [validTags.replace(/rt=[^;]+/, `rt=${b64('<b@example.net>')}, ${b64('<c@example.net>')}`), 'syntax error'],
            [validTags.replace(/rt=[^;]+/, `rt=${b64('<b@example.net>')} ,${b64('<c@example.net>')}`), 'syntax error'],
            [validTags.replace(/rt=[^;]+/, `rt=${b64('<b@example.net>')},`), 'syntax error'],
            [validTags.replace(/s=.*$/, `s=rsa:rsa-sha256: ${H};`), 'syntax error'],
            [validTags.replace(/s=.*$/, `s=rsa:rsa-sha256:${H}|;`), 'syntax error'],
            [validTags.replace(/s=.*$/, `s=rsa:rsa-sha256:${H},,b:rsa-sha256:${H};`), 'syntax error'],
            [validTags.replace(/s=.*$/, `s=r sa:rsa-sha256:${H};`), 'syntax error'],
            [validTags.replace(/s=.*$/, `s=rsa:rsa-sha256:${H}|RSA:mldsa44:${H};`), 'has a duplicate selector'],
            [`n=${'x'.repeat(65)}; ${validTags}`, 'syntax error'],
            [`n=has space; ${validTags}`, 'syntax error'],
            [`f=bad flag; ${validTags}`, 'syntax error'],
            [validTags.replace(/s=.*$/, `s=rsa:rsa-sha256:${H},RSA:ed25519-sha256:${H};`), 'has a duplicate selector'],
            [validTags.replace(/s=.*$/, `s=a:rsa-sha256;`), 'syntax error']
        ]) {
            it(`reports "${error}" for ${value.slice(0, 60)}`, () => {
                expect(parseSignature(sig(value)).error).to.equal(error);
            });
        }
    });

    describe('signature input (section 12.8)', () => {
        it('removes all whitespace, lowercases the name and empties the signature values', () => {
            let line = Buffer.from(
                `DKIM2-Signature :  i=1; m=1;\r\n\ts = a : rsa-sha256 : AB\r\n CD== , b:ed25519-sha256:EF== | c:mldsa44:GH==; x=s=1; S=a:b:c`
            );
            expect(canonicalSignatureField(line, true).toString()).to.equal(
                'dkim2-signature:i=1;m=1;s=a:rsa-sha256:,b:ed25519-sha256:|c:mldsa44:;x=s=1;S=a:b:c\r\n'
            );
            expect(canonicalSignatureField(line).toString()).to.equal(
                'dkim2-signature:i=1;m=1;s=a:rsa-sha256:ABCD==,b:ed25519-sha256:EF==|c:mldsa44:GH==;x=s=1;S=a:b:c\r\n'
            );
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
                flags: ['feedhere', 'feedback'],
                signatures: [
                    { selector: 'selector-one', algorithm: 'rsa-sha256', signature: crypto.randomBytes(256).toString('base64'), group: 0 },
                    { selector: 'selector-two', algorithm: 'ed25519-sha256', signature: crypto.randomBytes(64).toString('base64'), group: 0 },
                    { selector: 'selector-three', algorithm: 'mldsa44', signature: crypto.randomBytes(2420).toString('base64'), group: 1 }
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
            expect(parsedInstance.recipe!.h.get('subject')).to.deep.equal([{ lines: ['x'.repeat(200)], source: { d: ['x'.repeat(200)] } }]);
        });
    });

    describe('chain of custody between hops (section 7.1 item 1)', () => {
        const previous: any = { rcptTo: ['<list@Example.com>', '<other@example.org>'] };

        it('matches a mf= domain (Parameter1) with a previous rt= domain (Parameter2)', () => {
            expect(custodyProblem(previous, { mailFrom: '<bounce@bounces.mail.example.com>', signingDomain: 'x.example' })).to.equal(null);
            expect(custodyProblem(previous, { mailFrom: '<a@example.org>', signingDomain: 'x.example' })).to.equal(null);
            expect(custodyProblem(previous, { mailFrom: '<a@notexample.com>', signingDomain: 'x.example' })).to.equal('mf');
            // a parent of the recipient domain is not a match
            expect(custodyProblem({ rcptTo: ['<list@mail.example.com>'] }, { mailFrom: '<a@example.com>', signingDomain: 'x.example' })).to.equal('mf');
        });

        it('matches a previous rt= domain (Parameter1) with d= (Parameter2) for the null mf= and for nd=', () => {
            for (let mailFrom of ['<>', undefined]) {
                // the recipient domain is d= or a subdomain of it
                expect(custodyProblem(previous, { mailFrom, signingDomain: 'example.org' })).to.equal(null);
                expect(custodyProblem({ rcptTo: ['<list@lists.example.com>'] }, { mailFrom, signingDomain: 'example.com' })).to.equal(null);
                // d= may not be a subdomain of the recipient domain, nor an unrelated domain
                expect(custodyProblem(previous, { mailFrom, signingDomain: 'mail.example.org' })).to.equal('d');
                expect(custodyProblem(previous, { mailFrom, signingDomain: 'example.net' })).to.equal('d');
            }
        });

        it('never matches a domain literal (section 7.2 step 2)', () => {
            expect(custodyProblem({ rcptTo: ['<a@[192.0.2.1]>'] }, { mailFrom: '<b@[192.0.2.1]>', signingDomain: 'example.com' })).to.equal('mf');
            expect(custodyProblem({ rcptTo: ['<a@[192.0.2.1]>'] }, { mailFrom: '<>', signingDomain: 'example.com' })).to.equal('d');
        });

        it('has nothing to match without a previous hop, or after an nd= hop', () => {
            expect(custodyProblem(undefined, { mailFrom: '<a@example.net>', signingDomain: 'example.net' })).to.equal(null);
            expect(custodyProblem({ nextDomain: 'example.net' }, { mailFrom: '<a@example.org>', signingDomain: 'example.org' })).to.equal(null);
        });
    });

    describe('Recipe JSON (section 5)', () => {
        for (let [json, error] of [
            ['{not json', 'contains invalid JSON'],
            ['', 'contains invalid JSON'],
            ['[]', 'contains invalid JSON: not a JSON object'],
            ['null', 'contains invalid JSON: not a JSON object'],
            // section 5: the keys are unique within every object, JSON.parse() would keep the last one
            ['{"b":null,"b":[{"c":[1,1]}]}', 'contains invalid JSON: duplicate key "b"'],
            ['{"h":{"subject":[],"subject":[{"c":[1,1]}]}}', 'contains invalid JSON: duplicate key "subject"'],
            ['{"h":{"subject":[{"c":[1,1],"c":[2,2]}]}}', 'contains invalid JSON: duplicate key "c"'],
            ['{"h":{"subject":[],"\\u0073ubject":[]}}', 'contains invalid JSON: duplicate key "subject"'],
            // and in lower case
            ['{"H":{"subject":[]}}', 'recipe "H" is invalid'],
            ['{"h":{"Subject":[]}}', 'recipe "Subject" is invalid'],
            ['{"b":[{"C":[1,1]}]}', 'recipe "C" is invalid'],
            ['{}', 'recipe {} is invalid'],
            ['{"x":1}', 'recipe {"x":1} is invalid'],
            ['{"h":{}}', 'recipe {"h":{}} is invalid'],
            ['{"h":[]}', 'recipe {"h":[]} is invalid'],
            ['{"h":{"sub ject":[]}}', 'recipe "sub ject" is invalid'],
            ['{"h":{"subject":{}}}', 'recipe {} is invalid'],
            ['{"b":"x"}', 'recipe "x" is invalid'],
            ['{"b":[{"c":[1]}]}', 'recipe {"c":[1]} is invalid'],
            ['{"b":[{"c":[0,1]}]}', 'recipe {"c":[0,1]} is invalid'],
            ['{"b":[{"c":[1.5,2]}]}', 'recipe {"c":[1.5,2]} is invalid'],
            ['{"b":[{"c":["1",2]}]}', 'recipe {"c":["1",2]} is invalid'],
            ['{"b":[{"c":[2,1]}]}', 'recipe {"c":[2,1]} is invalid'],
            ['{"b":[{"c":[1,2]},{"c":[2,3]}]}', 'recipe {"c":[2,3]} is invalid'],
            ['{"b":[{"c":[3,4]},{"d":["x"]},{"c":[1,2]}]}', 'recipe {"c":[1,2]} is invalid'],
            // section 5: exactly one key per step, and no other keys
            ['{"b":[{"c":[1,2],"d":["x"]}]}', 'recipe {"c":[1,2],"d":["x"]} is invalid'],
            ['{"b":[{"c":[1,1],"note":"x"}]}', 'recipe {"c":[1,1],"note":"x"} is invalid'],
            ['{"b":[{}]}', 'recipe {} is invalid'],
            ['{"b":[{"x":["a"]}]}', 'recipe {"x":["a"]} is invalid'],
            ['{"b":[["c",1]]}', 'recipe ["c",1] is invalid'],
            ['{"b":[{"d":[]}]}', 'recipe {"d":[]} is invalid'],
            ['{"b":[{"d":"x"}]}', 'recipe {"d":"x"} is invalid'],
            ['{"b":[{"d":["a\\r\\nb"]}]}', 'recipe {"d":["a\\r\\nb"]} is invalid'],
            ['{"b":[{"d":["a\\nb"]}]}', 'recipe {"d":["a\\nb"]} is invalid'],
            ['{"b":[{"d":[1]}]}', 'recipe {"d":[1]} is invalid'],
            // a lone surrogate is not UTF-8
            ['{"b":[{"d":["\\ud800"]}]}', `recipe ${JSON.stringify({ d: ['\ud800'] })} is invalid`],
            // "u" values are canonical base64 that does not decode to CR or LF
            ['{"b":[{"u":[]}]}', 'recipe {"u":[]} is invalid'],
            ['{"b":[{"u":["/w"]}]}', 'recipe {"u":["/w"]} is invalid'],
            ['{"b":[{"u":["/x=="]}]}', 'recipe {"u":["/x=="]} is invalid'],
            ['{"b":[{"u":["/w= ="]}]}', 'recipe {"u":["/w= ="]} is invalid'],
            ['{"b":[{"u":["/w==="]}]}', 'recipe {"u":["/w==="]} is invalid'],
            ['{"b":[{"u":["/w-="]}]}', 'recipe {"u":["/w-="]} is invalid'],
            [`{"b":[{"u":["${b64('a\r')}"]}]}`, `recipe {"u":["${b64('a\r')}"]} is invalid`],
            [`{"b":[{"u":["${b64('\n')}"]}]}`, `recipe {"u":["${b64('\n')}"]} is invalid`]
        ]) {
            it(`rejects ${json}`, () => {
                expect(parseRecipe(json).error).to.equal(error);
            });
        }

        it('rejects JSON that is not UTF-8, or starts with a byte order mark', () => {
            expect(parseRecipe(Buffer.from([0x7b, 0x22, 0x62, 0x22, 0x3a, 0xff, 0x7d])).error).to.equal('contains invalid JSON');
            expect(parseRecipe(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"b":null}')])).error).to.equal('contains invalid JSON');
            expect(parseRecipe(Buffer.from('{"b":null}')).error).to.equal(undefined);
        });

        it('quotes at most 100 characters of the invalid part', () => {
            let error = parseRecipe(JSON.stringify({ b: [{ d: ['x'.repeat(500)], z: 1 }] })).error!;
            expect(error).to.equal(`recipe ${JSON.stringify({ d: ['x'.repeat(500)], z: 1 }).slice(0, 100)}... is invalid`);
        });

        it('reads "d" and "u" steps into the bytes of their lines', () => {
            let parsed = parseRecipe(JSON.stringify({ b: [{ d: ['', 'hé'] }, { u: ['', '/w==', 'gA=='] }, { c: [1, 2] }] }));
            expect(parsed.error).to.equal(undefined);
            expect(parsed.value!.b!.map(step => step.lines || step.c)).to.deep.equal([
                ['', 'hÃ©'],
                ['', 'ÿ', '\u0080'],
                [1, 2]
            ]);
        });

        it('ignores unknown top-level fields, and does not pollute prototypes', () => {
            let parsed = parseRecipe('{"h":{"subject":[{"c":[1,1]}]},"b":null,"z":1,"__proto__":{"polluted":true}}');
            expect(parsed.error).to.equal(undefined);
            expect(parsed.value!.b).to.equal(null);
            expect(({} as any).polluted).to.equal(undefined);
        });

        it('treats strings that look like JSON structure as strings', () => {
            let parsed = parseRecipe('{"h":{"subject":[{"d":["{\\"b\\":1,\\"b\\":2}","\\"","\\\\"]}]}}');
            expect(parsed.error).to.equal(undefined);
            expect(parsed.value!.h.get('subject')![0].lines).to.deep.equal(['{"b":1,"b":2}', '"', '\\']);
        });

        it('reports a Recipe for a header field that is not signed (section 5.1)', () => {
            for (let name of ['received', 'x-mailer', 'received-spf', 'authentication-results', 'dkim2-signature', 'message-instance']) {
                let instance = `Message-Instance: m=2; h=sha256:${H}:${H}; r=${b64(JSON.stringify({ h: { [name]: [] } }))}`;
                expect(parseMessageInstance(instance).error).to.equal(`recipe ${JSON.stringify(name)} is invalid`);
            }
        });

        it('reports a "c" range past the end of the message as an invalid Recipe', async () => {
            let input = message();
            let instance1 = instanceOf(input);
            let instance2 = `Message-Instance: m=2; h=sha256:${H}:${H}; r=${b64('{"b":[{"c":[1,99]}]}')};`;
            let crafted = craftSignature(prepend(input, instance2, instance1), header({ m: '2' }), { rsa: rsaKey });
            let result = await verify(crafted);
            expect(result.status.result).to.equal('permerror');
            expect(result.status.comment).to.equal('Message-Instance m=2 recipe {"c":[1,99]} is invalid');
            expect(result.status.header!.i).to.equal(1);
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
            ['a repeated instance', () => craftSignature(prepend(input, instance, instance), header(), { rsa: rsaKey }), 'Message-Instance m=1 is duplicated'],
            [
                'a repeated signature',
                () => prepend(craftSignature(prepend(input, instance), header(), { rsa: rsaKey }), header({ s: `rsa:rsa-sha256:${H}` })),
                'DKIM2-Signature i=1 is duplicated'
            ],
            ['a broken signature', () => prepend(input, instance, header({ d: null })), 'DKIM2-Signature i=1 tag=d missing'],
            ['a broken instance', () => prepend(input, instance.replace(/h=/, 'x='), header()), 'Message-Instance m=1 tag=h missing'],
            [
                'an instance with only unknown hashes',
                () => craftSignature(prepend(input, instance.replace(/sha256/, 'sha3')), header(), { rsa: rsaKey }),
                'Message-Instance m=1 algorithm sha3 unknown'
            ]
        ] as any[][]) {
            it(`reports ${label}`, async () => {
                let result = await verify(build());
                expect(result.status.result).to.equal('permerror');
                expect(result.status.comment).to.equal(comment);
            });
        }

        it('reports a signature with only unknown signature algorithms as a PERMERROR (section 14.6 step 4)', async () => {
            let result = await verify(prepend(input, instance, header({ s: `rsa:rsa-sha3:${H},x:future-sig:${H}` })));
            expect(result.status.result).to.equal('permerror');
            expect(result.status.comment).to.equal('DKIM2-Signature i=1 selector rsa algorithm unknown');
            expect(result.signatures[0].values.map((entry: any) => [entry.result, entry.comment])).to.deep.equal([
                ['permerror', 'selector rsa algorithm unknown'],
                ['permerror', 'selector x algorithm unknown']
            ]);
            // algorithm names are case-sensitive
            let upper = await verify(prepend(input, instance, header({ s: `rsa:RSA-SHA256:${H}` })));
            expect(upper.status.comment).to.equal('DKIM2-Signature i=1 selector rsa algorithm unknown');
        });

        it('requires every hash and signature of a "," group, unknown algorithms included (sections 14.6 and 14.7)', async () => {
            let mixed = instance.replace(/;$/, `,sha3:${H}:${H};`);
            let crafted = craftSignature(prepend(input, mixed), header({ s: `rsa:rsa-sha256:,new:future-sig:${H}` }), { rsa: rsaKey });
            let result = await verify(crafted);
            expect(result.status.result).to.equal('permerror');
            expect(result.errors.map((error: any) => error.message)).to.deep.equal([
                'Message-Instance m=1 algorithm sha3 unknown',
                'DKIM2-Signature i=1 selector new algorithm unknown'
            ]);
            expect(result.signatures[0].values.map((entry: any) => entry.result)).to.deep.equal(['pass', 'permerror']);
            expect(result.instances[0].hashes).to.deep.equal([{ algorithm: 'sha256', header: 'pass', body: 'pass', group: 1 }]);
        });

        it('passes with one passing "|" group next to groups with unknown algorithms (sections 14.6 and 14.7)', async () => {
            let mixed = instance.replace(/h=/, `h=sha3:${H}:${H}|`);
            let crafted = craftSignature(prepend(input, mixed), header({ s: `new:future-sig:${H}|rsa:rsa-sha256:` }), { rsa: rsaKey });
            let result = await verify(crafted);
            expect(result.status.result).to.equal('pass');
            expect(result.errors).to.deep.equal([]);
            expect(result.signatures[0].values.map((entry: any) => [entry.selector, entry.group, entry.result])).to.deep.equal([
                ['new', 1, 'permerror'],
                ['rsa', 2, 'pass']
            ]);
            expect(result.instances[0].hashes).to.deep.equal([{ algorithm: 'sha256', header: 'pass', body: 'pass', group: 2 }]);
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

    describe('timestamps (section 14.3)', () => {
        it('fails a timestamp more than one day, or maxFutureTime, in the future', async () => {
            let signed = await signMessage(message(), originatorOptions({ signTime: new Date('2026-09-02T00:10:00Z') }));
            let curTime = new Date('2026-09-02T00:00:00Z');

            expect((await verify(signed, { curTime: new Date('2026-09-01T00:10:00Z') })).status.result).to.equal('pass');
            let defaultLimit = await verify(signed, { curTime: new Date('2026-09-01T00:09:59Z') });
            expect(defaultLimit.status.result).to.equal('fail');
            expect(defaultLimit.status.comment).to.equal('DKIM2-Signature i=1 signature is from the future');
            expect((await verify(signed, { curTime: new Date('2026-08-01T00:00:00Z'), maxFutureTime: false })).status.result).to.equal('pass');
            expect((await verify(signed, { curTime, maxFutureTime: 600 })).status.result).to.equal('pass');
            expect((await verify(signed, { curTime, maxFutureTime: 0 })).status.result).to.equal('fail');

            let future = await verify(signed, { curTime, maxFutureTime: 599 });
            expect(future.status.result).to.equal('fail');
            expect(future.status.comment).to.equal('DKIM2-Signature i=1 signature is from the future');
        });

        it('expires signatures after 14 days', async () => {
            let signed = await signMessage(message(), originatorOptions({ signTime: new Date('2026-09-01T00:00:00Z') }));

            let fresh = await verify(signed, { curTime: new Date('2026-09-14T00:00:00Z') });
            expect(fresh.status.result).to.equal('pass');

            let expired = await verify(signed, { curTime: new Date('2026-09-16T00:00:00Z') });
            expect(expired.status.result).to.equal('fail');
            expect(expired.status.comment).to.equal('DKIM2-Signature i=1 signature expired');

            expect((await verify(signed, { curTime: new Date('2026-09-16T00:00:00Z'), maxSignatureAge: false })).status.result).to.equal('pass');
            expect((await verify(signed, { curTime: new Date('2026-09-03T00:00:00Z'), maxSignatureAge: 86400 })).status.result).to.equal('fail');
        });
    });

    describe('public keys (sections 3.7 and 14.5, draft-ietf-dkim-dkim2-dns-02)', () => {
        const rsaOnly = originatorOptions({ signatureData: [{ selector: 'rsa', privateKey: rsaKey }] });
        const record = keyRecord(rsaKey);
        const errorFor = (code: any) => async () => {
            let err: any = new Error(code);
            err.code = code;
            throw err;
        };

        for (let [label, zone, result, comment] of [
            ['a missing key', { 'rsa._domainkey.example.com': { TXT: [] } }, 'permerror', 'public key rsa does not exist'],
            ['multiple records', { 'rsa._domainkey.example.com': { TXT: [[record], [record]] } }, 'permerror', 'public key rsa has multiple records'],
            [
                'multiple records, one without v=',
                { 'rsa._domainkey.example.com': { TXT: [[record], [record.replace('v=DKIM1; ', '')]] } },
                'permerror',
                'public key rsa has multiple records'
            ],
            [
                'only records with another version',
                { 'rsa._domainkey.example.com': { TXT: [[record.replace('DKIM1', 'DKIM2')], ['v=spf1 -all']] } },
                'permerror',
                'public key rsa does not exist'
            ],
            ['a revoked key', { 'rsa._domainkey.example.com': { TXT: [['v=DKIM1; k=rsa; p=']] } }, 'permerror', 'public key rsa has been revoked'],
            ['a record without p=', { 'rsa._domainkey.example.com': { TXT: [['v=DKIM1; k=rsa']] } }, 'permerror', 'public key rsa has a syntax error'],
            [
                'an unknown version',
                { 'rsa._domainkey.example.com': { TXT: [[record.replace('DKIM1', 'DKIM2')]] } },
                'permerror',
                'public key rsa does not exist'
            ],
            [
                'a v= in another case',
                { 'rsa._domainkey.example.com': { TXT: [[record.replace('v=DKIM1', 'v=dkim1')]] } },
                'permerror',
                'public key rsa does not exist'
            ],
            [
                'v= that is not first',
                { 'rsa._domainkey.example.com': { TXT: [[record.replace('v=DKIM1; k=rsa', 'k=rsa; v=DKIM1')]] } },
                'permerror',
                'public key rsa has a syntax error'
            ],
            ['a duplicate tag', { 'rsa._domainkey.example.com': { TXT: [[record + '; k=rsa']] } }, 'permerror', 'public key rsa has a syntax error'],
            ['bad key data', { 'rsa._domainkey.example.com': { TXT: [['v=DKIM1; k=rsa; p=AAAA']] } }, 'permerror', 'public key rsa is malformed'],
            [
                'p= that is not base64',
                { 'rsa._domainkey.example.com': { TXT: [['v=DKIM1; k=rsa; p=A!A=']] } },
                'permerror',
                'public key rsa has a syntax error'
            ],
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
                let verified = await dkim2Verify(signed, { resolver: resolver(zone as any) });
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
            expect((await dkim2Verify(signed, { resolver: resolver(zone as any) })).status.result).to.equal('pass');
        });

        it('ignores records that begin with another v= before counting them (section 3.7)', async () => {
            let signed = await signMessage(message(), rsaOnly);
            let zone = { 'rsa._domainkey.example.com': { TXT: [['v=spf1 -all'], [record], [' v = DKIM2; p=AAAA']] } };
            expect((await dkim2Verify(signed, { resolver: resolver(zone as any) })).status.result).to.equal('pass');
            // a record with v= after other tags is not dropped, and is a syntax error
            let late = { 'rsa._domainkey.example.com': { TXT: [['k=rsa; v=DKIM2; p=AAAA'], [record]] } };
            expect((await dkim2Verify(signed, { resolver: resolver(late as any) })).status.comment).to.equal(
                'DKIM2-Signature i=1 public key rsa has multiple records'
            );
        });

        it('requires both signatures of a "," group, so a missing key is a PERMERROR (section 14.6 step 6)', async () => {
            let signed = await signMessage(message(), originatorOptions());
            let verified = await dkim2Verify(signed, { resolver: resolver({ 'ed._domainkey.example.com': { TXT: [] } }) });
            expect(verified.status.result).to.equal('permerror');
            expect(verified.status.comment).to.equal('DKIM2-Signature i=1 public key ed does not exist');
            expect(verified.signatures[0].values.map((entry: any) => [entry.result, entry.comment])).to.deep.equal([
                ['pass', undefined],
                ['permerror', 'public key ed does not exist']
            ]);
        });

        it('passes on one "|" group when the key of another is missing (section 14.6 step 7)', async () => {
            let signed = await signMessage(
                message(),
                originatorOptions({ signatureData: [[{ selector: 'rsa', privateKey: rsaKey }], [{ selector: 'ed', privateKey: ed25519Key }]] })
            );
            expect(signed.toString()).to.match(/s=rsa:rsa-sha256:[^;]*\|ed:ed25519-sha256:/);
            let verified = await dkim2Verify(signed, { resolver: resolver({ 'ed._domainkey.example.com': { TXT: [] } }) });
            expect(verified.status.result).to.equal('pass');
            expect(verified.signatures[0].values.map((entry: any) => [entry.group, entry.result])).to.deep.equal([
                [1, 'pass'],
                [2, 'permerror']
            ]);
        });

        it('gives TEMPERROR only when every result that is not a PASS is a TEMPERROR (section 14.6)', async () => {
            const failing = (codes: Record<string, string>) => async (name: any) => {
                let err: any = new Error('x');
                err.code = codes[name.split('.')[0]];
                if (!err.code) {
                    return resolver()(name, 'TXT');
                }
                throw err;
            };

            let signed = await signMessage(message(), originatorOptions());
            // a PERMERROR and a TEMPERROR in one group are a PERMERROR
            let verified = await dkim2Verify(signed, { resolver: failing({ rsa: 'ENOTFOUND', ed: 'ETIMEOUT' }) });
            expect(verified.status.result).to.equal('permerror');
            expect(verified.status.comment).to.equal('DKIM2-Signature i=1 public key rsa does not exist');

            // a PASS and a TEMPERROR in one group are a TEMPERROR
            verified = await dkim2Verify(signed, { resolver: failing({ ed: 'ETIMEOUT' }) });
            expect(verified.status.result).to.equal('temperror');
            expect(verified.status.comment).to.equal('DKIM2-Signature i=1 public key ed could not be fetched');

            // a TEMPERROR group wins over a PERMERROR group, it may still pass
            let grouped = await signMessage(
                message(),
                originatorOptions({ signatureData: [[{ selector: 'rsa', privateKey: rsaKey }], [{ selector: 'ed', privateKey: ed25519Key }]] })
            );
            verified = await dkim2Verify(grouped, { resolver: failing({ rsa: 'ENOTFOUND', ed: 'ETIMEOUT' }) });
            expect(verified.status.result).to.equal('temperror');
            expect(verified.status.comment).to.equal('DKIM2-Signature i=1 public key ed could not be fetched');

            // and a FAIL group over a PERMERROR group
            let tampered = Buffer.from(grouped.toString().replace(/(\|ed:ed25519-sha256:)(.)/, (m, lead, c) => lead + (c === 'A' ? 'B' : 'A')));
            verified = await dkim2Verify(tampered, { resolver: failing({ rsa: 'ENOTFOUND' }) });
            expect(verified.status.result).to.equal('fail');
            expect(verified.status.comment).to.equal('DKIM2-Signature i=1 no group of signatures passed');

            let expired = await dkim2Verify(Buffer.from(signed.toString().replace('Hello world', 'Hello there')), {
                resolver: async () => {
                    let err: any = new Error('x');
                    err.code = 'ETIMEOUT';
                    throw err;
                }
            });
            expect(expired.status.result).to.equal('fail');
        });

        it('ignores the retired t= flags (section 14.5)', async () => {
            let signed = await signMessage(message(), rsaOnly);
            let verified = await dkim2Verify(signed, { resolver: resolver({ 'rsa._domainkey.example.com': { TXT: [[keyRecord(rsaKey, 't=y:s')]] } }) });
            expect(verified.status.result).to.equal('pass');
            expect(verified.signatures[0].values[0]).to.not.have.property('testing');
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
                [short, 'too short'],
                [exponent3, 'has an unsupported exponent']
            ]) {
                let crafted = craftSignature(prepend(input, instanceOf(input)), header(), { rsa: key });
                let verified = await dkim2Verify(crafted, { resolver: resolver({ 'rsa._domainkey.example.com': { TXT: [[keyRecord(key)]] } }) });
                expect(verified.status.comment).to.equal(`DKIM2-Signature i=1 public key rsa ${comment}`);
            }
        });

        it('accepts RSA keys from 1024 to 8192 bits only', () => {
            const key = (modulusLength: any, publicExponent: any) => ({ asymmetricKeyDetails: { modulusLength, publicExponent: BigInt(publicExponent) } });
            expect(rsaKeyProblem(key(1024, 65537) as any)).to.equal(null);
            expect(rsaKeyProblem(key(8192, 65537) as any)).to.equal(null);
            expect(rsaKeyProblem(key(1023, 65537) as any)).to.equal('is too short');
            expect(rsaKeyProblem(key(8193, 65537) as any)).to.equal('is too long');
            expect(rsaKeyProblem(key(2048, 3) as any)).to.equal('has an unsupported exponent');
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
            [
                'a repeated selector in another group',
                { signatureData: [[{ selector: 'rsa', privateKey: rsaKey }], [{ selector: 'RSA', privateKey: ed25519Key }]] },
                'EINVALIDSELECTOR'
            ],
            ['an empty group', { signatureData: [[{ selector: 'rsa', privateKey: rsaKey }], []] }, 'ENOKEY'],
            [
                'keys mixed with groups',
                { signatureData: [{ selector: 'rsa', privateKey: rsaKey }, [{ selector: 'ed', privateKey: ed25519Key }]] },
                'EINVALIDOPTS'
            ],
            ['the exploded flag on the first signature', { flags: ['exploded'] }, 'EINVALIDOPTS'],
            ['a Recipe for an unsigned header field', { recipe: { h: { received: [] } } }, 'EINVALIDRECIPE'],
            ['a Recipe with an unknown step key', { recipe: { b: [{ c: [1, 1], x: 1 }] } }, 'EINVALIDRECIPE'],
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
                let err = await dkim2Sign(message(), originatorOptions(options as any)).catch(err => err);
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
            let result = await dkim2Sign(message(), originatorOptions({ nonce: 'id-42', flags: ['feedback', 'future-flag'] }));
            let parsed = parseSignature(result.signature);
            expect(parsed.nonce).to.equal('id-42');
            expect(parsed.flags).to.deep.equal(['feedback', 'future-flag']);
        });

        it('signs with several keys of one algorithm (section 10.9)', async () => {
            let other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
            let options = originatorOptions({
                signatureData: ['rsa', 'rsa2', 'rsa3'].map(selector => ({ selector, privateKey: selector === 'rsa' ? rsaKey : other }))
            });
            let signed = await signMessage(message(), options);
            let zone = resolver({
                'rsa2._domainkey.example.com': { TXT: [[keyRecord(other)]] },
                'rsa3._domainkey.example.com': { TXT: [[keyRecord(other)]] }
            });
            let verified = await dkim2Verify(signed, { resolver: zone });
            expect(verified.status.result).to.equal('pass');
            expect(verified.signatures[0].values.map((entry: any) => entry.selector)).to.deep.equal(['rsa', 'rsa2', 'rsa3']);
        });
    });
});

// example.com sending to an example.com address, so that example.com can sign the next hop too
function originatorToSelf() {
    return originatorOptions({ rcptTo: 'rcpt@example.com' });
}
