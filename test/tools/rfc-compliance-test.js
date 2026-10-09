/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const fs = require('node:fs');
const chai = require('chai');
const expect = chai.expect;

const {
    formatAuthHeaderRow,
    escapeCommentValue,
    escapePropValue,
    formatAuthservId,
    stripSignatureValue,
    validateAlgorithm,
    getPublicKey,
    toALabel,
    formatSignatureHeaderLine,
    formatDomain,
    getAlignment,
    parseDkimHeaders
} = require('../../lib/tools');
const { resolverFrom, spkiB64, pkcs1B64, edRawB64 } = require('../helpers/dkim-reference');

chai.config.includeStack = true;

const fixture = file => fs.readFileSync(`${__dirname}/../fixtures/${file}`);
const RSA_PUBLIC = crypto.createPublicKey(crypto.createPrivateKey(fixture('private-rsa.pem')));
const ED_PUBLIC = crypto.createPublicKey(crypto.createPrivateKey(fixture('private-ed25519.pem')));

// Strips RFC 5322 comments and quoted strings the way a structured field parser reads them,
// and reports what is left unterminated. Written for these tests only, it shares no code
// with the formatter
const readStructured = value => {
    let out = '';
    let depth = 0;
    let quoted = false;
    for (let i = 0; i < value.length; i++) {
        let c = value.charAt(i);
        if (quoted) {
            if (c === '\\') {
                i++;
            } else if (c === '"') {
                quoted = false;
            }
            continue;
        }
        if (depth) {
            if (c === '\\') {
                i++;
            } else if (c === '(') {
                depth++;
            } else if (c === ')') {
                depth--;
            }
            continue;
        }
        if (c === '(') {
            depth++;
        } else if (c === '"') {
            quoted = true;
        } else {
            out += c;
        }
    }
    return { out, depth, quoted };
};

describe('Header formatting RFC compliance', () => {
    describe('escapeCommentValue', () => {
        it('Should keep comments balanced whatever the input (RFC 5322 section 3.2.2)', () => {
            for (let value of ['a(b', 'a)b', '((((', '))))', 'a\\', 'a\\(b', '(a)(b', 'x"y', ')(']) {
                let row = formatAuthHeaderRow('spf', { result: 'fail', comment: value });
                let { out, depth, quoted } = readStructured(row);
                expect(depth, value).to.equal(0);
                expect(quoted, value).to.be.false;
                expect(out.trim(), value).to.equal('spf=fail');
            }
        });

        it('Should not let a comment hide the results that follow it', () => {
            // C5: MAIL FROM "a(b"@x left the comment open, and hid dmarc=fail from RFC 5322 readers
            let header = [
                formatAuthHeaderRow('spf', { result: 'pass', comment: 'domain of "x(y"@attacker.example designates 192.0.2.1' }),
                formatAuthHeaderRow('dmarc', { result: 'fail', header: { from: 'bank.example' } })
            ].join('; ');
            expect(readStructured(header).out).to.include('dmarc=fail');
        });

        it('Should replace DEL and control characters', () => {
            expect(escapeCommentValue('a\x7fb\x00c\r\nd')).to.equal('a b c d');
        });

        it('Should shorten a single word that could not be folded', () => {
            let value = escapeCommentValue(`domain of ${'a'.repeat(2000)}@example.com is bad`);
            expect(value.length).to.be.below(500);
            expect(value.startsWith('domain of aaa')).to.be.true;
            expect(value.endsWith('... is bad')).to.be.true;
        });
    });

    describe('escapePropValue', () => {
        const cases = [
            // value, default output, strict output
            ['example.com', 'example.com', 'example.com'],
            ['user@example.com', 'user@example.com', 'user@example.com'],
            ['@example.com', '@example.com', '@example.com'],
            ["o'brien@example.com", "o'brien@example.com", "o'brien@example.com"],
            ['user+tag@example.com', 'user+tag@example.com', 'user+tag@example.com'],
            // already valid quoted-strings in the default mode, RFC 8601 section 2.2 form in strict mode
            [
                'SRS0=HHH=TT=example.com=user@forwarder.example',
                '"SRS0=HHH=TT=example.com=user@forwarder.example"',
                'SRS0=HHH=TT=example.com=user@forwarder.example'
            ],
            ['prvs=1234abcd=user@example.com', '"prvs=1234abcd=user@example.com"', 'prvs=1234abcd=user@example.com'],
            ['"john doe"@example.com', '"\\"john doe\\"@example.com"', '"john doe"@example.com'],
            ['john doe@example.com', '"john doe@example.com"', '"john doe"@example.com'],
            // were written unquoted, which is not valid pvalue syntax
            ['a@b@example.com', '"a@b@example.com"', '"a@b"@example.com'],
            ['user@', '"user@"', '"user@"'],
            ['a..b@example.com', '"a..b@example.com"', '"a..b"@example.com'],
            ['root@localhost', '"root@localhost"', '"root@localhost"'],
            // specials
            ['x; dkim=pass', '"x; dkim=pass"', '"x; dkim=pass"'],
            ['a"b\\c', '"a\\"b\\\\c"', '"a\\"b\\\\c"'],
            ['a\x7fb', '"a b"', '"a b"'],
            ['bücher.example', '"bücher.example"', '"bücher.example"'],
            ['   ', '', '']
        ];

        for (let [value, lax, strict] of cases) {
            it(`Should format ${JSON.stringify(value)}`, () => {
                expect(escapePropValue(value)).to.equal(lax);
                expect(escapePropValue(value, true)).to.equal(strict);
            });
        }

        it('Should leave out an empty or unrepresentable property', () => {
            expect(formatAuthHeaderRow('spf', { result: 'pass', smtp: { mailfrom: '   ', helo: 'mx.example.com' } })).to.equal(
                'spf=pass smtp.helo=mx.example.com'
            );
            expect(formatAuthHeaderRow('spf', { result: 'pass', header: { i: { x: 1 } } })).to.equal('spf=pass');
        });

        it('Should leave out a property value that would take the line past 998 characters', () => {
            let row = formatAuthHeaderRow('spf', { result: 'pass', smtp: { mailfrom: `${'a'.repeat(1100)}@example.com`, helo: 'mx.example.com' } });
            expect(row).to.equal('spf=pass smtp.helo=mx.example.com');
        });

        it('Should keep the result a keyword', () => {
            expect(formatAuthHeaderRow('spf', { result: 'pass; dkim=pass' })).to.equal('spf=passdkimpass');
        });
    });

    describe('formatAuthservId', () => {
        it('Should accept a host name', () => {
            expect(formatAuthservId('mx.example.com')).to.equal('mx.example.com');
            expect(formatAuthservId('My-Mac_1.local')).to.equal('My-Mac_1.local');
            expect(formatAuthservId('mx.bücher.example')).to.equal('mx.xn--bcher-kva.example');
        });

        it('Should quote a value that is not a token', () => {
            expect(formatAuthservId('mx.example; dkim=pass header.d=bank.example')).to.equal('"mx.example; dkim=pass header.d=bank.example"');
            expect(formatAuthservId('mx example')).to.equal('"mx example"');
            expect(formatAuthservId('mx"example')).to.equal('"mx\\"example"');
        });

        it('Should refuse a value that is not a token in strict mode', () => {
            for (let value of ['mx.example; dkim=pass header.d=bank.example', 'mx example', 'mx"example']) {
                expect(() => formatAuthservId(value, true), value).to.throw(TypeError);
            }
        });

        it('Should refuse an empty or oversized value', () => {
            for (let value of ['', 'a'.repeat(1000)]) {
                expect(() => formatAuthservId(value), value).to.throw(TypeError);
                expect(() => formatAuthservId(value, true), value).to.throw(TypeError);
            }
        });
    });

    describe('stripSignatureValue', () => {
        const strip = line => stripSignatureValue(Buffer.from(line)).toString();

        it('Should empty the value of the b= tag', () => {
            expect(strip('DKIM-Signature: v=1; bh=abc; b=def')).to.equal('DKIM-Signature: v=1; bh=abc; b=');
            expect(strip('dkim-signature:v=1; b=def; x=1')).to.equal('dkim-signature:v=1; b=; x=1');
            expect(strip('DKIM-Signature: v=1;\r\n\tb=abc\r\n\tdef')).to.equal('DKIM-Signature: v=1;\r\n\tb=');
            expect(strip('DKIM-Signature:b=abc; v=1')).to.equal('DKIM-Signature:b=; v=1');
        });

        it('Should find the b= tag the way a tag-list is read', () => {
            // not a "b=" inside another tag
            expect(strip('DKIM-Signature: z=Subject:b=3Dx; bh=abc; b=def')).to.equal('DKIM-Signature: z=Subject:b=3Dx; bh=abc; b=');
            expect(strip('DKIM-Signature: xnote=see b=here; b=def')).to.equal('DKIM-Signature: xnote=see b=here; b=');
            // FWS between the name and "="
            expect(strip('DKIM-Signature: bh=abc; b =def ')).to.equal('DKIM-Signature: bh=abc; b =');
            expect(strip('DKIM-Signature: bh=abc;\r\n b\r\n =def')).to.equal('DKIM-Signature: bh=abc;\r\n b\r\n =');
        });

        it('Should not take a byte such as 0xA0 for whitespace', () => {
            let line = Buffer.from('DKIM-Signature: v=1; \xa0b=decoy; b=real', 'binary');
            expect(stripSignatureValue(line).toString('binary')).to.equal('DKIM-Signature: v=1; \xa0b=decoy; b=');
        });

        it('Should strip the b= tag the parser takes the signature from in each mode', () => {
            const stripMode = (line, strict) => stripSignatureValue(Buffer.from(line), strict).toString();
            let line = 'DKIM-Signature: v=1; b=XXX; d=a.com; B=YYY';

            // the lenient parser folds tag names to lower case and keeps the last value
            expect(parseDkimHeaders(line).parsed.b.value).to.equal('YYY');
            expect(stripMode(line, false)).to.equal('DKIM-Signature: v=1; b=XXX; d=a.com; B=');

            // the strict parser reads tag names case-sensitively, "B" is an unknown tag
            expect(parseDkimHeaders(line, { strict: true }).parsed.b.value).to.equal('XXX');
            expect(stripMode(line, true)).to.equal('DKIM-Signature: v=1; b=; d=a.com; B=YYY');

            expect(stripMode('DKIM-Signature: b=real; B=other', false)).to.equal('DKIM-Signature: b=real; B=');
            expect(stripMode('DKIM-Signature: b=real; B=other', true)).to.equal('DKIM-Signature: b=; B=other');
            expect(stripMode('DKIM-Signature: v=1; B=only', false)).to.equal('DKIM-Signature: v=1; B=');
            expect(stripMode('DKIM-Signature: v=1; B=only', true)).to.equal('DKIM-Signature: v=1; B=only');
        });
    });

    describe('validateAlgorithm', () => {
        it('Should refuse ed25519-sha1 in every mode (RFC 8463)', () => {
            expect(() => validateAlgorithm('ed25519-sha1')).to.throw();
            expect(() => validateAlgorithm('ed25519-sha1', true)).to.throw();
            expect(() => validateAlgorithm('ed25519-sha256')).to.not.throw();
            expect(() => validateAlgorithm('rsa-sha1')).to.not.throw();
            expect(() => validateAlgorithm('rsa-sha1', true)).to.throw();
        });
    });

    describe('toALabel', () => {
        it('Should convert U-labels to lower case A-labels and leave ASCII labels alone', () => {
            expect(toALabel('bücher.example')).to.equal('xn--bcher-kva.example');
            expect(toALabel('BÜCHER.Example')).to.equal('xn--bcher-kva.Example');
            expect(toALabel('Example.COM')).to.equal('Example.COM');
            expect(toALabel('')).to.equal('');
        });

        it('Should be used for d= and s= and the domain of i=', () => {
            let line = formatSignatureHeaderLine('DKIM', { d: 'ÕNNELIK.ee', s: 'Sõber', i: '"a@b"@Bücher.example', a: 'rsa-sha256', b: 'x' }, false);
            expect(line).to.include('d=xn--nnelik-oxa.ee');
            expect(line).to.include('s=xn--sber-0qa');
            expect(line).to.include('i="a@b"@xn--bcher-kva.example');
        });

        it('Should give formatDomain, DMARC alignment and DKIM d= the same A-label for decomposed input', () => {
            // "e" followed by U+0301 COMBINING ACUTE ACCENT is the NFD form of U+00E9
            let decomposed = 'café.example';
            let composed = 'café.example';
            let aLabel = toALabel(composed);
            expect(aLabel).to.equal('xn--caf-dma.example');
            expect(toALabel(decomposed)).to.equal(aLabel);
            expect(formatDomain(decomposed)).to.equal(aLabel);

            let line = formatSignatureHeaderLine('DKIM', { d: decomposed, s: 'sel', a: 'rsa-sha256', b: 'x' }, false);
            let signedDomain = line.match(/\bd=([^;]+)/)[1];
            expect(signedDomain).to.equal(aLabel);

            // the From domain in one form aligns with a d= written from the other
            for (let strict of [false, true]) {
                expect(getAlignment(decomposed, [{ domain: signedDomain }], strict)).to.deep.equal({ domain: signedDomain });
                expect(getAlignment(composed, [{ domain: decomposed }], strict)).to.deep.equal({ domain: decomposed });
            }
        });
    });

    describe('getPublicKey', () => {
        const NAME = 'sel._domainkey.example.com';
        const get = (record, options, type) => getPublicKey(type || 'DKIM', NAME, 1024, resolverFrom({ [NAME]: [record] }), options);
        const rejects = async (promise, code) => {
            try {
                await promise;
            } catch (err) {
                expect(err.code).to.equal(code);
                return err;
            }
            throw new Error(`Expected ${code}`);
        };

        it('Should accept a bare RSAPublicKey (RFC 6376 section 3.6.1)', async () => {
            let res = await get(`v=DKIM1; k=rsa; p=${pkcs1B64(RSA_PUBLIC)}`);
            expect(res.keyType).to.equal('rsa');
            expect(res.modulusLength).to.equal(2048);
        });

        it('Should look up a U-label name under its A-label', async () => {
            let log = [];
            await getPublicKey(
                'DKIM',
                'sel._domainkey.bücher.example',
                1024,
                resolverFrom({ 'sel._domainkey.xn--bcher-kva.example': [`p=${spkiB64(RSA_PUBLIC)}`] }, log)
            );
            expect(log).to.deep.equal(['TXT sel._domainkey.xn--bcher-kva.example']);
        });

        it('Should enforce the key h= tag when the hash is known', async () => {
            await rejects(get(`v=DKIM1; h=sha1; p=${spkiB64(RSA_PUBLIC)}`, { hashAlgo: 'sha256' }), 'EINVALIDHASH');
            await rejects(get(`v=DKIM1; h=sha256; p=${spkiB64(RSA_PUBLIC)}`, { hashAlgo: 'sha1', strict: true }), 'EINVALIDHASH');
            expect((await get(`v=DKIM1; h=sha1 : sha256; p=${spkiB64(RSA_PUBLIC)}`, { hashAlgo: 'sha256' })).keyType).to.equal('rsa');
        });

        it('Should enforce the key s= tag', async () => {
            await rejects(get(`v=DKIM1; s=foo; p=${spkiB64(RSA_PUBLIC)}`), 'EINVALIDSERVICE');
            for (let s of ['email', '*', 'foo:email', 'EMAIL']) {
                expect((await get(`v=DKIM1; s=${s}; p=${spkiB64(RSA_PUBLIC)}`)).keyType).to.equal('rsa');
            }
        });

        it('Should report the key flags', async () => {
            let res = await get(`v=DKIM1; t=y:s; p=${spkiB64(RSA_PUBLIC)}`);
            expect(res.flags).to.deep.equal(['y', 's']);
            expect(res.testing).to.be.true;
        });

        it('Should apply the key record syntax rules in strict mode only', async () => {
            let lax = await get(`k=rsa; v=DKIM1; p=${spkiB64(RSA_PUBLIC)}`);
            expect(lax.warnings).to.deep.equal(['key-v-syntax']);
            await rejects(get(`k=rsa; v=DKIM1; p=${spkiB64(RSA_PUBLIC)}`, { strict: true }), 'EINVALIDVER');

            lax = await get(`v=DKIM1; p=${edRawB64(ED_PUBLIC)}`);
            expect(lax.keyType).to.equal('ed25519');
            expect(lax.warnings).to.deep.equal(['key-type-inferred']);
            await rejects(get(`v=DKIM1; p=${edRawB64(ED_PUBLIC)}`, { strict: true }), 'EINVALIDTYPE');
            expect((await get(`v=DKIM1; k=ed25519; p=${edRawB64(ED_PUBLIC)}`, { strict: true })).keyType).to.equal('ed25519');

            lax = await get(`v=DKIM1; k=ed25519; p=${spkiB64(ED_PUBLIC)}`);
            expect(lax.keyType).to.equal('ed25519');
            expect(lax.warnings).to.deep.equal(['key-ed25519-spki']);
            await rejects(get(`v=DKIM1; k=ed25519; p=${spkiB64(ED_PUBLIC)}`, { strict: true }), 'EINVALIDVAL');

            lax = await get(`v=DKIM1; v=DKIM1; p=${spkiB64(RSA_PUBLIC)}`);
            expect(lax.warnings).to.deep.equal(['key-syntax']);
            await rejects(get(`v=DKIM1; v=DKIM1; p=${spkiB64(RSA_PUBLIC)}`, { strict: true }), 'EINVALIDVAL');
        });

        it('Should not remove whitespace from inside a key record value', async () => {
            // RFC 6376 section 3.6.1: key-v-tag is exactly "DKIM1", FWS is only allowed around "="
            let lax = await get(`v=DKIM 1; k=rsa; p=${spkiB64(RSA_PUBLIC)}`);
            expect(lax.keyType).to.equal('rsa');
            expect(lax.warnings).to.deep.equal(['key-v-syntax']);
            await rejects(get(`v=DKIM 1; k=rsa; p=${spkiB64(RSA_PUBLIC)}`, { strict: true }), 'EINVALIDVER');
            await rejects(get(`v=DKIM 2; k=rsa; p=${spkiB64(RSA_PUBLIC)}`), 'EINVALIDVER');

            for (let rec of [
                `v=DKIM1; k=r sa; p=${spkiB64(RSA_PUBLIC)}`,
                `v=DKIM1; s=em ail; p=${spkiB64(RSA_PUBLIC)}`,
                `v=DKIM1; t=y : s s; p=${spkiB64(RSA_PUBLIC)}`
            ]) {
                lax = await get(rec);
                expect(lax.keyType, rec).to.equal('rsa');
                expect(lax.warnings, rec).to.deep.equal(['key-syntax']);
                await rejects(get(rec, { strict: true }), 'EINVALIDVAL');
            }
            expect((await get(`v=DKIM1; t=y : s s; p=${spkiB64(RSA_PUBLIC)}`)).flags).to.deep.equal(['y', 'ss']);
        });

        it('Should accept FWS where the key record grammar allows it, in strict mode too', async () => {
            let b64 = spkiB64(RSA_PUBLIC);
            let folded = b64.match(/.{1,40}/g).join(' \r\n ');
            let res = await get(`v = DKIM1 ;\tk = rsa ; t = y : s ; s = email : * ; p = ${folded} `, { strict: true });
            expect(res.keyType).to.equal('rsa');
            expect(res.flags).to.deep.equal(['y', 's']);
            expect(res.warnings).to.deep.equal([]);
        });

        it('Should read quotes, parentheses and backslashes as value characters', async () => {
            for (let n of ["it's", 'see(below', 'a\\b', '"quoted"']) {
                let res = await get(`v=DKIM1; k=rsa; n=${n}; p=${spkiB64(RSA_PUBLIC)}`, { strict: true });
                expect(res.keyType, n).to.equal('rsa');
            }
        });
    });
});
