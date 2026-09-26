/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

let parseDkimHeaders = require('../../lib/parse-dkim-headers');

chai.config.includeStack = true;

describe('parseDkimHeaders Tests', () => {
    it('Should parse ARC header', () => {
        let parsed = parseDkimHeaders(
            'i=1; mx.microsoft.com 1; spf=fail (sender ip is 52.138.216.130) smtp.rcpttodomain=recipient.com smtp.mailfrom=sender.com; dmarc=fail (p=reject sp=reject pct=100) action=oreject header.from=sender.com; dkim=none (message not signed); arc=none (0)'
        );

        expect(parsed.parsed.arc.value).to.equal('none');
    });

    describe('Crafted property keys', () => {
        // A leaked property would otherwise cascade into every later test in the run
        afterEach(() => {
            delete Object.prototype.polluted;
        });

        it('Should not pollute Object.prototype', () => {
            const vectors = [
                'ARC-Authentication-Results: i=1; mx.example.com; dkim=pass __proto__.polluted=owned@evil.example',
                'ARC-Authentication-Results: i=1; mx.example.com; dkim=pass constructor.prototype.polluted=owned@evil.example',
                'Authentication-Results: mx.example.com; dkim=pass prototype.polluted=owned@evil.example',
                'Authentication-Results: mx.example.com; dkim=pass header.__proto__.polluted=owned@evil.example',
                'Authentication-Results: mx.example.com; polluted=1; __proto__=owned@evil.example'
            ];

            for (let vector of vectors) {
                parseDkimHeaders(vector);
                expect(Object.prototype.polluted, vector).to.be.undefined;
                expect({}.polluted, vector).to.be.undefined;
            }
        });

        it('Should not shadow inherited members of a parsed entry', () => {
            // Shadowing toString or valueOf with an object makes string coercion of that
            // entry throw, which used to crash the ARC result formatting
            for (let name of ['toString', 'valueOf', 'hasOwnProperty', 'constructor']) {
                let parsed = parseDkimHeaders(`Authentication-Results: mx.example.com; dmarc=pass header.from.${name}.z=1`);
                expect(parsed.parsed.dmarc.header, name).to.be.undefined;
                expect(() => `${parsed.parsed.dmarc}`, name).to.not.throw();
            }
        });

        it('Should not let a crafted key overwrite the method result', () => {
            for (let key of ['value=owned', 'value.x=1']) {
                let parsed = parseDkimHeaders(`Authentication-Results: mx.example.com; dkim=pass ${key}`);
                expect(parsed.parsed.dkim, key).to.deep.equal([{ value: 'pass' }]);
            }
        });

        it('Should not let a crafted part overwrite the authserv-id value', () => {
            // "value" at the part level holds the authserv-id picked from the first
            // key-only part; a "value=" part used to replace that string with an object
            let parsed = parseDkimHeaders('ARC-Authentication-Results: i=1; mx.example.com; value=evil; dkim=pass');
            expect(parsed.parsed.value).to.equal('mx.example.com');
        });

        it('Should not let a crafted part overwrite the header name', () => {
            // "header" is the other key the result shape pre-seeds
            let parsed = parseDkimHeaders('Authentication-Results: mx.example.com; header=evil; dkim=pass');
            expect(parsed.parsed.header).to.equal('authentication-results');
        });

        it('Should drop propspecs deeper than ptype.property', () => {
            // RFC 8601 2.2: a propspec is exactly "ptype.property", so a third segment would
            // only ever nest an object where the readers of this shape expect a string
            let parsed = parseDkimHeaders('Authentication-Results: mx.example.com; dkim=pass header.i.x=1');
            expect(parsed.parsed.dkim).to.deep.equal([{ value: 'pass' }]);
        });

        it('Should keep the other properties of an entry with a rejected key', () => {
            // the control case: sibling propspecs of a rejected one still parse
            for (let rejected of ['header.toString.z=1', 'value.x=1']) {
                let parsed = parseDkimHeaders(`Authentication-Results: mx.example.com; dkim=pass header.d=example.com ${rejected} header.s=sel1`);
                expect(parsed.parsed.dkim, rejected).to.deep.equal([{ value: 'pass', header: { d: 'example.com', s: 'sel1' } }]);
            }
        });
    });

    it('Should still parse nested property keys', () => {
        let parsed = parseDkimHeaders('Authentication-Results: mx.example.com; dkim=pass header.d=example.com header.s=sel1');
        expect(parsed.parsed.dkim).to.deep.equal([{ value: 'pass', header: { d: 'example.com', s: 'sel1' } }]);
    });

    describe('Tag-list grammar (RFC 6376 section 3.2)', () => {
        const { parseTagList } = parseDkimHeaders;

        it('Should read quotes, parentheses and backslashes as ordinary value characters', () => {
            let parsed = parseDkimHeaders(`DKIM-Signature: v=1; z=From:O'Brien=20(x)|Subject:a\\b"c; n=it's; d=example.com; b=abc`);
            expect(parsed.parsed.z.value).to.equal(`From:O'Brien=20(x)|Subject:a\\b"c`);
            expect(parsed.parsed.n.value).to.equal("it's");
            expect(parsed.parsed.d.value).to.equal('example.com');
            expect(parsed.parsed.b.value).to.equal('abc');
            expect(parsed.syntaxErrors).to.deep.equal([]);
            expect(parsed.parsed.z.comment).to.be.undefined;
        });

        it('Should not double or drop characters after a backslash', () => {
            // the escape flag used to stay set, so every later character was added twice
            let parsed = parseDkimHeaders('DKIM-Signature: n=a\\b; d=example.com; s=sel');
            expect(parsed.parsed.n.value).to.equal('a\\b');
            expect(parsed.parsed.d.value).to.equal('example.com');
            expect(parsed.parsed.s.value).to.equal('sel');
        });

        it('Should parse a bare tag-list with a colon in a value', () => {
            let parsed = parseTagList('v=DKIM1; h=sha1:sha256; s=email:*; n=see: notes (1); p=abc');
            expect(parsed.parsed.v.value).to.equal('DKIM1');
            expect(parsed.parsed.h.value).to.equal('sha1:sha256');
            expect(parsed.parsed.s.value).to.equal('email:*');
            expect(parsed.parsed.n.value).to.equal('see: notes (1)');
            expect(parsed.parsed.p.value).to.equal('abc');
            expect(parsed.tags.map(tag => tag.name)).to.deep.equal(['v', 'h', 's', 'n', 'p']);
        });

        it('Should keep FWS out of the value, and inner whitespace in it', () => {
            let parsed = parseDkimHeaders('DKIM-Signature: n =\r\n  two  words \r\n ; b= ab\r\n cd ;');
            expect(parsed.parsed.n.value).to.equal('two words');
            expect(parsed.parsed.b.value).to.equal('abcd');
            expect(parsed.syntaxErrors).to.deep.equal([]);
        });

        it('Should report what is not valid tag-list syntax', () => {
            expect(parseTagList('a=1; a=2').syntaxErrors).to.deep.equal(['duplicate tag: "a"']);
            expect(parseTagList('a=1;; b=2').syntaxErrors).to.deep.equal(['empty tag-spec']);
            expect(parseTagList('x-note=1').syntaxErrors).to.deep.equal(['invalid tag name: "x-note"']);
            expect(parseTagList('a=1; b').syntaxErrors).to.deep.equal(['tag-spec without "=": "b"']);
            // one trailing semicolon is allowed
            expect(parseTagList('a=1; b=2;').syntaxErrors).to.deep.equal([]);
            // upper and lower case names are different tags
            expect(parseTagList('d=1; D=2').syntaxErrors).to.deep.equal([]);
        });

        it('Should keep the lenient map shape: lower case names, last value wins', () => {
            let parsed = parseTagList('D=1; d=2; t=123; l=0x10');
            expect(parsed.parsed.d.value).to.equal('2');
            expect(parsed.parsed.t.value).to.equal(123);
            expect(parsed.parsed.l.value).to.equal(16);
            expect(parsed.tags).to.deep.equal([
                { name: 'D', value: '1' },
                { name: 'd', value: '2' },
                { name: 't', value: '123' },
                { name: 'l', value: '0x10' }
            ]);
        });

        it('Should build a case-sensitive map for the strict mode', () => {
            let strictMap = parseTagList('D=1; t=123; X=2; key-only', { strict: true }).parsed;
            expect(strictMap.d).to.be.undefined;
            expect(strictMap.D.value).to.equal('1');
            expect(strictMap.t.value).to.equal(123);
            expect(strictMap.value).to.be.undefined;

            let header = parseDkimHeaders('DKIM-Signature: D=1; d=2; i=@x', { strict: true }).parsed;
            expect(header.header).to.equal('dkim-signature');
            expect(header.D.value).to.equal('1');
            expect(header.d.value).to.equal('2');
        });

        it('Should keep the "DNS: TXT;" prefix convention working', () => {
            let parsed = parseDkimHeaders('DNS: TXT;v=BIMI1; l=https://example.com/logo(1).svg; a=');
            expect(parsed.parsed.value).to.equal('txt');
            expect(parsed.parsed.l.value).to.equal('https://example.com/logo(1).svg');
            expect(parsed.parsed.a.value).to.equal('');
        });

        it('Should parse ARC-Seal and ARC-Message-Signature as tag-lists', () => {
            let parsed = parseDkimHeaders("ARC-Message-Signature: i=2; a=rsa-sha256; z=it's(x; d=example.com; b=abc");
            expect(parsed.parsed.i.value).to.equal(2);
            expect(parsed.parsed.z.value).to.equal("it's(x");
            expect(parsed.parsed.d.value).to.equal('example.com');
        });
    });

    describe('Authentication-Results grammar (RFC 8601 section 2.2)', () => {
        it('Should read comments, nested comments and quoted strings', () => {
            let parsed = parseDkimHeaders(
                'Authentication-Results: mx.example.com; spf=pass (a (nested) comment; still comment) smtp.mailfrom="a;b@example.com"; dkim=pass header.i=@example.com'
            );
            expect(parsed.parsed.value).to.equal('mx.example.com');
            expect(parsed.parsed.spf.value).to.equal('pass');
            expect(parsed.parsed.spf.comment).to.equal('a (nested) comment; still comment');
            expect(parsed.parsed.spf.smtp.mailfrom).to.equal('a;b@example.com');
            expect(parsed.parsed.dkim).to.deep.equal([{ value: 'pass', header: { i: '@example.com' } }]);
        });

        it('Should decode quoted-pairs in quoted strings and comments', () => {
            let parsed = parseDkimHeaders('Authentication-Results: mx.example.com; spf=fail (a \\) b) smtp.mailfrom="x\\"y@example.com"; dmarc=pass');
            expect(parsed.parsed.spf.comment).to.equal('a ) b');
            expect(parsed.parsed.spf.smtp.mailfrom).to.equal('x"y@example.com');
            expect(parsed.parsed.dmarc.value).to.equal('pass');
        });

        it('Should not read an apostrophe as a quote', () => {
            let parsed = parseDkimHeaders(
                "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=o'brien@example.com; dmarc=fail header.from=example.com"
            );
            expect(parsed.parsed.spf.smtp.mailfrom).to.equal("o'brien@example.com");
            expect(parsed.parsed.dmarc.value).to.equal('fail');
        });

        it('Should keep reading the ARC-Authentication-Results instance as a number', () => {
            let parsed = parseDkimHeaders('ARC-Authentication-Results: i=3; mx.example.com; arc=pass');
            expect(parsed.parsed.i.value).to.equal(3);
            expect(parsed.parsed.value).to.equal('mx.example.com');
            expect(parsed.parsed.arc.value).to.equal('pass');
        });
    });
});
