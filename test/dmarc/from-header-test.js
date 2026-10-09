/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const { parseFromHeader } = require('../../lib/dmarc/author-domain');
const { dmarc } = require('../../lib/dmarc');
const { authenticate } = require('../../lib/mailauth');
const { zoneResolver } = require('../helpers/dns-zone');

chai.config.includeStack = true;

const zone = {
    '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject']] },
    '_dmarc.evil.example': { TXT: [['v=DMARC1; p=none']] },
    'evil.example': { TXT: [['v=spf1 +all']] }
};

const check = async (from, strict) => {
    const res = await authenticate(Buffer.from(`From: ${from}\r\nTo: r@example.org\r\nSubject: t\r\n\r\nbody\r\n`), {
        ip: '192.0.2.1',
        helo: 'mx.evil.example',
        sender: 'bob@evil.example',
        mta: 'mx.test',
        resolver: zoneResolver(zone),
        strict
    });
    return res;
};

describe('DMARC From header parsing (RFC 5322 3.4, 3.6.2, 4.4)', () => {
    describe('parseFromHeader', () => {
        it('Should parse valid mailbox lists', () => {
            for (let [value, addresses] of [
                ['ceo@bank.example', ['ceo@bank.example']],
                ['CEO <ceo@bank.example>', ['ceo@bank.example']],
                ['"Doe, John" <j@bank.example>, a@bank.example', ['j@bank.example', 'a@bank.example']],
                ['John Q. Public <j@bank.example>', ['j@bank.example']],
                ['a@bank.example (Comment (nested))', ['a@bank.example']],
                ['=?utf-8?Q?J=C3=B6rg?= <j@bank.example>', ['j@bank.example']],
                ['Jörg <j@bänk.example>', ['j@bänk.example']],
                ['"ceo@x"@bank.example', ['"ceo@x"@bank.example']],
                ['<@relay.example,@r2.example:ceo@bank.example>', ['ceo@bank.example']],
                ['a@[192.0.2.1]', ['a@[192.0.2.1]']],
                ['Group: a@bank.example, B <b@bank.example>;', ['a@bank.example', 'b@bank.example']],
                ['undisclosed-recipients:;', []],
                [', a@bank.example,,', ['a@bank.example']]
            ]) {
                expect(parseFromHeader(value), value).to.deep.equal({ addresses, syntax: 'valid' });
            }
        });

        it('Should remove CFWS between the atoms of an obs-domain and obs-local-part', () => {
            for (let value of [
                'CEO <ceo@bank .example>',
                'CEO <ceo@bank (x).example>',
                'CEO <ceo@bank. example>',
                'CEO <ceo@bank\r\n\t.example>',
                'CEO <ceo @ bank . example>',
                'ceo@(x)bank.example(y)'
            ]) {
                expect(parseFromHeader(value), JSON.stringify(value)).to.deep.equal({ addresses: ['ceo@bank.example'], syntax: 'valid' });
            }
            expect(parseFromHeader('john . smith@bank.example').addresses).to.deep.equal(['john.smith@bank.example']);
        });

        it('Should keep a Unicode space as part of the domain', () => {
            for (let space of [' ', ' ', '　', '﻿', ' ']) {
                expect(parseFromHeader(`CEO <ceo@bank${space}.example>`).addresses).to.deep.equal([`ceo@bank${space}.example`]);
            }
        });

        it('Should reject malformed fields', () => {
            for (let value of [
                '<bob@evil.example> alice@bank.example',
                'bob <bob@evil.example> <alice@bank.example>',
                'ceo@bank.example bob@evil.example',
                'ceo@bank example',
                'ceo@bank.example; a@evil.example',
                'ceo@bank.example>',
                'CEO <ceo@bank.example',
                '"ceo@bank.example',
                'ceo@bank.example (comment',
                'a@[1.2.3.4',
                'ceo@bank\x00.example',
                'ceo@bank\x7f.example',
                'a"b"@bank.example',
                '@bank.example',
                '<>',
                'G: H: a@bank.example;;',
                // a domain literal is not a word, it can not take the place of the dot
                // between the words of a local-part
                'a[x]b@bank.example',
                'bob[@evil.example]a@bank.example',
                '""[192.0.2.1]y@bank.example',
                'CEO a[x]b@bank.example'
            ]) {
                expect(parseFromHeader(value).syntax, JSON.stringify(value)).to.equal('invalid');
            }
        });

        it('Should accept common deviations as lax', () => {
            for (let [value, addresses] of [
                ['Doe, John <j@bank.example>', ['j@bank.example']],
                ['Mailer-Daemon', []],
                ['Group: a@bank.example', ['a@bank.example']],
                ['a@bank.example.', ['a@bank.example.']],
                ['John [Jack] <j@bank.example>', ['j@bank.example']],
                ['j@bank.example <J@BANK.example>', ['J@BANK.example']],
                ['alice@bank.example <bob@evil.example>', ['alice@bank.example', 'bob@evil.example']]
            ]) {
                expect(parseFromHeader(value), value).to.deep.equal({ addresses, syntax: 'lax' });
            }
        });
    });

    describe('authenticate()', () => {
        it('Should evaluate the obs-domain the reader sees', async () => {
            for (let strict of [false, true]) {
                for (let from of ['CEO <ceo@bank .example>', 'CEO <ceo@bank (x).example>']) {
                    const res = await check(from, strict);
                    expect(res.dmarc.status.result, from).to.equal('fail');
                    expect(res.dmarc.status.header.from, from).to.equal('bank.example');
                    expect(res.dmarc.policy, from).to.equal('reject');
                    expect(res.dmarc.warnings, from).to.not.exist;
                }
            }
        });

        it('Should not evaluate a domain with a Unicode space', async () => {
            for (let strict of [false, true]) {
                for (let space of [' ', ' ', '　', '﻿', ' ']) {
                    const res = await check(`CEO <ceo@bank${space}.example>`, strict);
                    expect(res.dmarc, JSON.stringify(space)).to.be.false;
                    expect(res.dmarcSkipReason, JSON.stringify(space)).to.equal('invalid-author-domain');
                }
            }
        });

        it('Should not pick one of two addresses that are not separated by a comma', async () => {
            for (let strict of [false, true]) {
                for (let from of [
                    '<bob@evil.example> alice@bank.example',
                    'bob <bob@evil.example> <alice@bank.example>',
                    'bob@evil.example alice@bank.example'
                ]) {
                    const res = await check(from, strict);
                    expect(res.dmarc, from).to.be.false;
                    expect(res.dmarcSkipReason, from).to.equal('invalid-author-domain');
                }
            }
        });

        it('Should not evaluate only the angle-addr when the display name is another address', async () => {
            let res = await check('alice@bank.example <bob@evil.example>', false);
            expect(res.dmarc).to.be.false;
            expect(res.dmarcSkipReason).to.equal('multiple-author-domains');

            res = await check('alice@bank.example <bob@evil.example>', true);
            expect(res.dmarc).to.be.false;
            expect(res.dmarcSkipReason).to.equal('invalid-author-domain');
        });

        it('Should warn about a lax From field in the default mode and reject it in strict mode', async () => {
            let res = await check('Doe, John <j@bank.example>', false);
            expect(res.dmarc.status.header.from).to.equal('bank.example');
            expect(res.dmarc.warnings).to.deep.equal(['from-syntax']);

            res = await check('Doe, John <j@bank.example>', true);
            expect(res.dmarc).to.be.false;
            expect(res.dmarcSkipReason).to.equal('invalid-author-domain');
        });
    });

    describe('dmarc()', () => {
        it('Should honor fromSyntax', async () => {
            const resolver = zoneResolver(zone);
            expect(await dmarc({ headerFrom: 'a@bank.example', fromSyntax: 'invalid', resolver })).to.be.false;
            expect(await dmarc({ headerFrom: 'a@bank.example', fromSyntax: 'lax', strict: true, resolver })).to.be.false;
            let res = await dmarc({ headerFrom: 'a@bank.example', fromSyntax: 'lax', resolver });
            expect(res.status.result).to.equal('fail');
            expect(res.warnings).to.deep.equal(['from-syntax']);
        });
    });
});

describe('DMARC Author Domain with invisible or control characters', () => {
    const recordingResolver = () => {
        const resolver = zoneResolver(zone);
        const wrapped = async (name, type) => {
            wrapped.queries.push(name);
            return resolver(name, type);
        };
        wrapped.queries = [];
        return wrapped;
    };

    it('Should not evaluate a domain with a format character', async () => {
        for (let strict of [false, true]) {
            for (let c of ['​', '­', '⁠', '‎', '‮']) {
                const res = await check(`ceo@ba${c}nk.example`, strict);
                expect(res.dmarc, JSON.stringify(c)).to.be.false;
                expect(res.dmarcSkipReason, JSON.stringify(c)).to.equal('invalid-author-domain');
            }
        }
    });

    it('Should not evaluate a domain with a control character or DEL', async () => {
        for (let strict of [false, true]) {
            for (let c of ['\x00', '\x01', '\x1b', '\x7f', '\x85', '\x9f']) {
                const resolver = recordingResolver();
                expect(await dmarc({ headerFrom: `ceo@bank${c}.example`, resolver, strict }), JSON.stringify(c)).to.be.false;
                expect(resolver.queries, JSON.stringify(c)).to.deep.equal([]);
            }
        }
    });

    it('Should still accept a U-label and the CONTEXTJ joiners', async () => {
        const resolver = recordingResolver();
        let res = await dmarc({ headerFrom: 'ceo@bänk.example', resolver });
        expect(res.status.header.from).to.equal('xn--bnk-qla.example');
        // U+200C and U+200D are allowed by IDNA2008 in some scripts (RFC 5892 A.1, A.2)
        res = await dmarc({ headerFrom: 'ceo@ن‌ا.example', resolver });
        expect(res).to.not.be.false;
    });
});
