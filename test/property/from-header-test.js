'use strict';

const { expect } = require('chai');

const { parseFromHeader, getAuthorDomain } = require('../../lib/dmarc/author-domain');
const { parseAddressList } = require('../helpers/rfc5322-reference');
const { fc, check, timeout } = require('./helper');

// CFWS that may go wherever RFC 5322 allows it: nothing, whitespace, a fold or a comment, which
// can hold specials, quoted-pairs and nested comments
const cfws = fc.constantFrom('', '', ' ', '\t', '\r\n ', ' (comment) ', '(a@evil.example)', '(<x@evil.example>, "q")', '(n(est)ed \\) @ )', ' (\r\n x) ');

const atext = fc.constantFrom(..."abcxyzABC0189!#$%&'*+-/=?^_`{|}~".split(''), 'é', 'ü');
const atomText = fc.string({ unit: atext, minLength: 1, maxLength: 8 });

// quoted-string content: qtext, quoted-pairs and whitespace, and the specials a parser might
// mistake for structure
const qcontent = fc.constantFrom('a', 'b', ' ', '\t', '@', '<', '>', ',', ';', ':', '.', '(', ')', '[', ']', '\\"', '\\\\', '\\a', 'é');
const quotedString = fc.array(qcontent, { maxLength: 8 }).map(parts => `"${parts.join('')}"`);

const word = fc.oneof({ weight: 3, arbitrary: atomText }, { weight: 1, arbitrary: quotedString });

// Each generated piece is { text, value }: `text` is what goes into the header, `value` is
// the part of the addr-spec it stands for, with CFWS removed
const withCfws = arb => fc.tuple(cfws, arb, cfws).map(([before, value, after]) => ({ text: before + value + after, value }));

const localPart = fc.array(withCfws(word), { minLength: 1, maxLength: 3 }).map(words => ({
    text: words.map(w => w.text).join('.'),
    value: words.map(w => w.value).join('.')
}));

const domainLiteral = fc.constantFrom('[192.0.2.1]', '[IPv6:2001:db8::1]', '[ a.b ]');
const domain = fc.oneof(
    {
        weight: 4,
        arbitrary: fc
            .array(withCfws(atomText), { minLength: 1, maxLength: 3 })
            .map(atoms => ({ text: atoms.map(a => a.text).join('.'), value: atoms.map(a => a.value).join('.') }))
    },
    { weight: 1, arbitrary: withCfws(domainLiteral) }
);

const addrSpec = fc.tuple(localPart, domain).map(([local, dom]) => ({ text: `${local.text}@${dom.text}`, value: `${local.value}@${dom.value}` }));

// display-name = phrase, also the obs-phrase with "." after the first word
const displayName = fc
    .tuple(withCfws(word), fc.array(fc.oneof(withCfws(word), fc.constant({ text: '.', value: '.' })), { maxLength: 3 }))
    .map(([first, rest]) => [first, ...rest].map(w => w.text).join(' '));

const route = fc.option(
    fc.array(withCfws(atomText), { minLength: 1, maxLength: 2 }).map(domains => domains.map(d => `@${d.text}`).join(',') + ':'),
    { nil: '' }
);

const mailbox = fc.oneof(
    addrSpec,
    fc
        .tuple(fc.option(displayName, { nil: '' }), cfws, route, addrSpec, cfws)
        .map(([name, before, obsRoute, spec, after]) => ({ text: `${name}${before}<${obsRoute}${spec.text}>${after}`, value: spec.value }))
);

const mailboxes = fc.array(mailbox, { minLength: 1, maxLength: 3 });

// address-list, with groups (RFC 6854) and the empty list elements of obs-addr-list
const address = fc.oneof(
    { weight: 4, arbitrary: mailbox.map(box => ({ text: box.text, values: [box.value] })) },
    {
        weight: 1,
        arbitrary: fc.tuple(displayName, fc.option(mailboxes, { nil: [] }), cfws).map(([name, members, after]) => ({
            text: `${name}:${members.map(m => m.text).join(',')};${after}`,
            values: members.map(m => m.value)
        }))
    }
);

const addressList = fc
    .tuple(fc.array(address, { minLength: 1, maxLength: 4 }), fc.array(fc.constantFrom(',', ', ', ''), { minLength: 4, maxLength: 4 }))
    .map(([addresses, extra]) => ({
        text: addresses.map((a, i) => a.text + (i < addresses.length - 1 ? ',' + extra[i] : '')).join(''),
        values: addresses.flatMap(a => a.values)
    }));

// Fragments of From header fields that mix valid structure with the characters that make
// parsers disagree: unbalanced quotes, comments and brackets, stray "@", "<" and ">", and
// quoted strings or comments that hide an address
const soup = fc
    .array(
        fc.oneof(
            atomText,
            quotedString,
            cfws,
            domainLiteral,
            fc.constantFrom(
                '<',
                '>',
                '@',
                ',',
                ':',
                ';',
                '.',
                ' ',
                '"',
                '(',
                ')',
                '[',
                ']',
                '\\a',
                'example.com',
                'evil.example',
                'a@example.com',
                '<b@evil.example>',
                '"x@evil.example"',
                '(c@evil.example)',
                '@relay.example:'
            )
        ),
        { maxLength: 14 }
    )
    .map(parts => parts.join(''));

describe('Property: From header parsing (parseFromHeader)', function () {
    this.timeout(timeout(500));

    it('never throws, for any input', () =>
        check(
            fc.property(fc.oneof(fc.string({ unit: 'binary' }), fc.string({ unit: 'grapheme' }), soup), value => {
                let result = parseFromHeader(value);
                expect(result.addresses).to.be.an('array');
                expect(['valid', 'lax', 'invalid']).to.include(result.syntax);
                for (let addr of result.addresses) {
                    expect(addr).to.be.a('string').and.to.include('@');
                }
                // and the Author Domain logic built on it does not throw either
                getAuthorDomain(result.addresses, 1, result.syntax === 'invalid');
            }),
            500
        ));

    it('returns exactly the generated addresses of a valid address-list', () =>
        check(
            fc.property(addressList, ({ text, values }) => {
                let result = parseFromHeader(text);
                expect(result.syntax, text).to.equal('valid');
                expect(result.addresses, text).to.deep.equal(values);
            }),
            500
        ));

    it('agrees with the RFC 5322 reference parser on what is valid and on the addresses', () =>
        check(
            fc.property(
                fc.oneof(
                    addressList.map(list => list.text),
                    soup
                ),
                value => {
                    let reference = parseAddressList(value);
                    let result = parseFromHeader(value);

                    if (reference) {
                        expect(result.syntax, value).to.equal('valid');
                        expect(result.addresses, value).to.deep.equal(reference);
                    }

                    if (result.syntax === 'valid') {
                        expect(reference, value).to.not.equal(null);
                    }
                }
            ),
            500
        ));
});
