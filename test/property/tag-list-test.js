'use strict';

const { expect } = require('chai');

const parseDkimHeaders = require('../../lib/parse-dkim-headers');
const { parseTagList } = require('../../lib/parse-dkim-headers');
const { parseDmarcRecord } = require('../../lib/dmarc/get-dmarc-record');
const reference = require('../helpers/dkim-reference');
const { fc, check, timeout, bytesFrom } = require('./helper');

// Tag-lists of RFC 6376 section 3.2 with the characters that matter for the parser: separators,
// FWS, characters that are special in other header grammars, and names that collide with
// object properties
const FWS = fc.constantFrom('', '', ' ', '\t', '\r\n ', ' \r\n\t ');
// tag-name = ALPHA *ALNUMPUNC
const validTagName = fc.oneof(
    fc.stringMatching(/^[A-Za-z][A-Za-z0-9_]{0,5}$/),
    fc.constantFrom('v', 'a', 'b', 'bh', 'd', 'h', 'i', 'l', 's', 't', 'x', 'p', 'k', 'header', 'value', 'constructor', 'prototype')
);
const tagName = fc.oneof(validTagName, fc.constantFrom('__proto__', '_x', '1a', 'a-b', ''));
// tag-value = [ tval *( 1*(WSP / FWS) tval ) ], tval = 1*VALCHAR (%x21-3A / %x3C-7E)
const tval = bytesFrom('aZ09!"#$%&\'()*+,-./:<=>?@[\\]^_`{|}~', { minLength: 1, maxLength: 10 });
const tagValue = fc
    .array(fc.tuple(fc.constantFrom(' ', '\t', '\r\n ', '  '), tval), { maxLength: 3 })
    .chain(rest => fc.option(tval, { nil: '' }).map(first => (first ? first + rest.map(([ws, t]) => ws + t).join('') : '')));

const validTagList = fc
    .uniqueArray(fc.tuple(validTagName, tagValue, FWS, FWS, FWS, FWS), { minLength: 1, maxLength: 8, selector: ([name]) => name })
    .chain(tags => fc.boolean().map(trailing => ({ tags, trailing })))
    .map(({ tags, trailing }) => ({
        text: tags.map(([name, value, a, b, c, d]) => `${a}${name}${b}=${c}${value}${d}`).join(';') + (trailing ? ';' : ''),
        tags: tags.map(([name, value]) => ({ name, value }))
    }));

// Anything at all, and tag-list fragments mixed with separators, quotes and comments
const anyTagList = fc.oneof(
    fc.string({ unit: 'binary' }),
    fc
        .array(fc.oneof(tagName, tval, fc.constantFrom(';', '=', ' ', '\r\n ', '"', '(', ')', '\\', ':', 'DKIM-Signature:')), { maxLength: 20 })
        .map(parts => parts.join(''))
);

// Unfolds and collapses whitespace the way the parser reports a tag value
const normalizeValue = value => value.replace(/\s+/g, ' ').trim();

describe('Property: tag-list parsing (RFC 6376 section 3.2)', function () {
    this.timeout(timeout(500));

    afterEach(() => {
        delete Object.prototype.polluted;
    });

    it('never throws and never touches Object.prototype, for any input', () =>
        check(
            fc.property(anyTagList, fc.boolean(), (value, strict) => {
                let probe = {};
                for (let header of ['DKIM-Signature', 'ARC-Seal', 'ARC-Message-Signature', 'Authentication-Results', 'ARC-Authentication-Results']) {
                    let result = parseDkimHeaders(`${header}: ${value}`, { strict });
                    expect(result.parsed).to.be.an('object');
                }
                let { parsed, tags, syntaxErrors } = parseTagList(value, { strict });
                expect(parsed).to.be.an('object');
                expect(tags).to.be.an('array');
                expect(syntaxErrors).to.be.an('array');
                expect(Object.getPrototypeOf(probe)).to.equal(Object.prototype);
                expect(probe.polluted).to.equal(undefined);
                expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')).to.equal(false);
            }),
            500
        ));

    it('reads every tag of a valid tag-list, and reports no syntax error', () =>
        check(
            fc.property(validTagList, ({ text, tags }) => {
                let result = parseTagList(text, { strict: true });
                expect(result.syntaxErrors, text).to.deep.equal([]);
                expect(result.tags, text).to.deep.equal(tags.map(tag => ({ name: tag.name, value: normalizeValue(tag.value) })));
            }),
            500
        ));

    it('agrees with the reference parser on which tag-lists are valid', () =>
        check(
            fc.property(
                fc.oneof(
                    validTagList.map(list => list.text),
                    anyTagList
                ),
                value => {
                    // the reference reads a tag-list from a header field value, without the CRLF at the end
                    let ref = reference.parseTagList(value);
                    let result = parseTagList(value, { strict: true });
                    if (!ref.errors.length) {
                        expect(result.syntaxErrors, JSON.stringify(value)).to.deep.equal([]);
                        expect(result.tags.map(tag => tag.name)).to.deep.equal(Object.keys(ref.tags));
                    }
                }
            ),
            500
        ));
});

describe('Property: DMARC record parsing', function () {
    this.timeout(timeout(500));

    const recordText = fc.oneof(
        fc.string({ unit: 'binary' }),
        fc
            .array(fc.oneof(tagName, tval, fc.constantFrom(';', '=', ' ', 'p', 'sp', 'pct', 'rua', 'P', 'v=DMARC1', 'reject', '\t')), { maxLength: 20 })
            .map(parts => 'v=DMARC1; ' + parts.join(''))
    );

    it('never throws, and only reports tags written as name=value', () =>
        check(
            fc.property(recordText, fc.boolean(), (txt, strict) => {
                let warnings = new Set();
                let parsed = parseDmarcRecord(txt, { strict, warnings });
                if (parsed === null) {
                    // a duplicated tag in the strict mode
                    expect(strict).to.equal(true);
                    return;
                }
                expect(parsed.rr).to.equal(txt);

                // the tag names of the fragments that have a name and a "="
                let names = new Set(
                    txt
                        .split(';')
                        .filter(fragment => fragment.indexOf('=') > 0)
                        .map(fragment => fragment.slice(0, fragment.indexOf('=')).trim())
                        .filter(name => name)
                        .flatMap(name => [name, name.toLowerCase()])
                );
                for (let key of Object.keys(parsed)) {
                    if (key !== 'rr') {
                        expect(names.has(key), `${key} in ${JSON.stringify(txt)}`).to.equal(true);
                    }
                }
                expect({}.polluted).to.equal(undefined);
            }),
            500
        ));
});
