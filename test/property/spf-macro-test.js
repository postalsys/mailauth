'use strict';

const { expect } = require('chai');

const macro = require('../../lib/spf/macro');
const { spf } = require('../../lib/spf');
const { fc, check, timeout, bytesFrom } = require('./helper');

const RESULTS = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'];

// macro-expand = ( "%{" macro-letter transformers *delimiter "}" ) / "%%" / "%_" / "%-",
// generated together with the malformed variants a record can hold
const macroExpand = fc.oneof(
    fc
        .tuple(
            fc.constantFrom(...'slodiphcrtvSLODIPHCRTVxZ'.split('')),
            fc.option(fc.oneof(fc.integer({ min: 0, max: 130 }), fc.constant(99999999999)), { nil: '' }),
            fc.constantFrom('', 'r', 'R'),
            bytesFrom('.-+,/_=x', { maxLength: 4 })
        )
        .map(([letter, digits, reverse, delimiters]) => `%{${letter}${digits}${reverse}${delimiters}}`),
    fc.constantFrom('%%', '%_', '%-', '%', '%{', '%{}', '%{s', '}', '%x')
);
const macroString = fc.array(fc.oneof(macroExpand, bytesFrom('az09.-_')), { maxLength: 8 }).map(parts => parts.join(''));

// A sender with a long local-part, with and without dots, so that expansions can grow past the
// 253 characters of a domain name
const localPart = fc.oneof(
    bytesFrom('abc.-+=_', { maxLength: 80 }),
    fc.integer({ min: 60, max: 600 }).map(n => 'x'.repeat(n)),
    fc.integer({ min: 10, max: 200 }).map(n => 'ab.'.repeat(n))
);
const senderDomain = fc.oneof(fc.domain(), fc.constant('example.com'));
const clientIp = fc.oneof(fc.ipV4(), fc.ipV6());

describe('Property: SPF macro expansion', function () {
    this.timeout(timeout(300, 30));

    it('macro() returns a string or throws an SPF permerror, nothing else', () =>
        check(
            fc.property(macroString, localPart, senderDomain, clientIp, fc.domain(), (input, local, dom, ip, helo) => {
                let output;
                try {
                    output = macro(input, { sender: `${local}@${dom}`, ip, helo, mta: 'mx.example', domain: dom });
                } catch (err) {
                    expect(err.spfResult, err.message).to.be.an('object');
                    expect(err.spfResult.error).to.equal('permerror');
                    return;
                }
                expect(output).to.be.a('string');
                if (input.indexOf('%') < 0) {
                    expect(output).to.equal(input);
                }
            }),
            500
        ));

    for (let strict of [false, true]) {
        it(`spf() never queries a name longer than 253 characters and always gives a result${strict ? ' (strict)' : ''}`, () =>
            check(
                fc.asyncProperty(
                    fc.array(fc.tuple(macroString, fc.constantFrom('.example.com', '')), { minLength: 1, maxLength: 4 }),
                    localPart,
                    clientIp,
                    async (specs, local, ip) => {
                        let queried = [];
                        let record = [
                            'v=spf1',
                            ...specs.map(([spec, suffix], i) => `${['exists', 'a', 'mx', 'include'][i % 4]}:${spec}${suffix}`),
                            '-all'
                        ].join(' ');
                        let resolver = async (name, type) => {
                            queried.push(name);
                            if (name === 'example.com' && type === 'TXT') {
                                return [[record]];
                            }
                            let err = new Error(`NXDOMAIN ${name}`);
                            err.code = 'ENOTFOUND';
                            throw err;
                        };

                        let res = await spf({ sender: `${local}@example.com`, ip, helo: 'mx.example.net', mta: 'mx.example', resolver, strict });

                        expect(RESULTS).to.include(res.status.result);
                        for (let name of queried) {
                            expect(name.replace(/\.$/, '').length, name).to.be.at.most(253);
                        }
                    }
                ),
                300
            ));
    }
});
