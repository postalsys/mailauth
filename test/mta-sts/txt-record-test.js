/* eslint no-unused-expressions:0 */
'use strict';

const { expect } = require('chai');
const { resolvePolicy, getPolicy } = require('../../lib/mta-sts');
const { mockResolver, dnsError } = require('./harness');

const txtResolver = records => mockResolver({ '_mta-sts.example.test|TXT': records });

const resolve = (records, opts) => resolvePolicy('example.test', Object.assign({ resolver: txtResolver(records) }, opts));

describe('MTA-STS TXT record (RFC 8461 3.1)', () => {
    describe('both modes', () => {
        for (let strict of [false, true]) {
            describe(strict ? 'strict' : 'lax', () => {
                it('parses a basic record', async () => {
                    expect(await resolve([['v=STSv1; id=20160831085700Z;']], { strict })).to.equal('20160831085700Z');
                });

                it('concatenates multiple strings without spaces', async () => {
                    expect(await resolve([['v=STSv1; id=2016', '0831085700Z;']], { strict })).to.equal('20160831085700Z');
                });

                it('uses the first id when id is duplicated', async () => {
                    expect(await resolve([['v=STSv1; id=first; id=second']], { strict })).to.equal('first');
                });

                it('accepts extension values containing ":", "(", quotes and backslashes', async () => {
                    for (let record of [
                        'v=STSv1; id=abc; ext=a:b',
                        'v=STSv1; ext=https://x.example; id=abc',
                        'v=STSv1; id=abc; ext=(x)',
                        'v=STSv1; ext=(x; id=abc',
                        'v=STSv1; ext="x; id=abc',
                        "v=STSv1; ext='q; id=abc",
                        'v=STSv1; id=abc; ext=a\\b'
                    ]) {
                        expect(await resolve([[record]], { strict }), record).to.equal('abc');
                    }
                });

                it('discards records that do not begin with "v=STSv1;" before counting', async () => {
                    for (let other of ['v=STSv1-x; id=a', 'v=STSv1', 'v=STSv1.1; id=a', 'v=STSv10; id=a', 'v=spf1 -all', 'id=a; v=STSv1']) {
                        expect(await resolve([[other], ['v=STSv1; id=good']], { strict }), other).to.equal('good');
                    }
                });

                it('fails with multi_sts_records for two valid records', async () => {
                    let err;
                    try {
                        await resolve([['v=STSv1; id=a'], ['v=STSv1; id=b']], { strict });
                    } catch (E) {
                        err = E;
                    }
                    expect(err?.code).to.equal('multi_sts_records');
                });

                it('returns false for records without a usable id', async () => {
                    for (let record of ['v=STSv1;', 'v=STSv1; id=', 'v=STSv1 id=abc', 'id=abc; v=STSv1']) {
                        expect(await resolve([[record]], { strict }), record).to.be.false;
                    }
                });

                it('returns false for NXDOMAIN and NODATA, throws for other DNS errors', async () => {
                    for (let code of ['ENOTFOUND', 'ENODATA']) {
                        expect(await resolvePolicy('example.test', { strict, resolver: mockResolver({ '_mta-sts.example.test|TXT': dnsError(code) }) })).to.be
                            .false;
                    }
                    let err;
                    try {
                        await resolvePolicy('example.test', { strict, resolver: mockResolver({ '_mta-sts.example.test|TXT': dnsError('ESERVFAIL') }) });
                    } catch (E) {
                        err = E;
                    }
                    expect(err?.code).to.equal('ESERVFAIL');
                });

                it('converts IDN domains outside Latin-1 to A-labels', async () => {
                    for (let [domain, expected] of [
                        ['münchen.test', '_mta-sts.xn--mnchen-3ya.test|TXT'],
                        ['例え.test', '_mta-sts.xn--r8jz45g.test|TXT'],
                        ['пример.test', '_mta-sts.xn--e1afmkfd.test|TXT'],
                        ['user@пример.test', '_mta-sts.xn--e1afmkfd.test|TXT']
                    ]) {
                        let resolver = mockResolver({});
                        await resolvePolicy(domain, { strict, resolver });
                        expect(resolver.queries, domain).to.deep.equal([expected]);
                    }
                });

                it('strips the local part and a trailing dot', async () => {
                    let resolver = mockResolver({});
                    await resolvePolicy('User@Example.Test.', { strict, resolver });
                    expect(resolver.queries).to.deep.equal(['_mta-sts.example.test|TXT']);
                });
            });
        }
    });

    describe('lax mode', () => {
        it('accepts non-RFC id values and version case as before', async () => {
            expect(await resolve([['v=stsv1; id=abc']])).to.equal('abc');
            expect(await resolve([['V=STSv1; id=abc']])).to.equal('abc');
            expect(await resolve([['  v=STSv1; id=abc']])).to.equal('abc');
            expect(await resolve([['v=STSv1; id=2016-08-31']])).to.equal('2016-08-31');
            expect(await resolve([['v=STSv1; id=' + 'a'.repeat(33)]])).to.equal('a'.repeat(33));
            expect(await resolve([['v=STSv1; id=abc def']])).to.equal('abc def');
        });

        it('reports a txt-syntax warning from getPolicy', async () => {
            let resolver = mockResolver({ '_mta-sts.example.test|TXT': [['v=STSv1; id=2016-08-31']] });
            let known = { id: '2016-08-31', mode: 'enforce', mx: ['mx.example.test'], maxAge: 3600, expires: new Date(Date.now() + 3600e3).toISOString() };
            let result = await getPolicy('example.test', known, { resolver });
            expect(result.status).to.equal('renewed');
            expect(result.warnings).to.deep.equal(['txt-syntax']);
        });

        it('does not add warnings for a valid record', async () => {
            let resolver = mockResolver({ '_mta-sts.example.test|TXT': [['v=STSv1; id=abc']] });
            let known = { id: 'abc', mode: 'enforce', mx: ['mx.example.test'], maxAge: 3600, expires: new Date(Date.now() + 3600e3).toISOString() };
            let result = await getPolicy('example.test', known, { resolver });
            expect(result).to.not.have.property('warnings');
        });
    });

    describe('strict mode', () => {
        it('rejects records that are not syntactically valid', async () => {
            for (let record of [
                'v=stsv1; id=abc',
                'V=STSv1; id=abc',
                '  v=STSv1; id=abc',
                'v=STSv1; id=2016-08-31',
                'v=STSv1; id=1.2',
                'v=STSv1; id=' + 'a'.repeat(33),
                'v=STSv1; id=abc def',
                'v=STSv1; id="abc"',
                'v=STSv1; id=abc(xyz)',
                'v=STSv1; id=abc ',
                'v=STSv1; ; id=abc',
                'v=STSv1; id=abc; _ext=x',
                'v=STSv1; id=abc; ext=',
                'v=STSv1; id=abc; ext=a b',
                'v=STSv1; ID=abc',
                'v=STSv1; id=abc; ext=ü'
            ]) {
                expect(await resolve([[record]], { strict: true }), record).to.be.false;
            }
        });

        it('accepts valid ABNF edge cases', async () => {
            expect(await resolve([['v=STSv1; id=' + 'a'.repeat(32)]], { strict: true })).to.equal('a'.repeat(32));
            expect(await resolve([['v=STSv1 ;id=abc ; '], []], { strict: true })).to.equal('abc');
            expect(await resolve([['v=STSv1;\tid=abc;\text.name-1_x=value']], { strict: true })).to.equal('abc');
            // a later duplicate only has to be a valid field
            expect(await resolve([['v=STSv1; id=abc; id=x-y']], { strict: true })).to.equal('abc');
            expect(await resolve([['v=STSv1; id=x-y; id=abc']], { strict: true })).to.be.false;
        });

        it('treats lowercase v=stsv1 records as non-STS records when counting', async () => {
            expect(await resolve([['v=stsv1; id=a'], ['v=STSv1; id=good']], { strict: true })).to.equal('good');
        });
    });
});
