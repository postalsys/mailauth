/* eslint no-unused-expressions:0 */
'use strict';

const { expect } = require('chai');
const { parsePolicy } = require('../../lib/mta-sts');

const BASE = 'version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 604800\r\n';

const errorCode = (body, opts) => {
    try {
        parsePolicy(body, opts);
    } catch (err) {
        return err.code;
    }
    return null;
};

describe('MTA-STS policy file (RFC 8461 3.2)', () => {
    for (let strict of [false, true]) {
        describe(strict ? 'strict' : 'lax', () => {
            const opts = { strict };

            it('parses the RFC example', () => {
                expect(
                    parsePolicy(
                        'version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmx: backupmx.example.com\r\nmax_age: 604800\r\n',
                        opts
                    )
                ).to.deep.equal({
                    mode: 'enforce',
                    version: 'STSv1',
                    mx: ['mail.example.com', '*.example.net', 'backupmx.example.com'],
                    maxAge: 604800
                });
            });

            it('keeps the property order of the result object', () => {
                expect(JSON.stringify(parsePolicy(BASE, opts))).to.equal('{"mode":"enforce","version":"STSv1","mx":["mail.example.com"],"maxAge":604800}');
            });

            it('accepts LF line endings and a missing final line break', () => {
                expect(parsePolicy(BASE.replace(/\r\n/g, '\n'), opts).mode).to.equal('enforce');
                expect(parsePolicy(BASE.trim(), opts).mode).to.equal('enforce');
            });

            it('uses the first value of a duplicated non-mx field', () => {
                expect(parsePolicy(BASE + 'mode: none\r\n', opts).mode).to.equal('enforce');
                expect(parsePolicy('version: STSv1\r\nmode: testing\r\nmode: enforce\r\nmx: a.example\r\nmax_age: 60\r\n', opts).mode).to.equal('testing');
                expect(parsePolicy(BASE + 'max_age: 1\r\n', opts).maxAge).to.equal(604800);
                expect(parsePolicy(BASE + 'version: STSv2\r\n', opts).version).to.equal('STSv1');
                expect(errorCode('version: STSv2\r\n' + BASE, opts)).to.equal('invalid_sts_version');
            });

            it('collects all mx fields without duplicates', () => {
                expect(parsePolicy(BASE + 'mx: *.example.net\r\nmx: MAIL.example.com\r\n', opts).mx).to.deep.equal(['mail.example.com', '*.example.net']);
            });

            it('treats a missing mode as an invalid policy', () => {
                expect(errorCode(BASE.replace('mode: enforce\r\n', ''), opts)).to.equal('invalid_sts_mode');
            });

            it('rejects invalid or missing required fields', () => {
                expect(errorCode(BASE.replace('version: STSv1\r\n', ''), opts)).to.equal('invalid_sts_version');
                expect(errorCode(BASE.replace('STSv1', 'stsv1'), opts)).to.equal('invalid_sts_version');
                expect(errorCode(BASE.replace('enforce', 'reject'), opts)).to.equal('invalid_sts_mode');
                expect(errorCode(BASE.replace('max_age: 604800\r\n', ''), opts)).to.equal('invalid_sts_max_age');
                expect(errorCode(BASE.replace('604800', '31557601'), opts)).to.equal('invalid_sts_max_age');
                expect(errorCode(BASE.replace('mx: mail.example.com\r\n', ''), opts)).to.equal('invalid_sts_mx');
                expect(errorCode('<html><body>version: STSv1<br>\nmode: enforce\nmx: a.example\nmax_age: 60</body></html>', opts)).to.equal(
                    'invalid_sts_version'
                );
            });

            it('allows a missing mx for mode none', () => {
                expect(parsePolicy(BASE.replace('mx: mail.example.com\r\n', '').replace('enforce', 'none'), opts)).to.deep.equal({
                    mode: 'none',
                    version: 'STSv1',
                    maxAge: 604800
                });
            });

            it('accepts max_age boundaries', () => {
                expect(parsePolicy(BASE.replace('604800', '0'), opts).maxAge).to.equal(0);
                expect(parsePolicy(BASE.replace('604800', '31557600'), opts).maxAge).to.equal(31557600);
            });

            it('ignores unknown fields and lines without a colon', () => {
                expect(parsePolicy(BASE + 'foo_bar: baz\r\nthis is not a field\r\n', opts).mode).to.equal('enforce');
            });
        });
    }

    describe('lax mode', () => {
        it('keeps accepting non-RFC syntax as before', () => {
            expect(parsePolicy(BASE.replace('enforce', 'ENFORCE')).mode).to.equal('enforce');
            expect(parsePolicy(BASE.replace('mode:', 'MODE:')).mode).to.equal('enforce');
            expect(parsePolicy(BASE.replace('mode:', 'mode :')).mode).to.equal('enforce');
            expect(parsePolicy('﻿' + BASE).version).to.equal('STSv1');
            expect(parsePolicy(BASE.replace('604800', '1e3')).maxAge).to.equal(1000);
            expect(parsePolicy(BASE.replace('604800', '0x10')).maxAge).to.equal(16);
            expect(parsePolicy(BASE.replace('604800', '12.5')).maxAge).to.equal(12.5);
            expect(parsePolicy(BASE.replace('604800', '')).maxAge).to.equal(0);
            expect(parsePolicy(BASE.replace('604800', '00000000060')).maxAge).to.equal(60);
            expect(parsePolicy(BASE.replace('mail.example.com', 'foo*.example.com')).mx).to.deep.equal(['foo*.example.com']);
            expect(parsePolicy(BASE.replace('mail.example.com', 'mail.example.com.')).mx).to.deep.equal(['mail.example.com.']);
        });
    });

    describe('strict mode', () => {
        const opts = { strict: true };

        it('requires case-sensitive field names and mode values', () => {
            expect(errorCode(BASE.replace('enforce', 'ENFORCE'), opts)).to.equal('invalid_sts_mode');
            expect(errorCode(BASE.replace('mode:', 'MODE:'), opts)).to.equal('invalid_sts_mode');
            expect(errorCode(BASE.replace('mode:', 'mode :'), opts)).to.equal('invalid_sts_mode');
            expect(errorCode('﻿' + BASE, opts)).to.equal('invalid_sts_version');
        });

        it('requires max_age to be 1*10DIGIT', () => {
            for (let value of ['1e3', '0x10', '12.5', '+5', '-0', '', '00000000060', ' 5 5']) {
                expect(errorCode(BASE.replace('604800', value), opts), value).to.equal('invalid_sts_max_age');
            }
            expect(parsePolicy(BASE.replace('604800', '0000000060'), opts).maxAge).to.equal(60);
        });

        it('requires mx values to be ["*."] Domain', () => {
            for (let value of ['foo*.example.com', '*.*.example.com', 'mail.example.com.', 'münchen.example', '-mail.example.com', 'mail_x.example.com']) {
                expect(errorCode(BASE.replace('mail.example.com', value), opts), value).to.equal('invalid_sts_mx');
            }
            expect(parsePolicy(BASE.replace('mail.example.com', '*.EXAMPLE.com'), opts).mx).to.deep.equal(['*.example.com']);
            expect(parsePolicy(BASE.replace('mail.example.com', 'xn--mnchen-3ya.example'), opts).mx).to.deep.equal(['xn--mnchen-3ya.example']);
        });

        it('allows trailing whitespace after values', () => {
            expect(parsePolicy('version: STSv1 \r\nmode:\tenforce\t\r\nmx:mail.example.com\r\nmax_age: 60  \r\n', opts)).to.deep.equal({
                mode: 'enforce',
                version: 'STSv1',
                mx: ['mail.example.com'],
                maxAge: 60
            });
        });
    });
});
