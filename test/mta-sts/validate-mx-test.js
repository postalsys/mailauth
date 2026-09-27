/* eslint no-unused-expressions:0 */
'use strict';

const { expect } = require('chai');
const { validateMx, parsePolicy } = require('../../lib/mta-sts');

describe('MTA-STS MX host validation (RFC 8461 4.1)', () => {
    const policy = parsePolicy(
        'version: STSv1\nmode: enforce\nmx: *.example.com\nmx: mail.example.net\nmx: xn--mnchen-3ya.example\nmx: mx.xn--e1afmkfd.example\nmax_age: 86400\n'
    );

    for (let strict of [false, true]) {
        describe(strict ? 'strict' : 'lax', () => {
            const check = mx => validateMx(mx, policy, { strict });

            it('matches a wildcard against exactly one left-most label', () => {
                expect(check('mail.example.com')).to.deep.equal({ valid: true, mode: 'enforce', match: '.example.com', testing: false });
                expect(check('MAIL.EXAMPLE.COM').valid).to.be.true;
                expect(check('example.com').valid).to.be.false;
                expect(check('foo.bar.example.com').valid).to.be.false;
                expect(check('a.b.c.example.com').valid).to.be.false;
                expect(check('.example.com').valid).to.be.false;
                expect(check('xexample.com').valid).to.be.false;
                expect(check('*.example.com').valid).to.be.false;
            });

            it('matches exact names case-insensitively only', () => {
                expect(check('mail.example.net')).to.deep.equal({ valid: true, mode: 'enforce', match: 'mail.example.net', testing: false });
                expect(check('Mail.Example.Net').valid).to.be.true;
                expect(check(' mail.example.net ').valid).to.be.true;
                expect(check('x.mail.example.net').valid).to.be.false;
                expect(check('').valid).to.be.false;
            });

            it('ignores a trailing dot on the MX name', () => {
                expect(check('mail.example.com.').valid).to.be.true;
                expect(check('mail.example.net.').valid).to.be.true;
            });

            it('converts U-label MX names to A-labels', () => {
                expect(check('münchen.example').valid).to.be.true;
                expect(check('mx.пример.example')).to.deep.equal({ valid: true, mode: 'enforce', match: 'mx.xn--e1afmkfd.example', testing: false });
            });

            it('fails closed for an enforce policy without an mx list', () => {
                expect(validateMx('b.example', { mode: 'enforce' }, { strict })).to.deep.equal({ valid: false, mode: 'enforce', testing: false });
                expect(validateMx('b.example', { mode: 'enforce', mx: 'b.example' }, { strict }).valid).to.be.false;
            });

            it('never matches invalid patterns', () => {
                let p = { mode: 'enforce', mx: ['foo*.example.com', '*', '', null] };
                expect(validateMx('foo1.example.com', p, { strict }).valid).to.be.false;
                expect(validateMx('foo', p, { strict }).valid).to.be.false;
            });

            it('reports testing and none modes', () => {
                const pt = parsePolicy('version: STSv1\nmode: testing\nmx: a.example\nmax_age: 60\n');
                expect(validateMx('b.example', pt, { strict })).to.deep.equal({ valid: false, mode: 'testing', testing: true });
                const pn = parsePolicy('version: STSv1\nmode: none\nmx: a.example\nmax_age: 60\n');
                expect(validateMx('b.example', pn, { strict })).to.deep.equal({ valid: true, mode: 'none', testing: false });
                expect(validateMx('b.example', undefined, { strict })).to.deep.equal({ valid: true, mode: 'none', testing: false });
            });
        });
    }
});
