/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

let macro = require('../../lib/spf/macro');

chai.config.includeStack = true;

describe('SPF Macro Tests', () => {
    it('Should render macro values', async () => {
        let sender = 'strong-bad@email.example.com';
        let ipv4 = '192.0.2.3';
        let ipv6 = '2001:db8::cb01';

        expect(macro('%{s}', { sender })).to.equal('strong-bad@email.example.com');
        expect(macro('%{o}', { sender })).to.equal('email.example.com');
        expect(macro('%{d}', { sender })).to.equal('email.example.com');
        expect(macro('%{d4}', { sender })).to.equal('email.example.com');
        expect(macro('%{d3}', { sender })).to.equal('email.example.com');
        expect(macro('%{d2}', { sender })).to.equal('example.com');
        expect(macro('%{d1}', { sender })).to.equal('com');
        expect(macro('%{dr}', { sender })).to.equal('com.example.email');
        expect(macro('%{d2r}', { sender })).to.equal('example.email');
        expect(macro('%{l}', { sender })).to.equal('strong-bad');
        expect(macro('%{l-}', { sender })).to.equal('strong.bad');
        expect(macro('%{lr}', { sender })).to.equal('strong-bad');
        expect(macro('%{lr-}', { sender })).to.equal('bad.strong');
        expect(macro('%{l1r-}', { sender })).to.equal('strong');

        expect(macro('%{ir}.%{v}._spf.%{d2}', { sender, ip: ipv4 })).to.equal('3.2.0.192.in-addr._spf.example.com');
        expect(macro('%{lr-}.lp._spf.%{d2}', { sender, ip: ipv4 })).to.equal('bad.strong.lp._spf.example.com');
        expect(macro('%{lr-}.lp.%{ir}.%{v}._spf.%{d2}', { sender, ip: ipv4 })).to.equal('bad.strong.lp.3.2.0.192.in-addr._spf.example.com');
        expect(macro('%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}', { sender, ip: ipv4 })).to.equal('3.2.0.192.in-addr.strong.lp._spf.example.com');
        expect(macro('%{d2}.trusted-domains.example.net', { sender, ip: ipv4 })).to.equal('example.com.trusted-domains.example.net');
        expect(macro('%{ir}.%{v}._spf.%{d2}', { sender, ip: ipv6 })).to.equal(
            '1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com'
        );
    });

    it('Should expand %{d} using the currently evaluated domain, not the sender domain', async () => {
        let sender = 'strong-bad@email.example.com';
        let domain = 'included.example.net';
        let ipv4 = '192.0.2.3';

        // %{d} follows <domain>, %{o} and %{s} stay on the sender (RFC 7208 sections 7.2, 7.3)
        expect(macro('%{d}', { sender, domain })).to.equal('included.example.net');
        expect(macro('%{d2}', { sender, domain })).to.equal('example.net');
        expect(macro('%{o}', { sender, domain })).to.equal('email.example.com');
        expect(macro('%{s}', { sender, domain })).to.equal('strong-bad@email.example.com');
        expect(macro('%{ir}.%{v}.%{d}.spf.example.org', { sender, domain, ip: ipv4 })).to.equal('3.2.0.192.in-addr.included.example.net.spf.example.org');

        // without an explicit domain, %{d} falls back to the sender domain (top-level evaluation)
        expect(macro('%{d}', { sender })).to.equal('email.example.com');
    });
});
