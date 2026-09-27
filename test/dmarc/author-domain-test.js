/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const { getAuthorDomain, getAddressDomains } = require('../../lib/dmarc/author-domain');

chai.config.includeStack = true;

const domainsOf = address => getAddressDomains(address).map(entry => entry.authorDomain);

describe('DMARC Author Domain extraction (RFC 9989 5.3.1, RFC 5322 3.4.1)', () => {
    describe('Single address', () => {
        it('Should take the domain of a plain addr-spec', () => {
            expect(domainsOf('user@example.com')).to.deep.equal(['example.com']);
        });

        it('Should ignore an "@" inside a quoted local-part', () => {
            expect(domainsOf('"ceo@x"@victim.example')).to.deep.equal(['victim.example']);
            expect(domainsOf('"a\\"@b"@victim.example')).to.deep.equal(['victim.example']);
            // the address parser moves the space into the quoted string
            expect(domainsOf('"ceo@x "@ victim.example')).to.deep.equal(['victim.example']);
        });

        it('Should drop an obsolete source route', () => {
            expect(domainsOf('@relay.example:ceo@bank.example')).to.deep.equal(['bank.example']);
            expect(domainsOf('@r1.example,@r2.example:ceo@bank.example')).to.deep.equal(['bank.example']);
            expect(domainsOf('@[IPv6:::1]:ceo@bank.example')).to.deep.equal(['bank.example']);
        });

        it('Should still see the domain when a quoted string is not terminated', () => {
            expect(domainsOf('"ceo@victim.example')).to.deep.equal(['victim.example']);
        });

        it('Should return every candidate for an address with several unquoted "@" signs', () => {
            expect(domainsOf('ceo@victim.example@attacker.test')).to.deep.equal(['victim.example', 'attacker.test']);
        });

        it('Should normalize case, trailing dot and U-labels', () => {
            expect(getAddressDomains('A@EXAMPLE.COM.')).to.deep.equal([{ domain: 'example.com.', authorDomain: 'example.com' }]);
            expect(domainsOf('a@bücher.example')).to.deep.equal(['xn--bcher-kva.example']);
        });

        it('Should keep a domain literal and an "@" inside it', () => {
            expect(domainsOf('a@[192.0.2.1]')).to.deep.equal(['[192.0.2.1]']);
            expect(domainsOf('a@[x@y]')).to.deep.equal(['[x@y]']);
        });

        it('Should find no domain in an address without one', () => {
            for (let address of ['u@', 'u@.', '@', 'u@ ', '"@victim.example"', 'u@exa"mple.com', '', null, undefined, 42]) {
                expect(domainsOf(address), String(address)).to.deep.equal([]);
            }
        });

        it('Should accept a bare domain, as dmarc() always has', () => {
            expect(domainsOf('Example.COM')).to.deep.equal(['example.com']);
        });
    });

    describe('Header field', () => {
        it('Should accept several mailboxes in one domain', () => {
            expect(getAuthorDomain(['a@example.com', 'b@EXAMPLE.com', 'c@example.com.'])).to.deep.equal({
                domain: 'example.com',
                authorDomain: 'example.com',
                mailboxes: 3
            });
        });

        it('Should report several domains', () => {
            expect(getAuthorDomain(['a@example.com', 'b@example.net'])).to.deep.equal({
                reason: 'multiple-author-domains',
                domains: ['example.com', 'example.net'],
                mailboxes: 2
            });
            expect(getAuthorDomain('ceo@victim.example@attacker.test').reason).to.equal('multiple-author-domains');
        });

        it('Should report a missing domain', () => {
            for (let headerFrom of [[], 'u@', ['u@.'], undefined]) {
                expect(getAuthorDomain(headerFrom).reason, JSON.stringify(headerFrom)).to.equal('no-author-domain');
            }
        });

        it('Should not skip a mailbox without a usable domain next to one with a domain', () => {
            // the domain a reader sees for "ceo@bank.example;" is unknown, so dropping that
            // mailbox and evaluating only the other one would pick an Author Domain at random
            for (let headerFrom of [
                ['u@', 'ceo@victim.example'],
                ['ceo@bank.example;', 'a@evil.example']
            ]) {
                let author = getAuthorDomain(headerFrom);
                expect(author.authorDomain, JSON.stringify(headerFrom)).to.not.exist;
                expect(author.reason, JSON.stringify(headerFrom)).to.equal('invalid-author-domain');
            }
        });

        it('Should not merge the addresses of several From header fields', () => {
            // RFC 5322 allows one From field. DKIM signs the bottom-most one (RFC 6376 5.4.2)
            // while a mail client may show the top one, so a same-domain pair is no Author Domain
            let author = getAuthorDomain(['security@bank.example', 'news@bank.example'], 2);
            expect(author.authorDomain).to.not.exist;
            expect(author.reason).to.equal('multiple-from-fields');
            expect(author.domains).to.deep.equal(['bank.example']);

            expect(getAuthorDomain(['a@bank.example', 'b@bank.example'], 1).authorDomain).to.equal('bank.example');
        });
    });
});
