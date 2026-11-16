/* eslint @typescript-eslint/no-unused-expressions:0 */
// Behavior that draft-ietf-dkim-dkim2-spec-09 added or changed: Authentic From header fields and the
// Domain Policy Record, the "," and "|" groups of h= and s=, ML-DSA-44, and the direction of the
// relaxed domain match in the chain of custody

import { describe, it } from 'node:test';
import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { expect, config } from 'chai';

import { dkim2Sign } from '../../src/dkim2/sign.js';
import { dkim2Verify } from '../../src/dkim2/verify.js';
import { parseSignature, parseMessageInstance, formatSignature, formatMessageInstance } from '../../src/dkim2/fields.js';
import { matchFrom, checkAuthentic } from '../../src/dkim2/from.js';
import { Dkim2Verifier } from '../../src/dkim2/dkim2-verifier.js';
import { supportsMlDsa, verifySignature } from '../../src/dkim2/algorithms.js';
import { canonicalHeaderField } from '../../src/dkim2/fields.js';
import { rsaKey, ed25519Key, generated, keyRecord, resolver, message, originatorOptions, signMessage, craftSignature, b64 } from '../helpers/dkim2.js';
import * as reference from '../helpers/dkim2-reference.js';
import type { Zone } from '../helpers/dns-zone.js';

config.includeStack = true;

const rsaOnly = (extra?: any) => originatorOptions(Object.assign({ signatureData: [{ selector: 'rsa', privateKey: rsaKey }] }, extra || {}));

// the test message with another From header field, or none for null
const withFrom = (from: string | null, body?: string) => {
    let input = message([], body).toString('binary');
    input = from === null ? input.replace(/^From: .*\r\n/m, '') : input.replace(/^From: .*$/m, `From: ${from}`);
    return Buffer.from(input, 'binary');
};

// a resolver that fails the lookups of some names with a DNS error code, and records every query
const failing = (codes: Record<string, string>, zone?: Zone) => {
    let base = resolver(zone);
    let queries: string[] = [];
    let lookup = async (name: string, type: string) => {
        queries.push(name);
        if (codes[name]) {
            let err: any = new Error(codes[name]);
            err.code = codes[name];
            throw err;
        }
        return base(name, type);
    };
    return Object.assign(lookup, { queries });
};

// the From of a message as the hash sees it
const fromFields = (value: string) => [canonicalHeaderField(`From: ${value}`)];

// A message signed by the reference code with any d=, so that the verifier sees a From the
// library signer refuses to sign
const crafted = (input: Buffer, signingDomain: string, selector = 'lrsa', key: any = generated.rsa) => {
    let { fields, body } = reference.splitMessage(input.toString('binary'));
    let instance = `Message-Instance: m=1; h=sha256:${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')}`;
    let header = `DKIM2-Signature: i=1; m=1; t=${Math.floor(Date.now() / 1000)}; d=${signingDomain}; mf=${b64('<>')}; rt=${b64('<rcpt@example.net>')}; s=${selector}:rsa-sha256:;`;
    return craftSignature(Buffer.concat([Buffer.from(`${instance}\r\n`), input]), header, { [selector]: key });
};

describe('DKIM2 draft-ietf-dkim-dkim2-spec-09', () => {
    describe('the relaxed domain match for From (section 7.1 item 3)', () => {
        it('matches the From domain with d= in both directions', () => {
            expect(matchFrom(fromFields('a@example.com'), 'example.com')).to.deep.equal({ status: 'direct', domain: 'example.com' });
            expect(matchFrom(fromFields('a@Mail.Example.COM'), 'example.com')).to.deep.equal({ status: 'direct', domain: 'mail.example.com' });
            expect(matchFrom(fromFields('a@example.com'), 'mail.example.com')).to.deep.equal({ status: 'upward', domain: 'example.com' });
            // sibling domains never match, nor do domains that only share a suffix
            expect(matchFrom(fromFields('a@one.example.com'), 'two.example.com')).to.deep.equal({ status: 'fail', message: 'matching From is not authentic' });
            expect(matchFrom(fromFields('a@notexample.com'), 'example.com').status).to.equal('fail');
            expect(matchFrom(fromFields('a@example.com'), 'notexample.com').status).to.equal('fail');
        });

        it('compares the A-label of an internationalized From domain (section 18)', () => {
            expect(matchFrom([Buffer.from('from:a@bücher.example\r\n', 'utf8')], 'xn--bcher-kva.example')).to.deep.equal({
                status: 'direct',
                domain: 'xn--bcher-kva.example'
            });
        });

        for (let [label, fields, message] of [
            ['two addresses', fromFields('a@example.com, b@example.com'), 'From has more than one address'],
            ['two addresses of one domain in a group', fromFields('team: a@example.com, b@example.com;'), 'From has more than one address'],
            ['two From header fields', [...fromFields('a@example.com'), ...fromFields('a@example.com')], 'From has more than one address'],
            ['a domain literal', fromFields('a@[192.0.2.1]'), 'From uses a domain literal'],
            ['no From header field', [], 'matching From is not authentic'],
            ['an empty group', fromFields('undisclosed-recipients:;'), 'matching From is not authentic'],
            ['a From that is not RFC 5322 syntax', fromFields('<a@example.com> trailing text'), 'matching From is not authentic'],
            ['a From without an address', fromFields('just a name'), 'matching From is not authentic'],
            ['a From whose domain is only the root', fromFields('a@.'), 'matching From is not authentic'],
            ['a From whose domain has a space', fromFields('"a"@exa mple.com'), 'matching From is not authentic'],
            // the parser accepts the zero width space as atom text, it is not valid in a domain
            ['a From whose domain has an invisible character', [Buffer.from('from:a@exa\u200bmple.com\r\n', 'utf8')], 'matching From is not authentic']
        ] as [string, Buffer[], string][]) {
            it(`can never make ${label} Authentic (section 11)`, () => {
                expect(matchFrom(fields, 'example.com')).to.deep.equal({ status: 'fail', message });
            });
        }
    });

    describe('Authentic From header fields (sections 11 and 14.8)', () => {
        it('passes a From in d= or one of its subdomains without a policy lookup', async () => {
            for (let from of ['Sender <sender@example.com>', 'sender@news.example.com', '"x@other.example" <sender@EXAMPLE.com>']) {
                let signed = await signMessage(withFrom(from), rsaOnly());
                let zone = failing({});
                let result = await dkim2Verify(signed, { resolver: zone });
                expect(result.status.result, from).to.equal('pass');
                expect(zone.queries).to.deep.equal(['rsa._domainkey.example.com']);
            }
        });

        it('fails a From that d= does not match', async () => {
            let result = await dkim2Verify(crafted(withFrom('ceo@example.com'), 'list.example.org'), { resolver: resolver() });
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('DKIM2-Signature i=1 matching From is not authentic');
            expect(result.status.header).to.deep.equal({ d: 'list.example.org', i: 1 });
            expect(result.signatures[0].status).to.deep.equal({ result: 'fail', comment: 'DKIM2-Signature i=1 matching From is not authentic' });
        });

        for (let [label, from, comment] of [
            ['several addresses', 'a@list.example.org, b@list.example.org', 'From has more than one address'],
            ['a domain literal', 'a@[192.0.2.1]', 'From uses a domain literal'],
            ['no From', null, 'matching From is not authentic']
        ] as [string, string | null, string][]) {
            it(`fails a message with ${label}`, async () => {
                let result = await dkim2Verify(crafted(withFrom(from), 'list.example.org'), { resolver: resolver() });
                expect(result.status.result).to.equal('fail');
                expect(result.errors.map(error => error.message)).to.deep.equal([`DKIM2-Signature i=1 ${comment}`]);
            });
        }

        it('fails two From header fields', async () => {
            let input = Buffer.from(withFrom('a@list.example.org').toString('binary').replace('To: ', 'From: a@list.example.org\r\nTo: '), 'binary');
            let result = await dkim2Verify(crafted(input, 'list.example.org'), { resolver: resolver() });
            expect(result.errors.map(error => error.message)).to.deep.equal(['DKIM2-Signature i=1 From has more than one address']);
        });

        describe('a subdomain that signs for its parent (sections 3.8 and 11.1)', () => {
            // mail.example.org signs for a From in example.org
            const zone = (policy?: string[][]): Zone =>
                Object.assign(
                    { 'lrsa._domainkey.mail.example.org': { TXT: [[keyRecord(generated.rsa)]] } },
                    policy ? { '_domainkey.example.org': { TXT: policy } } : {}
                );
            const signedBySubdomain = () => crafted(withFrom('a@example.org'), 'mail.example.org');

            for (let [label, policy] of [
                ['there is no Domain Policy Record', undefined],
                ['the record has no f= tag', [['v=DKIM1']]],
                ['the record has no strict flag', [['v=DKIM1; f=relaxed:other']]],
                ['the strict flag is in another case', [['v=DKIM1; f=Strict']]],
                ['only records that do not begin with v=DKIM1 have it', [['f=strict; v=DKIM1'], ['v=spf1 -all'], ['v=DKIM2; f=strict']]],
                ['only a key record that does not begin with v= has it', [['k=rsa; f=strict; p=AAAA']]]
            ] as [string, string[][] | undefined][]) {
                it(`passes when ${label}`, async () => {
                    let lookups = failing({}, zone(policy));
                    let result = await dkim2Verify(signedBySubdomain(), { resolver: lookups });
                    expect(result.status.result, result.status.comment).to.equal('pass');
                    expect(lookups.queries.filter(name => name === '_domainkey.example.org')).to.have.length(1);
                });
            }

            for (let [label, policy, result, comment] of [
                ['the record has the strict flag', [['v=DKIM1; f=strict']], 'fail', 'From example.org forbids subdomain signing'],
                ['the strict flag is one of several', [['v=DKIM1; f = other : strict ; p=']], 'fail', 'From example.org forbids subdomain signing'],
                ['the record is split into strings', [['v=DKIM1; f=st', 'rict']], 'fail', 'From example.org forbids subdomain signing'],
                ['there are two records', [['v=DKIM1; f=strict'], ['v=DKIM1']], 'permerror', 'multiple records for example.org policy'],
                ['the record is broken', [['v=DKIM1; f=strict; f=other']], 'permerror', 'policy for example.org has a syntax error']
            ] as [string, string[][], string, string][]) {
                it(`gives ${result} when ${label}`, async () => {
                    let verified = await dkim2Verify(signedBySubdomain(), { resolver: resolver(zone(policy)) });
                    expect(verified.status.result).to.equal(result);
                    expect(verified.status.comment).to.equal(`DKIM2-Signature i=1 ${comment}`);
                });
            }

            it('gives TEMPERROR when the record can not be fetched, and passes without a record', async () => {
                let temp = await dkim2Verify(signedBySubdomain(), { resolver: failing({ '_domainkey.example.org': 'ETIMEOUT' }, zone()) });
                expect(temp.status.result).to.equal('temperror');
                expect(temp.status.comment).to.equal('DKIM2-Signature i=1 policy for example.org unavailable');

                for (let code of ['ENOTFOUND', 'ENODATA']) {
                    let none = await dkim2Verify(signedBySubdomain(), { resolver: failing({ '_domainkey.example.org': code }, zone()) });
                    expect(none.status.result).to.equal('pass');
                }
            });

            it('looks up the record of a From domain once, however many instances use it', async () => {
                // m=1 and m=2 have different From fields in the same domain, both signed by the subdomain
                let input = withFrom('a@example.org');
                let first = reference.splitMessage(input.toString('binary'));
                let changed = Buffer.from(input.toString('binary').replace('From: a@example.org', 'From: b@example.org'), 'binary');
                let second = reference.splitMessage(changed.toString('binary'));
                let recipe = { h: { from: [{ d: [' a@example.org'] }] } };
                let instances = [
                    `Message-Instance: m=2; h=sha256:${reference.headerHash(second.fields, 'sha256')}:${reference.bodyHash(second.body, 'sha256')}; r=${b64(JSON.stringify(recipe))}`,
                    `Message-Instance: m=1; h=sha256:${reference.headerHash(first.fields, 'sha256')}:${reference.bodyHash(first.body, 'sha256')}`
                ];
                let header = `DKIM2-Signature: i=1; m=2; t=${Math.floor(Date.now() / 1000)}; d=mail.example.org; mf=${b64('<>')}; rt=${b64('<rcpt@example.net>')}; s=lrsa:rsa-sha256:;`;
                let signed = craftSignature(Buffer.concat([Buffer.from(instances.join('\r\n') + '\r\n'), changed]), header, { lrsa: generated.rsa });

                let lookups = failing({}, zone([['v=DKIM1; f=strict']]));
                let result = await dkim2Verify(signed, { resolver: lookups });
                expect(result.status.result).to.equal('fail');
                expect(result.errors.map(error => error.message)).to.deep.equal([
                    'DKIM2-Signature i=1 From example.org forbids subdomain signing',
                    'DKIM2-Signature i=1 From example.org forbids subdomain signing'
                ]);
                expect(lookups.queries.filter(name => name === '_domainkey.example.org')).to.have.length(1);
            });

            it('does not inherit a policy up or down the DNS tree', async () => {
                // a strict record of the parent of the From domain does not apply
                let parent = Object.assign(zone(), { '_domainkey.org': { TXT: [['v=DKIM1; f=strict']] } });
                expect((await dkim2Verify(signedBySubdomain(), { resolver: resolver(parent) })).status.result).to.equal('pass');
                // nor one of the signing domain
                let child = Object.assign(zone(), { '_domainkey.mail.example.org': { TXT: [['v=DKIM1; f=strict']] } });
                expect((await dkim2Verify(signedBySubdomain(), { resolver: resolver(child) })).status.result).to.equal('pass');
            });

            it('looks up the record of an internationalized From domain by its A-label (section 18)', async () => {
                let lookups = failing(
                    {},
                    {
                        'lrsa._domainkey.mail.xn--bcher-kva.example': { TXT: [[keyRecord(generated.rsa)]] },
                        '_domainkey.xn--bcher-kva.example': { TXT: [['v=DKIM1; f=strict']] }
                    }
                );
                let input = Buffer.from(withFrom('a@bücher.example').toString('binary'), 'binary');
                let utf8 = Buffer.from(input.toString('binary').replace('bücher', 'bÃ¼cher'), 'binary');
                let result = await dkim2Verify(crafted(utf8, 'mail.xn--bcher-kva.example'), { resolver: lookups });
                expect(result.status.comment).to.equal('DKIM2-Signature i=1 From xn--bcher-kva.example forbids subdomain signing');
                expect(lookups.queries).to.include('_domainkey.xn--bcher-kva.example');
            });
        });

        describe('a From that a later hop changed (section 11)', () => {
            const listEnvelope = { mailFrom: 'bounce@list.example.org', rcptTo: 'member@example.net' };
            const listOptions = (extra?: any) =>
                Object.assign(
                    {
                        signingDomain: 'list.example.org',
                        selector: 'lrsa',
                        privateKey: generated.rsa,
                        mailFrom: 'bounce@list.example.org',
                        rcptTo: 'member@example.net'
                    },
                    extra || {}
                );
            const rewriteFrom = (signed: Buffer, from: string) =>
                Buffer.from(signed.toString('binary').replace('From: Sender <sender@example.com>', `From: ${from}`), 'binary');
            const fromRecipe = { h: { from: [{ d: [' Sender <sender@example.com>'] }] } };

            it('checks the new From against the signature of the hop that changed it', async () => {
                let signed = await signMessage(message(), originatorOptions({ rcptTo: 'list@list.example.org' }));
                let revised = await signMessage(rewriteFrom(signed, '"Sender via List" <list@list.example.org>'), listOptions({ recipe: fromRecipe }));
                let lookups = failing({});
                let result = await dkim2Verify(revised, Object.assign({ resolver: lookups }, listEnvelope));
                expect(result.status.result, result.status.comment).to.equal('pass');
                // both From are direct matches, no policy is looked up
                expect(lookups.queries.filter(name => name.startsWith('_domainkey.'))).to.deep.equal([]);
            });

            it('fails a changed From that the signing domain of the changing hop does not match', async () => {
                let signed = await signMessage(message(), originatorOptions({ rcptTo: 'list@list.example.org' }));
                let changed = rewriteFrom(signed, 'ceo@bank.example');
                let err = await dkim2Sign(changed, listOptions({ recipe: fromRecipe })).catch(err => err);
                expect(err.code).to.equal('EFROMNOTAUTHENTIC');

                // the reference signer does it anyway
                let { fields, body } = reference.splitMessage(changed.toString('binary'));
                let instance = `Message-Instance: m=2; h=sha256:${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')}; r=${b64(JSON.stringify(fromRecipe))}`;
                let header = `DKIM2-Signature: i=2; m=2; t=${Math.floor(Date.now() / 1000)}; d=list.example.org; mf=${b64('<bounce@list.example.org>')}; rt=${b64('<member@example.net>')}; s=lrsa:rsa-sha256:;`;
                let forged = craftSignature(Buffer.concat([Buffer.from(`${instance}\r\n`), changed]), header, { lrsa: generated.rsa });
                let result = await dkim2Verify(forged, Object.assign({ resolver: resolver() }, listEnvelope));
                expect(result.status.result).to.equal('fail');
                expect(result.errors.map(error => error.message)).to.deep.equal(['DKIM2-Signature i=2 matching From is not authentic']);
                expect(result.status.header).to.deep.equal({ d: 'example.com', i: 2 });
            });

            it('does not check an unchanged From again, even when a Recipe names it', async () => {
                let signed = await signMessage(message(), originatorOptions({ rcptTo: 'list@list.example.org' }));
                let changed = Buffer.from(signed.toString('binary').replace('Subject: Hello DKIM2', 'Subject: [list] Hello DKIM2'), 'binary');
                // the From step only copies the field, the From stays the one example.com signed
                let recipe = { h: { subject: [{ d: ['Hello DKIM2'] }], from: [{ c: [1, 1] }] } };
                let revised = await signMessage(changed, listOptions({ recipe }));
                let result = await dkim2Verify(revised, Object.assign({ resolver: resolver() }, listEnvelope));
                expect(result.status.result, result.status.comment).to.equal('pass');
            });

            it('checks the From of an instance against the lowest signature that covers it', async () => {
                // i=1 covers m=1 and m=2: the originator changed its own From before signing
                let input = message();
                let first = reference.splitMessage(input.toString('binary'));
                let changed = Buffer.from(input.toString('binary').replace('From: Sender <sender@example.com>', 'From: sender@other.example'), 'binary');
                let second = reference.splitMessage(changed.toString('binary'));
                let recipe = { h: { from: [{ d: [' Sender <sender@example.com>'] }] } };
                let instances = [
                    `Message-Instance: m=2; h=sha256:${reference.headerHash(second.fields, 'sha256')}:${reference.bodyHash(second.body, 'sha256')}; r=${b64(JSON.stringify(recipe))}`,
                    `Message-Instance: m=1; h=sha256:${reference.headerHash(first.fields, 'sha256')}:${reference.bodyHash(first.body, 'sha256')}`
                ];
                let header = `DKIM2-Signature: i=1; m=2; t=${Math.floor(Date.now() / 1000)}; d=example.com; mf=${b64('<sender@example.com>')}; rt=${b64('<rcpt@example.net>')}; s=rsa:rsa-sha256:;`;
                let forged = craftSignature(Buffer.concat([Buffer.from(instances.join('\r\n') + '\r\n'), changed]), header, { rsa: rsaKey });
                let result = await dkim2Verify(forged, { resolver: resolver() });
                expect(result.status.result).to.equal('fail');
                expect(result.errors.map(error => error.message)).to.deep.equal(['DKIM2-Signature i=1 matching From is not authentic']);
            });
        });
    });

    describe('signing with an Authentic From (section 12.4)', () => {
        it('refuses a From the signing domain can never make Authentic', async () => {
            for (let [from, reason] of [
                ['ceo@bank.example', 'matching From is not authentic'],
                ['a@example.com, b@example.com', 'From has more than one address'],
                ['a@[192.0.2.1]', 'From uses a domain literal']
            ]) {
                let err = await dkim2Sign(withFrom(from), rsaOnly()).catch(err => err);
                expect(err.code, from).to.equal('EFROMNOTAUTHENTIC');
                expect(err.message).to.equal(`The From header field can not be Authentic with the signing domain example.com: ${reason}`);
            }
            let err = await dkim2Sign(withFrom(null), rsaOnly()).catch(err => err);
            expect(err.code).to.equal('EFROMNOTAUTHENTIC');
        });

        it('signs a parent From from a subdomain unless the parent forbids it', async () => {
            const options = (zone: any) => ({
                signingDomain: 'mail.example.com',
                selector: 'lrsa',
                privateKey: generated.rsa,
                mailFrom: 'bounce@mail.example.com',
                rcptTo: 'rcpt@example.net',
                resolver: zone
            });
            let zone: Zone = { 'lrsa._domainkey.mail.example.com': { TXT: [[keyRecord(generated.rsa)]] } };

            let signed = await signMessage(message(), options(resolver(zone)));
            expect((await dkim2Verify(signed, { resolver: resolver(zone) })).status.result).to.equal('pass');

            let strict = resolver(Object.assign({ '_domainkey.example.com': { TXT: [['v=DKIM1; f=strict']] } }, zone));
            let err = await dkim2Sign(message(), options(strict)).catch(err => err);
            expect(err.code).to.equal('EFROMNOTAUTHENTIC');
            expect(err.message).to.equal(
                'The From header field can not be Authentic with the signing domain mail.example.com: From example.com forbids subdomain signing'
            );

            err = await dkim2Sign(message(), options(failing({ '_domainkey.example.com': 'ESERVFAIL' }, zone))).catch(err => err);
            expect(err.code).to.equal('EFROMPOLICY');
            expect(err.message).to.match(/policy for example\.com unavailable$/);
        });

        it('checks the From of a message that has a Message-Instance but no DKIM2-Signature yet', async () => {
            // the originator added an instance itself (section 12.1 allows a Recipe on m=1)
            let input = withFrom('ceo@bank.example');
            let { fields, body } = reference.splitMessage(input.toString('binary'));
            let instance = `Message-Instance: m=1; h=sha256:${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')}\r\n`;
            let err = await dkim2Sign(Buffer.concat([Buffer.from(instance), input]), rsaOnly()).catch(err => err);
            expect(err.code).to.equal('EFROMNOTAUTHENTIC');

            let ok = await dkim2Sign(
                Buffer.concat([
                    Buffer.from(
                        instance.replace(
                            /sha256:[^:]+/,
                            `sha256:${reference.headerHash(reference.splitMessage(message().toString('binary')).fields, 'sha256')}`
                        )
                    ),
                    message()
                ]),
                rsaOnly()
            );
            expect(ok.i).to.equal(1);
            expect(ok.messageInstance).to.equal(null);
        });

        it('checks the From of a forwarder that changes it, even when the From is otherwise unchanged in later instances', async () => {
            let signed = await signMessage(message(), originatorOptions({ rcptTo: 'list@list.example.org' }));
            let changed = Buffer.from(signed.toString('binary').replace('From: Sender <sender@example.com>', 'From: sender@example.com'), 'binary');
            // the address is the same but the field changed, so the list has to make it Authentic
            let err = await dkim2Sign(changed, {
                signingDomain: 'list.example.org',
                selector: 'lrsa',
                privateKey: generated.rsa,
                mailFrom: 'bounce@list.example.org',
                rcptTo: 'member@example.net',
                recipe: { h: { from: [{ d: [' Sender <sender@example.com>'] }] } }
            }).catch(err => err);
            expect(err.code).to.equal('EFROMNOTAUTHENTIC');
        });

        it('does not look at the From when forwarding, unless the forwarder changes it', async () => {
            let signed = await signMessage(withFrom('someone@example.com'), originatorOptions({ rcptTo: 'list@list.example.org' }));
            // the From is not in list.example.org, but the list did not change it
            let forwarded = await dkim2Sign(signed, {
                signingDomain: 'list.example.org',
                selector: 'lrsa',
                privateKey: generated.rsa,
                mailFrom: 'bounce@list.example.org',
                rcptTo: 'member@example.net'
            });
            expect(forwarded.i).to.equal(2);
        });
    });

    describe('signature groups (sections 10.9 and 14.6)', () => {
        it('signs groups of keys with "|" between them, and passes on any group', async () => {
            let signed = await signMessage(
                message(),
                originatorOptions({
                    signatureData: [
                        [
                            { selector: 'rsa', privateKey: rsaKey },
                            { selector: 'ed', privateKey: ed25519Key }
                        ],
                        [{ selector: 'rsa2', privateKey: generated.rsa }]
                    ]
                })
            );
            let parsed = parseSignature(
                signed
                    .toString()
                    .split('\r\n\r\n')[0]
                    .match(/^DKIM2-Signature:.*(?:\r\n[ \t].*)*/m)![0]
            );
            expect(parsed.signatures.map(entry => [entry.selector, entry.group])).to.deep.equal([
                ['rsa', 0],
                ['ed', 0],
                ['rsa2', 1]
            ]);

            // the first group passes even without the key of the second
            let first = await dkim2Verify(signed, { resolver: resolver() });
            expect(first.status.result).to.equal('pass');
            expect(first.signatures[0].values.map(entry => [entry.selector, entry.group, entry.result])).to.deep.equal([
                ['rsa', 1, 'pass'],
                ['ed', 1, 'pass'],
                ['rsa2', 2, 'permerror']
            ]);

            // and the second group passes on its own when a key of the first is missing
            let zone = { 'rsa2._domainkey.example.com': { TXT: [[keyRecord(generated.rsa)]] }, 'ed._domainkey.example.com': { TXT: [] } };
            expect((await dkim2Verify(signed, { resolver: resolver(zone) })).status.result).to.equal('pass');

            // a group that is not complete does not pass by itself
            expect((await dkim2Verify(signed, { resolver: resolver({ 'ed._domainkey.example.com': { TXT: [] } }) })).status.result).to.equal('permerror');
        });

        it('keeps the "," and "|" punctuation in the signature input (section 12.8)', async () => {
            let signed = await signMessage(
                message(),
                originatorOptions({ signatureData: [[{ selector: 'rsa', privateKey: rsaKey }], [{ selector: 'ed', privateKey: ed25519Key }]] })
            );
            let str = signed.toString('binary');
            let input = reference.signatureInput(str, 1).toString();
            expect(input).to.match(/;s=rsa:rsa-sha256:\|ed:ed25519-sha256:;/);
            expect(reference.verifySignatureValue(str, 1, 'rsa', crypto.createPublicKey(rsaKey))).to.be.true;
            expect(reference.verifySignatureValue(str, 1, 'ed', crypto.createPublicKey(ed25519Key))).to.be.true;

            // moving a signature into the other group breaks every signature
            let regrouped = Buffer.from(str.replace(/(s=rsa:rsa-sha256:[^;|]*)\|/, '$1,'), 'binary');
            expect((await dkim2Verify(regrouped, { resolver: resolver() })).status.comment).to.equal('DKIM2-Signature i=1 selector rsa incorrect signature');
        });

        it('passes on one hash group of an instance and reports a failing one only when no group passes (section 14.7)', async () => {
            let input = message();
            let { fields, body } = reference.splitMessage(input.toString('binary'));
            let good = `sha256:${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')}`;
            let bad = `sha512:${b64(Buffer.alloc(64))}:${b64(Buffer.alloc(64))}`;
            const verifyWith = async (h: string) => {
                let signed = craftSignature(
                    Buffer.concat([Buffer.from(`Message-Instance: m=1; h=${h}\r\n`), input]),
                    `DKIM2-Signature: i=1; m=1; t=${Math.floor(Date.now() / 1000)}; d=example.com; mf=${b64('<sender@example.com>')}; rt=${b64('<rcpt@example.net>')}; s=rsa:rsa-sha256:;`,
                    { rsa: rsaKey }
                );
                return dkim2Verify(signed, { resolver: resolver() });
            };

            expect((await verifyWith(`${bad}|${good}`)).status.result).to.equal('pass');
            expect((await verifyWith(`${good}|${bad}`)).status.result).to.equal('pass');

            let both = await verifyWith(`${good},${bad}`);
            expect(both.status.result).to.equal('fail');
            expect(both.errors.map(error => error.message)).to.deep.equal([
                'Message-Instance m=1 header hash sha512 mismatch',
                'Message-Instance m=1 body hash sha512 mismatch'
            ]);
            expect(both.instances[0].hashes.map(hash => [hash.algorithm, hash.group, hash.header])).to.deep.equal([
                ['sha256', 1, 'pass'],
                ['sha512', 1, 'fail']
            ]);

            let none = await verifyWith(`${bad}|foo:${b64('x')}:${b64('x')}`);
            expect(none.status.result).to.equal('fail');
            expect(none.status.comment).to.equal('Message-Instance m=1 no group of hashes passed');

            let unknown = await verifyWith(`foo:${b64('x')}:${b64('x')}|bar:${b64('x')}:${b64('x')}`);
            expect(unknown.status.result).to.equal('permerror');
            expect(unknown.errors.map(error => error.message)).to.deep.equal([
                'Message-Instance m=1 algorithm foo unknown',
                'Message-Instance m=1 algorithm bar unknown'
            ]);
        });
    });

    describe('ML-DSA-44 (section 3.4)', { skip: !supportsMlDsa() && 'Node.js has no ML-DSA' }, () => {
        const mlDsa = () => crypto.generateKeyPairSync('ml-dsa-44' as any).privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;

        it('signs and verifies alone, and as an alternative to RSA and Ed25519', async () => {
            let pq = mlDsa();
            let zone = { 'pq._domainkey.example.com': { TXT: [[keyRecord(pq)]] } };
            expect(keyRecord(pq)).to.match(/^v=DKIM1; k=mldsa44; p=[A-Za-z0-9+/=]{1752}$/);

            let alone = await signMessage(message(), originatorOptions({ signatureData: [{ selector: 'pq', privateKey: pq }] }));
            let result = await dkim2Verify(alone, { resolver: resolver(zone) });
            expect(result.status.result, result.status.comment).to.equal('pass');
            expect(result.signatures[0].values[0]).to.deep.include({ selector: 'pq', algorithm: 'mldsa44', result: 'pass' });

            let hybrid = await signMessage(
                message(),
                originatorOptions({
                    signatureData: [
                        [
                            { selector: 'rsa', privateKey: rsaKey },
                            { selector: 'ed', privateKey: ed25519Key }
                        ],
                        [{ selector: 'pq', privateKey: pq, algorithm: 'mldsa44' }]
                    ]
                })
            );
            expect((await dkim2Verify(hybrid, { resolver: resolver(zone) })).status.result).to.equal('pass');
            // the reference reads the signature the same way
            expect(reference.verifySignatureValue(hybrid.toString('binary'), 1, 'pq', crypto.createPublicKey(pq))).to.be.true;
        });

        it('folds the 3228 character signature inside the base64string only', async () => {
            let pq = mlDsa();
            let result = await dkim2Sign(message(), originatorOptions({ signatureData: [{ selector: 'pq', privateKey: pq }] }));
            let lines = result.signature.split('\r\n');
            for (let line of lines) {
                expect(line.length).to.be.at.most(76);
            }
            let value = parseSignature(result.signature).signatures[0].signature;
            expect(value).to.have.length(3228);
            expect(Buffer.from(value, 'base64')).to.have.length(2420);
        });

        it('signs with the hedged variant, so two signatures of the same input differ', async () => {
            let pq = mlDsa();
            let options = originatorOptions({ signatureData: [{ selector: 'pq', privateKey: pq }], signTime: 1000 });
            let first = parseSignature((await dkim2Sign(message(), options)).signature).signatures[0].signature;
            let second = parseSignature((await dkim2Sign(message(), options)).signature).signatures[0].signature;
            expect(first).to.not.equal(second);
        });

        for (let [label, record, comment] of [
            ['a key that is one byte short', (raw: Buffer) => `v=DKIM1; k=mldsa44; p=${raw.subarray(1).toString('base64')}`, 'public key pq is malformed'],
            [
                'a key that is one byte long',
                (raw: Buffer) => `v=DKIM1; k=mldsa44; p=${Buffer.concat([raw, Buffer.alloc(1)]).toString('base64')}`,
                'public key pq is malformed'
            ],
            [
                'a SubjectPublicKeyInfo instead of the bare key',
                (raw: Buffer, spki: Buffer) => `v=DKIM1; k=mldsa44; p=${spki.toString('base64')}`,
                'public key pq is malformed'
            ],
            [
                'the key under k=ed25519, which is too long for Ed25519',
                (raw: Buffer) => `v=DKIM1; k=ed25519; p=${raw.toString('base64')}`,
                'public key pq is malformed'
            ],
            ['an Ed25519 key', () => keyRecord(ed25519Key), 'public key pq algorithm mismatch'],
            [
                'the composite key type of draft-ietf-dkim-dkim2-dns-02',
                (raw: Buffer) => `v=DKIM1; k=mldsa44-ed25519-sha512; p=${raw.toString('base64')}`,
                'public key pq algorithm mismatch'
            ]
        ] as [string, (raw: Buffer, spki: Buffer) => string, string][]) {
            it(`reports ${label}`, async () => {
                let pq = mlDsa();
                let spki = crypto.createPublicKey(pq).export({ type: 'spki', format: 'der' });
                let signed = await signMessage(message(), originatorOptions({ signatureData: [{ selector: 'pq', privateKey: pq }] }));
                let result = await dkim2Verify(signed, {
                    resolver: resolver({ 'pq._domainkey.example.com': { TXT: [[record(spki.subarray(-1312), spki)]] } })
                });
                expect(result.status.result).to.equal('permerror');
                expect(result.status.comment).to.equal(`DKIM2-Signature i=1 ${comment}`);
            });
        }

        it('fails a signature value that is not an ML-DSA-44 signature at all', async () => {
            let pq = mlDsa();
            let signed = await signMessage(message(), originatorOptions({ signatureData: [{ selector: 'pq', privateKey: pq }] }));
            let short = Buffer.from(signed.toString('binary').replace(/s=pq:mldsa44:[^;]+;/, `s=pq:mldsa44:${b64('short')};`), 'binary');
            let result = await dkim2Verify(short, { resolver: resolver({ 'pq._domainkey.example.com': { TXT: [[keyRecord(pq)]] } }) });
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('DKIM2-Signature i=1 selector pq incorrect signature');
        });

        it('fails a signature made without the "DKIM2" context', async () => {
            let pq = mlDsa();
            let input = message();
            let { fields, body } = reference.splitMessage(input.toString('binary'));
            let str = `DKIM2-Signature: i=1; m=1; t=${Math.floor(Date.now() / 1000)}; d=example.com; mf=${b64('<sender@example.com>')}; rt=${b64('<rcpt@example.net>')}; s=pq:mldsa44:;\r\nMessage-Instance: m=1; h=sha256:${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')}\r\n${input.toString('binary')}`;
            let signature = crypto.sign(null, reference.signatureInput(str, 1), crypto.createPrivateKey(pq)).toString('base64');
            let signed = Buffer.from(str.replace('s=pq:mldsa44:;', `s=pq:mldsa44:${signature};`), 'binary');
            let result = await dkim2Verify(signed, { resolver: resolver({ 'pq._domainkey.example.com': { TXT: [[keyRecord(pq)]] } }) });
            expect(result.status.comment).to.equal('DKIM2-Signature i=1 selector pq incorrect signature');
        });
    });

    it(
        'reports ML-DSA-44 as an unknown algorithm where Node.js has no ML-DSA (section 14.6 step 4)',
        { skip: supportsMlDsa() && 'Node.js has ML-DSA' },
        async () => {
            let input = message();
            let { fields, body } = reference.splitMessage(input.toString('binary'));
            let instance = `Message-Instance: m=1; h=sha256:${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')}\r\n`;
            const signedWith = (s: string) =>
                craftSignature(
                    Buffer.concat([Buffer.from(instance), input]),
                    `DKIM2-Signature: i=1; m=1; t=${Math.floor(Date.now() / 1000)}; d=example.com; mf=${b64('<sender@example.com>')}; rt=${b64('<rcpt@example.net>')}; s=${s};`,
                    { rsa: rsaKey }
                );
            let alone = await dkim2Verify(signedWith(`pq:mldsa44:${b64(Buffer.alloc(2420))}`), { resolver: resolver() });
            expect(alone.status.result).to.equal('permerror');
            expect(alone.status.comment).to.equal('DKIM2-Signature i=1 selector pq algorithm unknown');

            // the key of an algorithm that can not be used is never looked up, even when it is published
            let lookups = failing({}, { 'pq._domainkey.example.com': { TXT: [[`v=DKIM1; k=mldsa44; p=${b64(Buffer.alloc(1312))}`]] } });
            await dkim2Verify(signedWith(`pq:mldsa44:${b64(Buffer.alloc(2420))}`), { resolver: lookups });
            expect(lookups.queries).to.not.include('pq._domainkey.example.com');

            // an RSA alternative still passes
            let either = await dkim2Verify(signedWith(`rsa:rsa-sha256:|pq:mldsa44:${b64(Buffer.alloc(2420))}`), { resolver: resolver() });
            expect(either.status.result).to.equal('pass');
        }
    );

    describe('folding (sections 2.14, 9.3, 10.6 and 10.9)', () => {
        // no WSP next to the ":", "," and "|" of a hash-set, a sig-set or an rt= list, and none at
        // either end of a base64string
        const checkFolds = (field: string) => {
            let unfolded = field.replace(/\r\n/g, '');
            for (let tag of unfolded.slice(unfolded.indexOf(':') + 1).split(';')) {
                let [name, ...rest] = tag.trim().split('=');
                let value = rest.join('=');
                if (['h', 's', 'rt', 'mf', 'r'].includes(name)) {
                    expect(value, `${name}=`).to.not.match(/[ \t][:,|]|[:,|][ \t]|^[ \t]|[ \t]$/);
                }
            }
            for (let line of field.split('\r\n')) {
                expect(line.length).to.be.at.most(76);
            }
        };

        it('folds only where the grammar allows it, and the parser reads the result', () => {
            for (let n = 1; n < 40; n += 7) {
                let field = formatSignature({
                    i: 1,
                    m: 1,
                    t: 1,
                    signingDomain: 'example.com',
                    mailFrom: `<${'s'.repeat(n * 3)}@example.com>`,
                    rcptTo: Array.from({ length: n }, (v, index) => `<${'r'.repeat(index * 5)}@example.net>`),
                    signatures: Array.from({ length: n % 5 }, (v, index) => ({
                        selector: `sel${index}`,
                        algorithm: index % 2 ? 'ed25519-sha256' : 'rsa-sha256',
                        signature: crypto.randomBytes(64 + index * 64).toString('base64'),
                        group: index % 3 ? 0 : 1
                    })).concat([{ selector: 'last', algorithm: 'rsa-sha256', signature: crypto.randomBytes(256).toString('base64'), group: 1 }])
                });
                checkFolds(field);
                expect(parseSignature(field).error).to.equal(null);

                let instance = formatMessageInstance({
                    m: 1,
                    hashes: [
                        { algorithm: 'sha256', headerHash: crypto.randomBytes(32).toString('base64'), bodyHash: crypto.randomBytes(32).toString('base64') },
                        {
                            algorithm: 'sha512',
                            headerHash: crypto.randomBytes(64).toString('base64'),
                            bodyHash: crypto.randomBytes(64).toString('base64'),
                            group: 1
                        }
                    ],
                    recipe: { b: [{ d: ['x'.repeat(n * 10)] }] }
                });
                checkFolds(instance);
                let parsed = parseMessageInstance(instance);
                expect(parsed.error).to.equal(null);
                expect(parsed.hashes.map(hash => hash.group)).to.deep.equal([0, 1]);
            }
        });

        it('signs a message for many recipients that the strict parser accepts', async () => {
            let rcptTo = Array.from({ length: 12 }, (v, index) => `member-${index}-with-a-longer-name@example.net`);
            let result = await dkim2Sign(message(), originatorOptions({ rcptTo }));
            checkFolds(result.signature);
            checkFolds(result.messageInstance!);
            let signed = Buffer.concat([Buffer.from(result.signatures), message()]);
            expect((await dkim2Verify(signed, { resolver: resolver(), rcptTo: rcptTo[11] })).status.result).to.equal('pass');
        });
    });

    describe('the chain of custody for the null MAIL FROM and nd= (section 7.1 item 1)', () => {
        // the message was sent to list@lists.example.com
        const toList = () =>
            signMessage(message(), originatorOptions({ rcptTo: 'list@lists.example.com', signatureData: [{ selector: 'rsa', privateKey: rsaKey }] }));

        it('passes a parent of the recipient domain as d=', async () => {
            for (let extra of [{ mailFrom: '<>', rcptTo: 'member@example.net' }, { nextDomain: 'example.com' }]) {
                let first = await toList();
                let next = await signMessage(first, rsaOnly(Object.assign({ mailFrom: undefined, rcptTo: undefined }, extra)));
                let result = await dkim2Verify(next, { resolver: resolver() });
                expect(result.errors.filter(error => /rt= of i=1/.test(error.message))).to.deep.equal([]);
            }
        });

        it('fails a subdomain of the recipient domain as d=, and refuses to sign it', async () => {
            let first = await signMessage(
                message(),
                originatorOptions({ rcptTo: 'rcpt@example.com', signatureData: [{ selector: 'rsa', privateKey: rsaKey }] })
            );
            let options = {
                signingDomain: 'sub.example.com',
                selector: 'lrsa',
                privateKey: generated.rsa,
                mailFrom: '<>',
                rcptTo: 'member@example.net'
            };
            let err = await dkim2Sign(first, options).catch(err => err);
            expect(err.code).to.equal('ECUSTODY');
            expect(err.message).to.equal('The signature would break the chain of custody, its signing domain does not match a RCPT TO of DKIM2-Signature i=1');

            let input = first.toString('binary');
            let header = `DKIM2-Signature: i=2; m=1; t=${Math.floor(Date.now() / 1000)}; d=sub.example.com; mf=${b64('<>')}; rt=${b64('<member@example.net>')}; s=lrsa:rsa-sha256:;`;
            let forged = craftSignature(Buffer.from(input, 'binary'), header, { lrsa: generated.rsa });
            let result = await dkim2Verify(forged, {
                resolver: resolver({ 'lrsa._domainkey.sub.example.com': { TXT: [[keyRecord(generated.rsa)]] } })
            });
            expect(result.status.result).to.equal('fail');
            expect(result.errors.map(error => error.message)).to.deep.equal(['DKIM2-Signature i=2 d= does not match the rt= of i=1']);
        });
    });

    describe('unexpected errors', () => {
        it('treats a signature that crypto.verify() can not check as incorrect', () => {
            // an Ed25519 key for an RSA signature makes crypto.verify() throw
            let input = Buffer.from('input');
            let signature = crypto.sign('sha256', input, crypto.createPrivateKey(rsaKey));
            expect(verifySignature('rsa-sha256', input, crypto.createPublicKey(ed25519Key), signature)).to.be.false;
            expect(verifySignature('rsa-sha256', input, crypto.createPublicKey(rsaKey), signature)).to.be.true;
        });

        it('passes on errors that are not DNS results, instead of reading them as a policy or a key', async () => {
            let broken = async () => {
                throw new TypeError('resolver bug');
            };
            let err = await checkAuthentic(fromFields('a@example.org'), 'mail.example.org', broken).catch(err => err);
            expect(err).to.be.an.instanceOf(TypeError);

            let entry: any = { selector: 'rsa', algorithm: 'rsa-sha256' };
            let lookup = Promise.reject(new TypeError('lookup bug'));
            let keyErr = await new Dkim2Verifier().checkValue(entry, lookup, 'rsa-sha256', Buffer.from('x'), 'AAAA').catch(err => err);
            expect(keyErr).to.be.an.instanceOf(TypeError);
            expect(entry).to.not.have.property('result');
        });
    });

    describe('instance numbering (sections 13.2 and 14.2)', () => {
        it('reports a highest signature that does not cover the highest instance', async () => {
            let input = message();
            let { fields, body } = reference.splitMessage(input.toString('binary'));
            let hashes = `h=sha256:${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')}`;
            let t = Math.floor(Date.now() / 1000);
            let withInstances = Buffer.concat([Buffer.from(`Message-Instance: m=2; ${hashes}\r\nMessage-Instance: m=1; ${hashes}\r\n`), input]);
            let first = craftSignature(
                withInstances,
                `DKIM2-Signature: i=1; m=2; t=${t}; d=example.com; mf=${b64('<sender@example.com>')}; rt=${b64('<rcpt@example.com>')}; s=rsa:rsa-sha256:;`,
                { rsa: rsaKey }
            );
            let second = craftSignature(
                first,
                `DKIM2-Signature: i=2; m=1; t=${t}; d=example.com; mf=${b64('<rcpt@example.com>')}; rt=${b64('<x@example.net>')}; s=rsa:rsa-sha256:;`,
                { rsa: rsaKey }
            );
            let result = await dkim2Verify(second, { resolver: resolver() });
            expect(result.status.result).to.equal('permerror');
            expect(result.status.comment).to.equal('Message-Instance m=2 is not signed');
        });
    });
});
