/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { dkim2Sign } = require('../../lib/dkim2/sign');
const { dkim2Verify } = require('../../lib/dkim2/verify');
const { rsaKey, generated, resolver, message, originatorOptions, signMessage, craftSignature, b64 } = require('../helpers/dkim2');
const reference = require('../helpers/dkim2-reference');

chai.config.includeStack = true;

const verify = (input, options) => dkim2Verify(input, Object.assign({ resolver: resolver() }, options || {}));

const listEnvelope = { mailFrom: 'bounce@bounces.list.example.org', rcptTo: 'member@example.net' };

// the originator sends to the list address
const originatorToList = extra => originatorOptions(Object.assign({ rcptTo: 'list@list.example.org' }, extra || {}));

const listOptions = extra =>
    Object.assign(
        {
            signingDomain: 'list.example.org',
            signatureData: [
                { selector: 'lrsa', privateKey: generated.rsa },
                { selector: 'led', privateKey: generated.ed25519 }
            ],
            mailFrom: 'bounce@bounces.list.example.org',
            rcptTo: 'member@example.net'
        },
        extra || {}
    );

// what a mailing list does to the message: a subject tag, a List-Id and a footer
const reviseForList = signed =>
    Buffer.from(
        signed
            .toString('binary')
            .replace('Subject: Hello DKIM2', 'Subject: [list] Hello DKIM2\r\nList-Id: <list.example.org>')
            .replace(/$/, '--\r\nlist footer\r\n'),
        'binary'
    );

// the original body has the lines "Hello world!", "" and "Second paragraph."
const listRecipe = { h: { subject: [{ d: [' Hello DKIM2'] }], 'list-id': [] }, b: [{ c: [1, 3] }] };

const originatorHeader = overrides => {
    let tags = Object.assign(
        {
            i: '1',
            m: '1',
            t: String(Math.floor(Date.now() / 1000)),
            d: 'example.com',
            mf: b64('<sender@example.com>'),
            rt: b64('<rcpt@example.net>'),
            s: 'rsa:rsa-sha256:'
        },
        overrides || {}
    );
    return `DKIM2-Signature: ${Object.entries(tags)
        .filter(([, value]) => value !== null)
        .map(([key, value]) => `${key}=${value}`)
        .join('; ')};`;
};

describe('DKIM2 chains', () => {
    describe('a mailing list that revises the message (Recipes, section 5)', () => {
        let listSigned;

        before(async () => {
            let signed = await signMessage(message(), originatorToList());
            listSigned = await signMessage(reviseForList(signed), listOptions({ recipe: listRecipe }));
        });

        it('passes with both signatures and both instances', async () => {
            let result = await verify(listSigned, listEnvelope);
            expect(result.status.result).to.equal('pass');
            expect(result.info).to.equal('dkim2=pass (i=1 example.com pass, i=2 list.example.org pass) header.d=example.com');
            expect(result.instances).to.deep.equal([
                { m: 1, hashes: [{ algorithm: 'sha256', header: 'pass', body: 'pass' }] },
                { m: 2, hashes: [{ algorithm: 'sha256', header: 'pass', body: 'pass' }], recipe: { headers: ['subject', 'list-id'], body: 'recipe' } }
            ]);
            expect(result.signatures.map(entry => [entry.i, entry.m, entry.signingDomain, entry.status.result])).to.deep.equal([
                [1, 1, 'example.com', 'pass'],
                [2, 2, 'list.example.org', 'pass']
            ]);
        });

        it('recreates the original with the reference Recipe implementation', async () => {
            let { fields, body } = reference.splitMessage(listSigned.toString('binary'));
            let mi = fields.filter(field => field.name === 'message-instance');
            let first = mi.find(field => reference.getTag(field.value, 'm') === '1');
            let second = mi.find(field => reference.getTag(field.value, 'm') === '2');
            let recipe = JSON.parse(Buffer.from(reference.getTag(second.value, 'r'), 'base64').toString());
            expect(recipe).to.deep.equal(listRecipe);

            let previous = reference.applyRecipe({ fields, body }, recipe);
            let [, headerHash, bodyHash] = reference.getTag(first.value, 'h').split(':');
            expect(reference.headerHash(previous.fields, 'sha256')).to.equal(headerHash);
            expect(reference.bodyHash(previous.body, 'sha256')).to.equal(bodyHash);
        });

        it('fails when the revised body is changed again', async () => {
            let changed = Buffer.from(listSigned.toString('binary').replace('list footer', 'evil footer'), 'binary');
            let result = await verify(changed, listEnvelope);
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('Message Instance m=2 body hash sha256 mismatch');
            expect(result.status.header.i).to.equal(2);
        });

        it('fails when a header field the list kept is changed', async () => {
            let changed = Buffer.from(listSigned.toString('binary').replace('Message-ID: <dkim2-test@', 'Message-ID: <other@'), 'binary');
            let result = await verify(changed, listEnvelope);
            expect(result.status.result).to.equal('fail');
            // the change shows in every instance, the first one found is reported
            expect(result.errors.map(error => error.message)).to.deep.equal([
                'Message Instance m=1 header hash sha256 mismatch',
                'Message Instance m=2 header hash sha256 mismatch'
            ]);
        });

        it('checks the envelope against the highest signature only', async () => {
            let result = await verify(listSigned, { mailFrom: 'sender@example.com', rcptTo: 'list@list.example.org' });
            expect(result.status.result).to.equal('permerror');
            expect(result.errors.map(error => error.message)).to.deep.equal([
                'DKIM2-Signature i=2 MAIL FROM sender@example.com did not match',
                'DKIM2-Signature i=2 RCPT TO list@list.example.org did not match'
            ]);
        });

        it('refuses to sign a changed message without a recipe', async () => {
            let signed = await signMessage(message(), originatorToList());
            let err = await dkim2Sign(reviseForList(signed), listOptions()).catch(err => err);
            expect(err.code).to.equal('ENORECIPE');
        });

        it('accepts a "d" value without the space after the colon, which the header hash removes', async () => {
            let signed = await signMessage(message(), originatorToList());
            let recipe = { h: { subject: [{ d: ['Hello DKIM2'] }], 'list-id': [] }, b: [{ c: [1, 3] }] };
            let revised = await signMessage(reviseForList(signed), listOptions({ recipe }));
            expect((await verify(revised, listEnvelope)).status.result).to.equal('pass');
        });

        it('refuses to sign with a recipe that does not recreate the previous instance', async () => {
            let signed = await signMessage(message(), originatorToList());
            for (let recipe of [
                { h: { subject: [{ d: ['Hello DKIM'] }], 'list-id': [] }, b: [{ c: [1, 3] }] },
                { h: { subject: [{ d: [' Hello DKIM2'] }] }, b: [{ c: [1, 3] }] },
                { h: { subject: [{ d: [' Hello DKIM2'] }], 'list-id': [] }, b: [{ c: [1, 2] }] },
                { h: { subject: [{ d: [' Hello DKIM2'] }], 'list-id': [] } }
            ]) {
                let err = await dkim2Sign(reviseForList(signed), listOptions({ recipe })).catch(err => err);
                expect(err.code).to.equal('EINVALIDRECIPE');
            }

            let err = await dkim2Sign(reviseForList(signed), listOptions({ recipe: { h: { subject: [{ c: [1, 5] }] } } })).catch(err => err);
            expect(err.code).to.equal('EINVALIDRECIPE');
        });

        it('passes with a null body Recipe, and reports the earlier body as unknown', async () => {
            let signed = await signMessage(message(), originatorToList());
            let replaced = Buffer.from(signed.toString('binary').replace(/Hello world![\s\S]*$/, 'Replaced body\r\n'), 'binary');
            let revised = await signMessage(replaced, listOptions({ recipe: { b: null } }));
            let result = await verify(revised, listEnvelope);
            expect(result.status.result).to.equal('pass');
            expect(result.instances[0].hashes[0].body).to.equal('unknown');
            expect(result.instances[1].recipe).to.deep.equal({ headers: [], body: 'unrecoverable' });
        });

        it('fails a revision that removes a header field despite donotmodify', async () => {
            let signed = await signMessage(message(), originatorToList({ flags: ['donotmodify'] }));
            let revised = await signMessage(reviseForList(signed), listOptions({ recipe: listRecipe }));
            let result = await verify(revised, listEnvelope);
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('Message has been modified despite a donotmodify request');
            expect(result.status.header).to.deep.equal({ d: 'example.com' });
        });

        it('passes a revision that only adds a header field despite donotmodify', async () => {
            let signed = await signMessage(message(), originatorToList({ flags: ['donotmodify'] }));
            let added = Buffer.from(signed.toString('binary').replace('Subject: Hello DKIM2', 'Subject: Hello DKIM2\r\nList-Id: <list.example.org>'), 'binary');
            let revised = await signMessage(added, listOptions({ recipe: { h: { 'list-id': [] } } }));
            let result = await verify(revised, listEnvelope);
            expect(result.status.result).to.equal('pass');
        });

        it('fails a revision that changes only the body, or replaces a header field, despite donotmodify', async () => {
            let signed = await signMessage(message(), originatorToList({ flags: ['donotmodify'] }));

            let footer = Buffer.from(signed.toString('binary') + '--\r\nfooter\r\n', 'binary');
            let bodyOnly = await signMessage(footer, listOptions({ recipe: { b: [{ c: [1, 3] }] } }));
            expect((await verify(bodyOnly, listEnvelope)).status.comment).to.equal('Message has been modified despite a donotmodify request');

            let replaced = Buffer.from(signed.toString('binary').replace('Subject: Hello DKIM2', 'Subject: Changed'), 'binary');
            let headerOnly = await signMessage(replaced, listOptions({ recipe: { h: { subject: [{ d: ['Hello DKIM2'] }] } } }));
            expect((await verify(headerOnly, listEnvelope)).status.comment).to.equal('Message has been modified despite a donotmodify request');

            let unknownBody = await signMessage(footer, listOptions({ recipe: { b: null } }));
            expect((await verify(unknownBody, listEnvelope)).status.comment).to.equal('Message has been modified despite a donotmodify request');
        });

        it('recreates a body through a body Recipe that follows a null body Recipe', async () => {
            let signed = await signMessage(message(), originatorToList());
            let replaced = Buffer.from(signed.toString('binary').replace(/Hello world![\s\S]*$/, 'New body\r\n'), 'binary');
            let first = await signMessage(replaced, listOptions({ rcptTo: 'list@list.example.org', recipe: { b: null } }));
            let footer = Buffer.from(first.toString('binary') + 'footer\r\n', 'binary');
            let second = await signMessage(footer, listOptions({ recipe: { b: [{ c: [1, 1] }] } }));
            let result = await verify(second, listEnvelope);
            expect(result.status.result).to.equal('pass');
            expect(result.instances.map(entry => entry.hashes[0].body)).to.deep.equal(['unknown', 'pass', 'pass']);
        });

        it('fails an exploded message despite donotexplode', async () => {
            let signed = await signMessage(message(), originatorToList({ flags: ['donotexplode', 'feedback'] }));
            let forwarded = await signMessage(signed, listOptions({ flags: ['exploded'] }));
            let result = await verify(forwarded, listEnvelope);
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('Message has been exploded despite a donotexplode request');
            expect(result.signatures[0].flags).to.deep.equal(['donotexplode', 'feedback']);
        });

        it('forwards an unchanged message without a new Message-Instance', async () => {
            let signed = await signMessage(message(), originatorToList());
            let result = await dkim2Sign(signed, listOptions());
            expect(result.messageInstance).to.equal(null);
            expect(result.i).to.equal(2);
            expect(result.m).to.equal(1);

            let verified = await verify(Buffer.concat([Buffer.from(result.signatures), signed]), listEnvelope);
            expect(verified.status.result).to.equal('pass');
        });
    });

    describe('chain of custody (sections 9.2 to 9.4 and 11.4)', () => {
        it('compares the local part exactly and the domain without case', async () => {
            let signed = await signMessage(message(), originatorOptions({ mailFrom: 'Sender@Example.COM', rcptTo: ['Rcpt@example.net', 'two@example.org'] }));

            let pass = await verify(signed, { mailFrom: '<Sender@example.com>', rcptTo: ['Rcpt@EXAMPLE.NET'] });
            expect(pass.status.result).to.equal('pass');

            let fail = await verify(signed, { mailFrom: 'sender@example.com', rcptTo: ['rcpt@example.net'] });
            expect(fail.status.result).to.equal('permerror');
            expect(fail.errors.map(error => error.message)).to.deep.equal([
                'DKIM2-Signature i=1 MAIL FROM sender@example.com did not match',
                'DKIM2-Signature i=1 RCPT TO rcpt@example.net did not match'
            ]);
            expect(fail.info).to.match(/^dkim2=permerror \(i=1 example\.com permerror; DKIM2-Signature i=1 MAIL FROM sender@example\.com did not match\)/);
        });

        it('signs and verifies the null reverse-path', async () => {
            let signed = await signMessage(message(), originatorOptions({ mailFrom: '' }));
            expect((await verify(signed, { mailFrom: '', rcptTo: 'rcpt@example.net' })).status.result).to.equal('pass');
            expect((await verify(signed, { mailFrom: '<>' })).status.result).to.equal('pass');
            expect((await verify(signed, { mailFrom: 'sender@example.com' })).status.result).to.equal('permerror');
        });

        it('accepts a MAIL FROM in a subdomain of d= (section 9.4)', async () => {
            let signed = await signMessage(message(), originatorOptions({ mailFrom: 'bounces+123@mail.example.com' }));
            expect((await verify(signed, { mailFrom: 'bounces+123@mail.example.com' })).status.result).to.equal('pass');
        });

        it('refuses to sign when d= does not match the MAIL FROM domain', async () => {
            for (let mailFrom of ['sender@example.org', 'sender@notexample.com']) {
                let err = await dkim2Sign(message(), originatorOptions({ mailFrom })).catch(err => err);
                expect(err.code).to.equal('EINVALIDDOMAIN');
            }
        });

        it('reports a forged signature where d= does not match mf=', async () => {
            let forged = craftSignature(
                message([
                    'Message-Instance: m=1; h=' +
                        'sha256:' +
                        reference.headerHash(reference.splitMessage(message().toString()).fields, 'sha256') +
                        ':' +
                        reference.bodyHash(reference.splitMessage(message().toString()).body, 'sha256')
                ]),
                originatorHeader({ mf: b64('<sender@example.org>') }),
                { rsa: rsaKey }
            );
            let result = await verify(forged);
            expect(result.status.result).to.equal('permerror');
            expect(result.errors.map(error => error.message)).to.deep.equal(['DKIM2-Signature i=1 MAIL FROM and d= do not match']);
        });

        it('refuses to sign a hop that does not continue the chain', async () => {
            let signed = await signMessage(message(), originatorOptions());
            // the message went to rcpt@example.net, so list.example.org can not be the next hop
            let err = await dkim2Sign(signed, listOptions()).catch(err => err);
            expect(err.code).to.equal('ECUSTODY');
        });

        it('reports a broken link between two hops', async () => {
            let signed = await signMessage(message(), originatorOptions());
            let forged = craftSignature(
                signed,
                originatorHeader({
                    i: '2',
                    d: 'list.example.org',
                    mf: b64('<bounce@list.example.org>'),
                    rt: b64('<member@example.net>'),
                    s: 'lrsa:rsa-sha256:'
                }),
                { lrsa: generated.rsa }
            );
            let result = await verify(forged, listEnvelope);
            expect(result.status.result).to.equal('permerror');
            expect(result.errors.map(error => error.message)).to.deep.equal([
                'DKIM2-Signature i=2 MAIL FROM <bounce@list.example.org> did not match',
                'DKIM2-Signature i=2 MAIL FROM bounce@bounces.list.example.org did not match'
            ]);
        });

        it('follows an imaginary hop documented with nd= (section 9.3)', async () => {
            let signed = await signMessage(message(), originatorToList());
            let withNd = await signMessage(signed, listOptions({ mailFrom: undefined, rcptTo: undefined, nextDomain: 'fwd.example.net' }));
            let forwarded = await signMessage(withNd, {
                signingDomain: 'fwd.example.net',
                selector: 'frsa',
                privateKey: generated.rsa,
                mailFrom: 'bounce@fwd.example.net',
                rcptTo: 'member@example.net'
            });

            let result = await verify(forwarded, { mailFrom: 'bounce@fwd.example.net', rcptTo: 'member@example.net' });
            expect(result.status.result).to.equal('pass');
            expect(result.signatures[1].nextDomain).to.equal('fwd.example.net');
            expect(result.signatures[1]).to.not.have.property('mailFrom');

            // without the next hop, the message can not be accepted from the SMTP envelope alone
            let trailing = await verify(withNd, { mailFrom: 'bounce@fwd.example.net', rcptTo: 'member@example.net' });
            expect(trailing.status.result).to.equal('permerror');
            expect(trailing.status.comment).to.equal('DKIM2-Signature i=2 unexpected nd= tag');

            // and is fine when the envelope is not checked
            expect((await verify(withNd)).status.result).to.equal('pass');
        });

        it('refuses and reports a next signature that is not from the nd= domain', async () => {
            let signed = await signMessage(message(), originatorToList());
            let withNd = await signMessage(signed, listOptions({ mailFrom: undefined, rcptTo: undefined, nextDomain: 'fwd.example.net' }));

            let err = await dkim2Sign(withNd, {
                signingDomain: 'example.net',
                selector: 'frsa',
                privateKey: generated.rsa,
                mailFrom: 'bounce@example.net',
                rcptTo: 'member@example.net'
            }).catch(err => err);
            expect(err.code).to.equal('ECUSTODY');

            let forged = craftSignature(
                withNd,
                originatorHeader({ i: '3', m: '1', d: 'example.net', mf: b64('<bounce@example.net>'), rt: b64('<member@example.net>'), s: 'frsa:rsa-sha256:' }),
                { frsa: generated.rsa }
            );
            let result = await verify(forged);
            expect(result.status.result).to.equal('permerror');
            expect(result.status.comment).to.equal('DKIM2-Signature i=2 MAIL nd= does not match');
        });

        it('rejects nd= together with mf= or rt=', async () => {
            let err = await dkim2Sign(message(), originatorOptions({ nextDomain: 'fwd.example.net' })).catch(err => err);
            expect(err.code).to.equal('EINVALIDOPTS');
        });
    });

    describe('replay (section 11.9)', () => {
        it('reports a duplicate without an exploded flag', async () => {
            let seen = new Set();
            let checkReplay = async ({ key }) => {
                let duplicate = seen.has(key);
                seen.add(key);
                return duplicate;
            };

            let signed = await signMessage(message(), originatorOptions());
            expect((await verify(signed, { checkReplay })).status.result).to.equal('pass');
            let second = await verify(signed, { checkReplay });
            expect(second.status.result).to.equal('fail');
            expect(second.status.comment).to.equal('Duplicate message with no exploded flag');
            expect(second.status.header).to.deep.equal({ d: 'example.com' });
            expect(second.replay.key).to.match(/^sha256:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/);
            expect(second.replay.exploded).to.be.false;
        });

        it('allows copies of an exploded message', async () => {
            let signed = await signMessage(message(), originatorOptions({ flags: ['exploded'] }));
            let result = await verify(signed, { checkReplay: async () => true });
            expect(result.status.result).to.equal('pass');
            expect(result.replay.exploded).to.be.true;
        });
    });
});
