/* eslint @typescript-eslint/no-unused-expressions:0 */
import { describe, it, before } from 'node:test';
import { Buffer } from 'node:buffer';
import { expect, config } from 'chai';

import { dkim2Sign } from '../../src/dkim2/sign.js';
import { dkim2Verify } from '../../src/dkim2/verify.js';
import { rsaKey, generated, resolver, message, originatorOptions, signMessage, craftSignature, b64 } from '../helpers/dkim2.js';
import * as reference from '../helpers/dkim2-reference.js';

config.includeStack = true;

const verify = (input: any, options?: any) => dkim2Verify(input, Object.assign({ resolver: resolver() }, options || {}));

const listEnvelope = { mailFrom: 'bounce@bounces.list.example.org', rcptTo: 'member@example.net' };

// the originator sends to the list address
const originatorToList = (extra?: any) => originatorOptions(Object.assign({ rcptTo: 'list@list.example.org' }, extra || {}));

const listOptions = (extra?: any) =>
    Object.assign(
        {
            signingDomain: 'list.example.org',
            signatureData: [
                { selector: 'lrsa', privateKey: generated.rsa },
                { selector: 'led', privateKey: generated.ed25519 }
            ],
            mailFrom: 'bounce@bounces.list.example.org',
            rcptTo: 'member@example.net',
            resolver: resolver()
        },
        extra || {}
    );

// what a mailing list does to the message: a subject tag, a List-Id and a footer
const reviseForList = (signed: any) =>
    Buffer.from(
        signed
            .toString('binary')
            .replace('Subject: Hello DKIM2', 'Subject: [list] Hello DKIM2\r\nList-Id: <list.example.org>')
            .replace(/$/, '--\r\nlist footer\r\n'),
        'binary'
    );

// the original body has the lines "Hello world!", "" and "Second paragraph."
const listRecipe = { h: { subject: [{ d: [' Hello DKIM2'] }], 'list-id': [] }, b: [{ c: [1, 3] }] };

const originatorHeader = (overrides: any) => {
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
        let listSigned: any;

        before(async () => {
            let signed = await signMessage(message(), originatorToList());
            listSigned = await signMessage(reviseForList(signed), listOptions({ recipe: listRecipe }));
        });

        it('passes with both signatures and both instances', async () => {
            let result = await verify(listSigned, listEnvelope);
            expect(result.status.result).to.equal('pass');
            expect(result.info).to.equal('dkim2=pass (i=1 example.com pass, i=2 list.example.org pass) header.d=example.com');
            expect(result.instances).to.deep.equal([
                { m: 1, hashes: [{ algorithm: 'sha256', header: 'pass', body: 'pass', group: 1 }] },
                { m: 2, hashes: [{ algorithm: 'sha256', header: 'pass', body: 'pass', group: 1 }], recipe: { headers: ['subject', 'list-id'], body: 'recipe' } }
            ]);
            expect(result.signatures.map((entry: any) => [entry.i, entry.m, entry.signingDomain, entry.status.result])).to.deep.equal([
                [1, 1, 'example.com', 'pass'],
                [2, 2, 'list.example.org', 'pass']
            ]);
        });

        it('recreates the original with the reference Recipe implementation', async () => {
            let { fields, body } = reference.splitMessage(listSigned.toString('binary'));
            let mi = fields.filter((field: any) => field.name === 'message-instance');
            let first = mi.find((field: any) => reference.getTag(field.value, 'm') === '1');
            let second = mi.find((field: any) => reference.getTag(field.value, 'm') === '2');
            let recipe = JSON.parse(Buffer.from(reference.getTag(second!.value, 'r')!, 'base64').toString());
            expect(recipe).to.deep.equal(listRecipe);

            let previous = reference.applyRecipe({ fields, body }, recipe);
            let [, headerHash, bodyHash] = reference.getTag(first!.value, 'h')!.split(':');
            expect(reference.headerHash(previous.fields, 'sha256')).to.equal(headerHash);
            expect(reference.bodyHash(previous.body!, 'sha256')).to.equal(bodyHash);
        });

        it('fails when the revised body is changed again', async () => {
            let changed = Buffer.from(listSigned.toString('binary').replace('list footer', 'evil footer'), 'binary');
            let result = await verify(changed, listEnvelope);
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('Message-Instance m=2 body hash sha256 mismatch');
            expect(result.status.header!.i).to.equal(2);
        });

        it('fails when a header field the list kept is changed', async () => {
            let changed = Buffer.from(listSigned.toString('binary').replace('Message-ID: <dkim2-test@', 'Message-ID: <other@'), 'binary');
            let result = await verify(changed, listEnvelope);
            expect(result.status.result).to.equal('fail');
            // the change shows in every instance, the first one found is reported
            expect(result.errors.map((error: any) => error.message)).to.deep.equal([
                'Message-Instance m=1 header hash sha256 mismatch',
                'Message-Instance m=2 header hash sha256 mismatch'
            ]);
        });

        it('checks the envelope against the highest signature only', async () => {
            let result = await verify(listSigned, { mailFrom: 'sender@example.com', rcptTo: 'list@list.example.org' });
            expect(result.status.result).to.equal('fail');
            expect(result.errors.map((error: any) => error.message)).to.deep.equal([
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

        it('reports a null body Recipe as a PERMERROR, and the earlier body as unknown (section 14.2)', async () => {
            let signed = await signMessage(message(), originatorToList());
            let replaced = Buffer.from(signed.toString('binary').replace(/Hello world![\s\S]*$/, 'Replaced body\r\n'), 'binary');
            let revised = await signMessage(replaced, listOptions({ recipe: { b: null } }));
            let result = await verify(revised, listEnvelope);
            expect(result.status.result).to.equal('permerror');
            expect(result.status.comment).to.equal('Message-Instance m=2 has a null recipe');
            expect(result.status.header!.i).to.equal(2);
            expect(result.errors).to.have.length(1);
            expect(result.instances[0].hashes[0].body).to.equal('unknown');
            expect(result.instances[1].recipe).to.deep.equal({ headers: [], body: 'unrecoverable' });
            // the header fields below a null body Recipe are still checked
            let changed = Buffer.from(revised.toString('binary').replace('Message-ID: <dkim2-test@', 'Message-ID: <other@'), 'binary');
            expect((await verify(changed, listEnvelope)).status.result).to.equal('fail');
        });

        it('has no effect for the retired donotmodify and donotexplode flags (unknown flags, section 10.10)', async () => {
            let signed = await signMessage(message(), originatorToList({ flags: ['donotmodify', 'donotexplode', 'feedback'] }));
            let revised = await signMessage(reviseForList(signed), listOptions({ recipe: listRecipe, flags: ['exploded'] }));
            let result = await verify(revised, listEnvelope);
            expect(result.status.result).to.equal('pass');
            expect(result.signatures[0].flags).to.deep.equal(['donotmodify', 'donotexplode', 'feedback']);
            expect(result.signatures[1].flags).to.deep.equal(['exploded']);
        });

        it('recreates a body through a body Recipe that follows a null body Recipe', async () => {
            let signed = await signMessage(message(), originatorToList());
            let replaced = Buffer.from(signed.toString('binary').replace(/Hello world![\s\S]*$/, 'New body\r\n'), 'binary');
            let first = await signMessage(replaced, listOptions({ rcptTo: 'list@list.example.org', recipe: { b: null } }));
            let footer = Buffer.from(first.toString('binary') + 'footer\r\n', 'binary');
            // a message with a null Recipe is never Fully Verified (section 13), so signing it again
            // needs an out-of-band arrangement
            let refused = await dkim2Sign(footer, listOptions({ recipe: { b: [{ c: [1, 1] }] } })).catch(err => err);
            expect(refused.code).to.equal('ENOTVERIFIED');
            expect(refused.message).to.equal(
                'Can not sign a message that is not a Fully Verified DKIM2 Message (dkim2=permerror: Message-Instance m=2 has a null recipe)'
            );
            let second = await signMessage(footer, listOptions({ recipe: { b: [{ c: [1, 1] }] }, outOfBand: true }));
            let result = await verify(second, listEnvelope);
            expect(result.status.result).to.equal('permerror');
            expect(result.errors.map((error: any) => error.message)).to.deep.equal(['Message-Instance m=2 has a null recipe']);
            expect(result.instances.map((entry: any) => entry.hashes[0].body)).to.deep.equal(['unknown', 'pass', 'pass']);
        });

        it('recreates a body line that is not UTF-8 with a "u" step (section 5.2)', async () => {
            // the original body line is ISO-8859-1, the 0xF6 byte is not valid UTF-8
            let latin1 = Buffer.from(message([], 'Hello w\u00f6rld!\r\n').toString('utf8'), 'latin1');
            let signed = await signMessage(latin1, originatorToList());
            // the list converts the body to UTF-8
            let converted = Buffer.from(signed.toString('latin1').replace('Hello w\u00f6rld!', 'Hello w\u00c3\u00b6rld!'), 'latin1');
            expect(converted.toString('utf8')).to.include('Hello w\u00f6rld!');

            let recipe = { b: [{ u: [Buffer.from('Hello w\u00f6rld!', 'latin1').toString('base64')] }] };
            let revised = await signMessage(converted, listOptions({ recipe }));
            let result = await verify(revised, listEnvelope);
            expect(result.status.result).to.equal('pass');
            expect(result.instances[1].recipe).to.deep.equal({ headers: [], body: 'recipe' });

            // a "d" step can not hold the byte, its UTF-8 encoding is two other bytes
            let wrong = await signMessage(converted, listOptions({ recipe: { b: [{ d: ['Hello w\u00f6rld!'] }] } })).catch(err => err);
            expect(wrong.code).to.equal('EINVALIDRECIPE');
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

    describe('chain of custody (sections 7.1, 12.2, 12.3 and 14.4)', () => {
        it('compares the local part exactly and the domain without case', async () => {
            let signed = await signMessage(message(), originatorOptions({ mailFrom: 'Sender@Example.COM', rcptTo: ['Rcpt@example.net', 'two@example.org'] }));

            let pass = await verify(signed, { mailFrom: '<Sender@example.com>', rcptTo: ['Rcpt@EXAMPLE.NET'] });
            expect(pass.status.result).to.equal('pass');

            let fail = await verify(signed, { mailFrom: 'sender@example.com', rcptTo: ['rcpt@example.net'] });
            expect(fail.status.result).to.equal('fail');
            expect(fail.errors.map((error: any) => error.message)).to.deep.equal([
                'DKIM2-Signature i=1 MAIL FROM sender@example.com did not match',
                'DKIM2-Signature i=1 RCPT TO rcpt@example.net did not match'
            ]);
            expect(fail.info).to.match(/^dkim2=fail \(i=1 example\.com fail; DKIM2-Signature i=1 MAIL FROM sender@example\.com did not match\)/);
        });

        it('signs and verifies the null reverse-path', async () => {
            let signed = await signMessage(message(), originatorOptions({ mailFrom: '' }));
            expect((await verify(signed, { mailFrom: '', rcptTo: 'rcpt@example.net' })).status.result).to.equal('pass');
            expect((await verify(signed, { mailFrom: '<>' })).status.result).to.equal('pass');
            expect((await verify(signed, { mailFrom: 'sender@example.com' })).status.result).to.equal('fail');
        });

        it('accepts a MAIL FROM in a subdomain of d= (section 10.8)', async () => {
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
            expect(result.status.result).to.equal('fail');
            expect(result.errors.map((error: any) => error.message)).to.deep.equal(['DKIM2-Signature i=1 mf= and d= do not match']);
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
            expect(result.status.result).to.equal('fail');
            expect(result.errors.map((error: any) => error.message)).to.deep.equal([
                'DKIM2-Signature i=2 mf= does not match the rt= of i=1',
                'DKIM2-Signature i=2 MAIL FROM bounce@bounces.list.example.org did not match'
            ]);
        });

        it('follows an imaginary hop documented with nd= (section 12.3)', async () => {
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

            // without the next hop the message is not verified, with or without the envelope
            // (sections 12.3 and 13.2)
            for (let options of [{ mailFrom: 'bounce@fwd.example.net', rcptTo: 'member@example.net' }, {}]) {
                let trailing = await verify(withNd, options);
                expect(trailing.status.result).to.equal('fail');
                expect(trailing.errors.map((error: any) => error.message)).to.deep.equal(['DKIM2-Signature i=2 unexpected nd= tag']);
            }
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
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('DKIM2-Signature i=2 nd= does not match');
        });

        it('rejects nd= together with mf= or rt=', async () => {
            let err = await dkim2Sign(message(), originatorOptions({ nextDomain: 'fwd.example.net' })).catch(err => err);
            expect(err.code).to.equal('EINVALIDOPTS');
        });
    });

    describe('replay (section 15.1)', () => {
        it('reports a duplicate without changing the result', async () => {
            let seen = new Set();
            let calls: any[] = [];
            let checkReplay = async (replay: any) => {
                calls.push(replay);
                let duplicate = seen.has(replay.key);
                seen.add(replay.key);
                return duplicate;
            };

            let signed = await signMessage(message(), originatorOptions());
            let first = await verify(signed, { checkReplay });
            expect(first.status.result).to.equal('pass');
            expect(first.replay).to.deep.include({ exploded: false, intermediary: false, duplicate: false });
            let second = await verify(signed, { checkReplay });
            expect(second.status.result).to.equal('pass');
            expect(second.replay!.key).to.match(/^sha256:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/);
            expect(second.replay).to.deep.include({ exploded: false, intermediary: false, duplicate: true });
            expect(calls[0]).to.deep.equal({ key: second.replay!.key, exploded: false, intermediary: false });

            // without checkReplay there is no duplicate property
            expect(await verify(signed)).to.have.nested.property('replay.intermediary', false);
            expect((await verify(signed)).replay).to.not.have.property('duplicate');
        });

        it('reports an intermediary and an exploded flag, which the first signature can not have (section 12.5)', async () => {
            let err = await dkim2Sign(message(), originatorOptions({ flags: ['exploded'] })).catch(err => err);
            expect(err.code).to.equal('EINVALIDOPTS');

            let signed = await signMessage(message(), originatorToList());
            let forwarded = await signMessage(signed, listOptions({ flags: ['exploded'] }));
            let result = await verify(forwarded, Object.assign({ checkReplay: async () => true }, listEnvelope));
            expect(result.status.result).to.equal('pass');
            expect(result.replay).to.deep.include({ exploded: true, intermediary: true, duplicate: true });
        });

        it('reports the exploded flag on a forged first signature', async () => {
            let input = message();
            let { fields, body } = reference.splitMessage(input.toString('binary'));
            let instance = `Message-Instance: m=1; h=sha256:${reference.headerHash(fields, 'sha256')}:${reference.bodyHash(body, 'sha256')}`;
            let forged = craftSignature(Buffer.concat([Buffer.from(instance + '\r\n'), input]), originatorHeader({ f: 'exploded' }), { rsa: rsaKey });
            let result = await verify(forged);
            expect(result.status.result).to.equal('permerror');
            expect(result.status.comment).to.equal('DKIM2-Signature i=1 has an exploded flag');
        });
    });
});
