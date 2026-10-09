/* eslint no-unused-expressions:0 */
'use strict';

// How authenticate(), createSeal() and sealMessage() treat the caller's seal options

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { authenticate, sealMessage } = require('../../lib/mailauth');
const { createSeal } = require('../../lib/arc');
const { dkimTxtRecord, privateKey } = require('../helpers/keys');

const KEY_RECORD = dkimTxtRecord('public-rsa.pem');

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// the sealing key of sealer.example, every other name does not exist. Lookups for names
// under slow.example take longer, so a message from there finishes its checks last
const resolver = async (name, type) => {
    if (/(^|\.)slow\.example$/i.test(name)) {
        await delay(50);
    }
    if (name.toLowerCase() === 'arc._domainkey.sealer.example' && type === 'TXT') {
        return [[KEY_RECORD]];
    }
    const err = new Error('NXDOMAIN');
    err.code = 'ENOTFOUND';
    throw err;
};

const sealConfig = extra => Object.assign({ signingDomain: 'sealer.example', selector: 'arc', privateKey: privateKey('private-rsa.pem') }, extra || {});

const msg = (fromDomain, body) => Buffer.from(`From: a@${fromDomain}\r\nTo: b@example.net\r\nSubject: hi\r\n\r\n${body}\r\n`);

const authOpts = extra => Object.assign({ ip: '192.0.2.1', helo: 'mx.test', sender: 'a@example.com', mta: 'mx.sealer.example', resolver }, extra || {});

// validates the ARC chain of a message the way the next hop would
const downstream = async (message, strict) => (await authenticate(message, authOpts({ mta: 'mx.next.example', strict }))).arc.status.result;

const MODES = [
    { name: 'lax', strict: false },
    { name: 'strict', strict: true }
];

describe('ARC seal options', () => {
    for (const mode of MODES) {
        describe(`${mode.name} mode`, () => {
            describe('The caller seal object is not modified', () => {
                it('Should seal concurrent messages sharing one seal object with their own body hashes', async () => {
                    const seal = sealConfig();
                    const snapshot = Object.assign({}, seal);

                    const mA = msg('slow.example', 'body of message A');
                    const mB = msg('fast.example', 'a different body for message B');

                    const [a, b] = await Promise.all([
                        authenticate(mA, authOpts({ sender: 'a@slow.example', seal, strict: mode.strict })),
                        authenticate(mB, authOpts({ sender: 'a@fast.example', seal, strict: mode.strict }))
                    ]);

                    const bhA = a.headers.match(/bh=([^;]+);/)[1];
                    const bhB = b.headers.match(/bh=([^;]+);/)[1];
                    expect(bhA).to.not.equal(bhB);

                    expect(await downstream(Buffer.concat([Buffer.from(a.headers), mA]), mode.strict)).to.equal('pass');
                    expect(await downstream(Buffer.concat([Buffer.from(b.headers), mB]), mode.strict)).to.equal('pass');

                    expect(seal).to.deep.equal(snapshot);
                });

                it('Should let one seal object be reused for consecutive sealMessage() calls', async () => {
                    const seal = sealConfig({ authResults: 'mx1.sealer.example; arc=none', strict: mode.strict });

                    const m0 = msg('example.com', 'body');
                    const set1 = await sealMessage(m0, seal);
                    expect(set1.toString()).to.match(/^ARC-Seal: i=1;/);
                    expect(seal).to.not.have.property('i');
                    expect(seal).to.not.have.property('bodyHash');

                    const m1 = Buffer.concat([set1, m0]);
                    Object.assign(seal, { cv: 'pass', authResults: 'mx2.sealer.example; arc=pass' });
                    const set2 = await sealMessage(m1, seal);
                    expect(set2.toString()).to.match(/^ARC-Seal: i=2;/);
                    expect(seal).to.not.have.property('i');

                    expect(await downstream(Buffer.concat([set2, m1]), mode.strict)).to.equal('pass');
                });

                it('Should keep an explicit instance as given', async () => {
                    const seal = sealConfig({ i: '1', authResults: 'mx1.sealer.example; arc=none', strict: mode.strict });

                    const { headers, errors } = await createSeal(msg('example.com', 'body'), { seal });
                    expect(errors).to.deep.equal([]);
                    expect(headers[0]).to.match(/^ARC-Seal: i=1;/);
                    expect(seal.i).to.equal('1');
                });
            });

            describe('authenticate() uses its own chain status, AAR and instance', () => {
                const head = 'From: a@example.com\r\nTo: b@example.net\r\nSubject: hi\r\n\r\n';

                // a single ARC set whose AMS no longer validates, because the body changed
                const brokenChain = async () => {
                    const set1 = await sealMessage(Buffer.from(head + 'original\r\n'), sealConfig({ authResults: 'mx1.sealer.example; arc=none' }));
                    return Buffer.concat([set1, Buffer.from(head + 'tampered\r\n')]);
                };

                it('Should seal a broken chain with cv=fail even if the seal options say cv=pass', async () => {
                    const broken = await brokenChain();
                    const seal = sealConfig({ cv: 'pass', authResults: 'mx.forged.example; arc=pass', i: 7 });

                    const r = await authenticate(broken, authOpts({ seal, strict: mode.strict }));
                    expect(r.arc.status.result).to.equal('fail');

                    const sealHeader = r.headers.match(/^ARC-Seal: [^]*?(?=^\S)/m)[0];
                    expect(sealHeader).to.match(/^ARC-Seal: i=2;/);
                    expect(sealHeader).to.match(/cv=fail/);

                    const aar = r.headers.match(/^ARC-Authentication-Results: [^]*?(?=^\S|$(?![^]))/m)[0];
                    expect(aar).to.match(/^ARC-Authentication-Results: i=2; mx\.sealer\.example;/);
                    expect(aar).to.not.include('forged');

                    expect(await downstream(Buffer.concat([Buffer.from(r.headers), broken]), mode.strict)).to.equal('fail');
                });

                it('Should seal a new message with cv=none even if the seal options say cv=pass', async () => {
                    const message = msg('example.com', 'body');
                    const seal = sealConfig({ cv: 'pass', authResults: 'mx.forged.example; arc=pass' });

                    const r = await authenticate(message, authOpts({ seal, strict: mode.strict }));
                    expect(r.headers).to.match(/^ARC-Seal: i=1;[^]*?cv=none/m);
                    expect(r.headers).to.match(/^ARC-Authentication-Results: i=1; mx\.sealer\.example;/m);
                    expect(r.headers).to.not.include('forged');

                    expect(await downstream(Buffer.concat([Buffer.from(r.headers), message]), mode.strict)).to.equal('pass');
                });
            });
        });
    }
});
