'use strict';

const { Buffer } = require('node:buffer');
const { Readable } = require('node:stream');
const { expect } = require('chai');

const { dkim2Sign } = require('../../lib/dkim2/sign');
const { dkim2Verify } = require('../../lib/dkim2/verify');
const reference = require('../helpers/dkim2-reference');
const { ed25519Key, generated, resolver } = require('../helpers/dkim2');
const { fc, check, timeout, bytesFrom, chunkBuffer } = require('./helper');

const zone = resolver();

const originator = {
    signingDomain: 'example.com',
    selector: 'ed',
    privateKey: ed25519Key,
    mailFrom: 'sender@example.com',
    rcptTo: 'list@list.example.org',
    hashAlgorithms: ['sha256', 'sha512']
};

const list = {
    signingDomain: 'list.example.org',
    selector: 'led',
    privateKey: generated.ed25519,
    mailFrom: 'bounce@list.example.org',
    rcptTo: 'member@example.net'
};

// header field names, including ones DKIM2 does not sign, in mixed case
const fieldName = fc.constantFrom(
    'Subject',
    'SUBJECT',
    'To',
    'Cc',
    'Comments',
    'Keywords',
    'X-Custom',
    'Received',
    'Received-SPF',
    'Authentication-Results',
    'Delivered-To'
);
// values with runs of whitespace, folds and 8-bit bytes
const fieldValue = bytesFrom('ab \t\xe9', { minLength: 1, maxLength: 30 }).map(value => value.replace(/^[ \t]+/, '') || 'x');
const field = fc.tuple(fieldName, fieldValue, fc.boolean()).map(([name, value, fold]) => `${name}: ${fold ? value.replace(/ /, '\r\n ') : value}`);
const body = bytesFrom('ab \t\r\n.\xff', { maxLength: 200 });

const messageArb = fc
    .tuple(fc.array(field, { maxLength: 8 }), body)
    .map(([fields, text]) => Buffer.from(['From: sender@example.com', ...fields, '', text].join('\r\n'), 'latin1'));

const sign = async (input, options) => {
    let result = await dkim2Sign(input, options);
    return Buffer.concat([Buffer.from(result.signatures), input]);
};

describe('Property: DKIM2', function () {
    this.timeout(timeout(100, 40));

    it('the hashes equal those of the reference implementation and the signature verifies', () =>
        check(
            fc.asyncProperty(messageArb, async input => {
                let signed = await sign(input, originator);
                let str = signed.toString('binary');
                let { fields, body: text } = reference.splitMessage(str.replace(/\r?\n/g, '\r\n'));
                let instance = fields.find(entry => entry.name === 'message-instance');
                for (let set of reference.getTag(instance.value, 'h').split(',')) {
                    let [algorithm, headerHash, bodyHash] = set.split(':');
                    expect(headerHash).to.equal(reference.headerHash(fields, algorithm));
                    expect(bodyHash).to.equal(reference.bodyHash(text, algorithm));
                }

                let result = await dkim2Verify(signed, { resolver: zone, mailFrom: originator.mailFrom, rcptTo: originator.rcptTo });
                expect(result.status.result).to.equal('pass');
            }),
            100
        ));

    it('the result does not depend on how the message is split into chunks', () =>
        check(
            fc.asyncProperty(messageArb, fc.array(fc.nat(), { maxLength: 10 }), async (input, cuts) => {
                let signed = await sign(input, originator);
                let result = await dkim2Verify(Readable.from(chunkBuffer(signed, cuts)), { resolver: zone });
                expect(result.status.result).to.equal('pass');
            }),
            50
        ));

    it('a changed byte in a signed header value or in the body content fails', () =>
        check(
            fc.asyncProperty(messageArb, fc.nat(), async (input, pos) => {
                let signed = await sign(Buffer.concat([Buffer.from('Comments: protected\r\n'), input]), originator);
                let str = signed.toString('binary');
                // either the protected header value or a non-whitespace body byte
                let targets = [str.indexOf('protected')];
                let bodyStart = str.indexOf('\r\n\r\n') + 4;
                for (let i = bodyStart; i < str.length; i++) {
                    if (!/[\s]/.test(str[i])) {
                        targets.push(i);
                    }
                }
                let target = targets[pos % targets.length];
                let changed = str.slice(0, target) + (str[target] === 'q' ? 'r' : 'q') + str.slice(target + 1);
                let result = await dkim2Verify(Buffer.from(changed, 'binary'), { resolver: zone });
                expect(result.status.result).to.equal('fail');
            }),
            50
        ));

    it('a list revision with a matching Recipe verifies, and the reference recreates the original', () =>
        check(
            fc.asyncProperty(messageArb, fieldValue, bytesFrom('ab \r\n', { maxLength: 40 }), async (input, subject, footer) => {
                let signed = await sign(Buffer.concat([Buffer.from('Subject: original\r\n'), input]), originator);
                // the reference works on CRLF line endings, as the parser does after normalizing bare LFs
                let str = signed.toString('binary').replace(/\r?\n/g, '\r\n');
                let bodyStart = str.indexOf('\r\n\r\n') + 4;
                let text = str.slice(bodyStart);
                let lines = text.split('\r\n');
                if (text.endsWith('\r\n')) {
                    lines.pop();
                }

                // replace the first Subject, add a header field and append a footer
                let revised =
                    str.slice(0, bodyStart).replace('Subject: original\r\n', `Subject: ${subject}\r\nList-Id: <list.example.org>\r\n`) + text + '\r\n' + footer;
                let subjects = reference
                    .splitMessage(str)
                    .fields.filter(entry => entry.name === 'subject')
                    .reverse();
                // the replaced Subject is the top one, the last when numbered from the bottom
                let steps = subjects.length > 1 ? [{ c: [1, subjects.length - 1] }, { d: ['original'] }] : [{ d: ['original'] }];
                let recipe = { h: { subject: steps, 'list-id': [] }, b: lines.length ? [{ c: [1, lines.length] }] : [{ d: [''] }] };

                let listSigned = await sign(Buffer.from(revised, 'binary'), Object.assign({ recipe }, list));
                let result = await dkim2Verify(listSigned, { resolver: zone, mailFrom: list.mailFrom, rcptTo: list.rcptTo });
                expect(result.status.result).to.equal('pass');
                expect(result.instances).to.have.length(2);

                let current = reference.splitMessage(listSigned.toString('binary').replace(/\r?\n/g, '\r\n'));
                let previous = reference.applyRecipe(current, recipe);
                let first = current.fields.find(entry => entry.name === 'message-instance' && reference.getTag(entry.value, 'm') === '1');
                let [, headerHash, bodyHash] = reference.getTag(first.value, 'h').split(',')[0].split(':');
                expect(reference.headerHash(previous.fields, 'sha256')).to.equal(headerHash);
                expect(reference.bodyHash(previous.body, 'sha256')).to.equal(bodyHash);
            }),
            50
        ));
});
