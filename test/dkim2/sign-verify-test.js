/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const { Readable } = require('node:stream');
const chai = require('chai');
const expect = chai.expect;

const { dkim2Sign, Dkim2SignStream } = require('../../lib/dkim2/sign');
const { dkim2Verify } = require('../../lib/dkim2/verify');
const { dkim2Hash } = require('../../lib/dkim2/hash');
const { dkimSign, dkimVerify } = require('../../lib/mailauth');
const { rsaKey, ed25519Key, resolver, message, originatorOptions, signMessage } = require('../helpers/dkim2');
const { dkimTxtRecord } = require('../helpers/keys');
const reference = require('../helpers/dkim2-reference');
const { parseMessageInstance } = require('../../lib/dkim2/fields');

chai.config.includeStack = true;

const envelope = { mailFrom: 'sender@example.com', rcptTo: 'rcpt@example.net' };

const verify = (input, options) => dkim2Verify(input, Object.assign({ resolver: resolver() }, options || {}));

// replaces the first occurrence of `search` in a message
const tamper = (input, search, replacement) => Buffer.from(input.toString('binary').replace(search, replacement), 'binary');

describe('DKIM2 signing and verification', () => {
    it('signs and verifies with RSA and Ed25519 in one DKIM2-Signature', async () => {
        let signed = await signMessage(message(), originatorOptions());
        let result = await verify(signed, envelope);

        expect(result.status.result).to.equal('pass');
        expect(result.errors).to.deep.equal([]);
        expect(result.info).to.equal('dkim2=pass (i=1 example.com pass) header.d=example.com');
        expect(result.signatures).to.have.length(1);
        expect(result.signatures[0].values.map(entry => [entry.selector, entry.algorithm, entry.result])).to.deep.equal([
            ['rsa', 'rsa-sha256', 'pass'],
            ['ed', 'ed25519-sha256', 'pass']
        ]);
        expect(result.signatures[0].mailFrom).to.equal('<sender@example.com>');
        expect(result.signatures[0].rcptTo).to.deep.equal(['<rcpt@example.net>']);
        expect(result.instances).to.deep.equal([{ m: 1, hashes: [{ algorithm: 'sha256', header: 'pass', body: 'pass' }] }]);
    });

    it('creates an m=1 Message-Instance and an i=1 DKIM2-Signature for a new message', async () => {
        let result = await dkim2Sign(message(), originatorOptions({ signTime: new Date('2026-10-10T10:00:00Z') }));
        expect(result.i).to.equal(1);
        expect(result.m).to.equal(1);
        expect(result.signature).to.match(/^DKIM2-Signature: i=1; m=1; t=1791626400; d=example\.com;/);
        expect(result.messageInstance).to.match(/^Message-Instance: m=1; h=sha256:/);
        // DKIM2-Signature first, then the Message-Instance, both ending with CRLF
        expect(result.signatures).to.equal(`${result.signature}\r\n${result.messageInstance}\r\n`);
        // no v= tag (section 8)
        expect(result.signature).to.not.match(/[ ;]v=/);
    });

    it('matches the independent reference for the hashes and the signature input', async () => {
        let input = message(['X-Mailer: test', 'Received: from somewhere', 'Cc:   Someone   <cc@example.com>  ', 'subject: second subject']);
        let signed = await signMessage(input, originatorOptions({ hashAlgorithms: ['sha256', 'sha512'] }));
        let str = signed.toString('binary');
        let { fields, body } = reference.splitMessage(str);
        let mi = fields.find(field => field.name === 'message-instance');
        let hashSets = reference
            .getTag(mi.value, 'h')
            .split(',')
            .map(set => set.split(':'));

        for (let [algorithm, headerHash, bodyHash] of hashSets) {
            expect(headerHash).to.equal(reference.headerHash(fields, algorithm));
            expect(bodyHash).to.equal(reference.bodyHash(body, algorithm));
        }

        expect(reference.verifySignatureValue(str, 1, 'rsa', require('node:crypto').createPublicKey(rsaKey))).to.be.true;
        expect(reference.verifySignatureValue(str, 1, 'ed', require('node:crypto').createPublicKey(ed25519Key))).to.be.true;
    });

    it('computes the header hash from a hand canonicalized header block', async () => {
        // section 6.2 by hand: unsigned fields gone, names lower case, WSP collapsed and trimmed,
        // sorted by name, same names from the bottom up
        let input = Buffer.from(
            [
                'Subject:  Hello\r\n   World  ',
                'From: one@example.com',
                'X-Spam: yes',
                'Received: by host',
                'Received-SPF: pass',
                'Authentication-Results: mx; dkim=pass',
                'DKIM-Signature: v=1; a=rsa-sha256',
                'FROM :two@example.com',
                'To:\trcpt@example.net',
                '',
                'body'
            ].join('\r\n')
        );
        let expected = 'from:two@example.com\r\nfrom:one@example.com\r\nsubject:Hello World\r\nto:rcpt@example.net\r\n';
        let expectedHash = require('node:crypto').createHash('sha256').update(expected).digest('base64');
        let expectedBodyHash = require('node:crypto').createHash('sha256').update('body\r\n').digest('base64');

        let result = await dkim2Sign(input, originatorOptions({ mailFrom: 'one@example.com' }));
        expect(result.messageInstance.replace(/\s/g, '')).to.equal(`Message-Instance:m=1;h=sha256:${expectedHash}:${expectedBodyHash};`);
    });

    it('computes the Message-Instance hashes with dkim2Hash()', async () => {
        let input = message(['X-Mailer: test', 'Received: from somewhere']);
        let signed = await dkim2Sign(input, originatorOptions({ hashAlgorithms: ['sha256', 'sha512'] }));
        let hashSets = parseMessageInstance(signed.messageInstance).hashes;

        let result = await dkim2Hash(input, { algorithms: ['SHA256', 'sha512', 'sha256'] });
        expect(result.hashes).to.deep.equal(hashSets);
        expect(result.headers).to.deep.equal(['date', 'from', 'message-id', 'subject', 'to']);

        // the DKIM2 header fields of a signed message are not hashed, and sha256 is the default
        let again = await dkim2Hash(Readable.from([Buffer.concat([Buffer.from(signed.signatures), input])]));
        expect(again.hashes).to.deep.equal([hashSets[0]]);

        let err = await dkim2Hash(input, { algorithms: ['sha1'] }).catch(err => err);
        expect(err.code).to.equal('EINVALIDALGO');
    });

    it('verifies with sha512 hashes only', async () => {
        let signed = await signMessage(message(), originatorOptions({ hashAlgorithms: ['sha512'] }));
        let result = await verify(signed, envelope);
        expect(result.status.result).to.equal('pass');
        expect(result.instances[0].hashes).to.deep.equal([{ algorithm: 'sha512', header: 'pass', body: 'pass' }]);
    });

    it('verifies a message signed with a single key given with the shorthand options', async () => {
        let signed = await signMessage(message(), {
            signingDomain: 'example.com',
            selector: 'ed',
            privateKey: ed25519Key,
            mailFrom: 'sender@example.com',
            rcptTo: ['rcpt@example.net', 'other@example.org']
        });
        let result = await verify(signed, envelope);
        expect(result.status.result).to.equal('pass');
        expect(result.signatures[0].rcptTo).to.deep.equal(['<rcpt@example.net>', '<other@example.org>']);
    });

    it('signs a message with no body, and one with bare LF line endings', async () => {
        for (let input of [
            Buffer.from('From: sender@example.com\r\nSubject: x\r\n'),
            Buffer.from('From: sender@example.com\nSubject: x\n\nline 1\nline 2\n\n\n')
        ]) {
            let signed = await signMessage(input, originatorOptions());
            let result = await verify(signed, envelope);
            expect(result.status.result).to.equal('pass');
        }
    });

    it('treats bare LF and CRLF bodies the same (section 13)', async () => {
        let crlf = await dkim2Sign(Buffer.from('From: sender@example.com\r\n\r\na\r\nb\r\n'), originatorOptions({ signTime: 1 }));
        let lf = await dkim2Sign(Buffer.from('From: sender@example.com\n\na\nb\n'), originatorOptions({ signTime: 1 }));
        expect(lf.messageInstance).to.equal(crlf.messageInstance);
    });

    it('ignores trailing empty lines of the body (section 6.1)', async () => {
        let signed = await signMessage(message(), originatorOptions());
        let result = await verify(Buffer.concat([signed, Buffer.from('\r\n\r\n\r\n')]), envelope);
        expect(result.status.result).to.equal('pass');
    });

    it('fails when the body is changed', async () => {
        let signed = await signMessage(message(), originatorOptions());
        let result = await verify(tamper(signed, 'Hello world!', 'Hello World!'), envelope);
        expect(result.status.result).to.equal('fail');
        expect(result.status.comment).to.equal('Message Instance m=1 body hash sha256 mismatch');
        expect(result.status.header).to.deep.equal({ d: 'example.com', i: 1 });
        expect(result.info).to.equal('dkim2=fail (i=1 example.com fail; Message Instance m=1 body hash sha256 mismatch) header.d=example.com header.i=1');
    });

    it('fails when a signed header field is changed, removed or added', async () => {
        let signed = await signMessage(message(), originatorOptions());

        for (let changed of [
            tamper(signed, 'Subject: Hello DKIM2', 'Subject: Hello DKIM3'),
            tamper(signed, 'Subject: Hello DKIM2\r\n', ''),
            tamper(signed, 'Subject: Hello DKIM2\r\n', 'Subject: Hello DKIM2\r\nReply-To: evil@example.org\r\n'),
            tamper(signed, 'Subject: Hello DKIM2\r\n', 'Subject: Hello DKIM2\r\nSubject: second\r\n')
        ]) {
            let result = await verify(changed, envelope);
            expect(result.status.result).to.equal('fail');
            expect(result.status.comment).to.equal('Message Instance m=1 header hash sha256 mismatch');
        }
    });

    it('passes when unsigned header fields are added, removed or changed (section 4)', async () => {
        let input = message(['X-Original: 1', 'Received: from a by b']);
        let signed = await signMessage(input, originatorOptions());
        let changed = Buffer.concat([
            Buffer.from(
                'Authentication-Results: mx.example.net; dkim2=pass\r\nReceived: from x by y\r\nReceived-SPF: pass\r\nX-Spam: 0\r\nReturn-Path: <a@b>\r\nDelivered-To: rcpt@example.net\r\nARC-Seal: i=1\r\nDKIM-Signature: v=1\r\nAuto-Submitted: no\r\n'
            ),
            tamper(tamper(signed, 'X-Original: 1\r\n', ''), 'Received: from a by b', 'Received: changed')
        ]);
        let result = await verify(changed, envelope);
        expect(result.status.result).to.equal('pass');
    });

    it('passes when header fields with different names are reordered or refolded', async () => {
        let signed = await signMessage(message(), originatorOptions());
        let reordered = tamper(
            tamper(signed, 'Subject: Hello DKIM2\r\n', ''),
            'Message-ID: <dkim2-test@example.com>\r\n',
            'Message-ID:\r\n   <dkim2-test@example.com>\r\nsubject:   Hello    DKIM2   \r\n'
        );
        let result = await verify(reordered, envelope);
        expect(result.status.result).to.equal('pass');
    });

    it('fails when header fields with the same name are reordered', async () => {
        let signed = await signMessage(message(['Comments: first', 'Comments: second']), originatorOptions());
        let swapped = tamper(tamper(signed, 'Comments: first', 'Comments: TMP'), 'Comments: second', 'Comments: first');
        swapped = tamper(swapped, 'Comments: TMP', 'Comments: second');
        let result = await verify(swapped, envelope);
        expect(result.status.result).to.equal('fail');
    });

    it('passes when the DKIM2 header fields are refolded or moved', async () => {
        let result = await dkim2Sign(message(), originatorOptions());
        let signature = result.signature.replace(/; /g, ';\r\n\t ').replace(/:/, ' :  ');
        let moved = Buffer.concat([Buffer.from('Received: by mx\r\n'), message(), Buffer.alloc(0)]);
        // the fields go below the other header fields, in a different order
        let str = moved.toString('binary').replace('\r\n\r\n', `\r\n${result.messageInstance}\r\n${signature}\r\n\r\n`);
        let verified = await verify(Buffer.from(str, 'binary'), envelope);
        expect(verified.status.result).to.equal('pass');
    });

    it('fails when a signature value is changed', async () => {
        let result = await dkim2Sign(message(), originatorOptions());
        let signature = result.signature.replace(/(s=rsa:rsa-sha256:\s*)(.)/, (m, lead, c) => lead + (c === 'A' ? 'B' : 'A'));
        let verified = await verify(Buffer.concat([Buffer.from(`${signature}\r\n${result.messageInstance}\r\n`), message()]), envelope);
        expect(verified.status.result).to.equal('fail');
        expect(verified.status.comment).to.equal('DKIM2-Signature i=1 ed signature passed, rsa signature failed');
        expect(verified.signatures[0].values.map(entry => entry.result)).to.deep.equal(['fail', 'pass']);
    });

    it('fails with "incorrect signature" when every signature fails', async () => {
        let signed = await signMessage(message(), originatorOptions({ signatureData: [{ selector: 'rsa', privateKey: rsaKey }] }));
        // t= is covered by the signature
        let changed = tamper(signed, /t=(\d+)/, (m, t) => `t=${Number(t) + 1}`);
        let verified = await verify(changed, envelope);
        expect(verified.status.result).to.equal('fail');
        expect(verified.status.comment).to.equal('DKIM2-Signature i=1 rsa incorrect signature');
    });

    it('fails when the Message-Instance hashes are swapped for the hashes of another message', async () => {
        let first = await dkim2Sign(message(), originatorOptions());
        let second = await dkim2Sign(message([], 'Other body\r\n'), originatorOptions());
        let verified = await verify(
            Buffer.concat([Buffer.from(`${first.signature}\r\n${second.messageInstance}\r\n`), message([], 'Other body\r\n')]),
            envelope
        );
        expect(verified.status.result).to.equal('fail');
        expect(verified.status.comment).to.match(/incorrect signature/);
    });

    it('returns none for a message without DKIM2 header fields', async () => {
        let result = await verify(message());
        expect(result.status).to.deep.equal({ result: 'none' });
        expect(result.info).to.equal('dkim2=none');
    });

    it('accepts a stream as input, and signs through Dkim2SignStream', async () => {
        let signer = new Dkim2SignStream(originatorOptions());
        let chunks = [];
        signer.on('data', chunk => chunks.push(chunk));
        await new Promise((resolve, reject) => {
            signer.on('end', resolve);
            signer.on('error', reject);
            Readable.from([message()]).pipe(signer);
        });
        let output = Buffer.concat(chunks);
        expect(output.toString()).to.match(/^DKIM2-Signature: i=1;/);

        let result = await verify(Readable.from([output]), envelope);
        expect(result.status.result).to.equal('pass');
    });

    it('signs with the same t= that it emits', async () => {
        let result = await dkim2Sign(message(), originatorOptions({ signTime: new Date('2026-10-01T00:00:00Z') }));
        expect(result.signature).to.match(/t=1790812800;/);
    });

    describe('coexistence with DKIM1 (section 4 item 2)', () => {
        const dkimResolver = () =>
            resolver({
                'test._domainkey.example.com': { TXT: [[dkimTxtRecord('public-rsa.pem')]] }
            });
        const dkimOptions = { signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: rsaKey }] };

        it('verifies both when DKIM1 signs after DKIM2', async () => {
            let dkim2Signed = await signMessage(message(), originatorOptions());
            let dkim1 = await dkimSign(dkim2Signed, dkimOptions);
            let both = Buffer.concat([Buffer.from(dkim1.signatures), dkim2Signed]);

            expect((await dkim2Verify(both, Object.assign({ resolver: dkimResolver() }, envelope))).status.result).to.equal('pass');
            let dkimResult = await dkimVerify(both, { resolver: dkimResolver() });
            expect(dkimResult.results[0].status.result).to.equal('pass');
        });

        it('verifies both when DKIM2 signs after DKIM1', async () => {
            let dkim1 = await dkimSign(message(), dkimOptions);
            let dkim1Signed = Buffer.concat([Buffer.from(dkim1.signatures), message()]);
            let both = await signMessage(dkim1Signed, originatorOptions());

            expect((await dkim2Verify(both, Object.assign({ resolver: dkimResolver() }, envelope))).status.result).to.equal('pass');
            let dkimResult = await dkimVerify(both, { resolver: dkimResolver() });
            expect(dkimResult.results[0].status.result).to.equal('pass');
        });
    });
});
