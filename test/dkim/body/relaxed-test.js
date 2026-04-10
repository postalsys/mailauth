/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;
const crypto = require('node:crypto');

let fs = require('node:fs').promises;
let { RelaxedHash } = require('../../../lib/dkim/body/relaxed');

chai.config.includeStack = true;

const getBody = message => {
    message = message.toString('binary');
    let match = message.match(/\r?\n\r?\n/);
    if (match) {
        message = message.substr(match.index + match[0].length);
    }
    return Buffer.from(message, 'binary');
};

describe('DKIM RelaxedBody Tests', () => {
    it('Should calculate sha256 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new RelaxedHash('rsa-sha256');
        s.update(message);

        expect(s.digest('base64')).to.equal('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });

    it('Should calculate sha1 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new RelaxedHash('rsa-sha1');
        s.update(message);

        expect(s.digest('base64')).to.equal('2jmj7l5rSw0yVb/vlWAYkK/YBwk=');
    });

    it('Should calculate body hash byte by byte', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new RelaxedHash('rsa-sha256');
        for (let i = 0; i < message.length; i++) {
            s.update(Buffer.from([message[i]]));
        }

        expect(s.digest('base64')).to.equal('D2H5TEwtUgM2u8Ew0gG6vnt/Na6L+Zep7apmSmfy8IQ=');
    });

    it('Should calculate body hash all at once', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new RelaxedHash('rsa-sha256');
        s.update(message);

        expect(s.digest('base64')).to.equal('D2H5TEwtUgM2u8Ew0gG6vnt/Na6L+Zep7apmSmfy8IQ=');
    });

    it('Should calculate body hash with l=0', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new RelaxedHash('rsa-sha256', 0);
        s.update(message);

        expect(s.digest('base64')).to.equal('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });

    it('Should calculate body hash with l=20', async () => {
        let s = new RelaxedHash('rsa-sha256', 20);
        s.update(Buffer.from('tere tere\r\n \r\nvana kere\r\n\r\n'));

        expect(s.digest('base64')).to.equal(
            crypto
                .createHash('sha256')
                .update(Buffer.from(['tere tere\r\n', '\r\n', 'vana ke'].join('')))
                .digest('base64')
        );
    });

    it('Should produce identical hash for all 2-chunk splits', async () => {
        // Body with leading whitespace + tab trigger -- reproduces issue #115
        const body = Buffer.from('\r\n Hello\r\nWorld\r\nContent\there\r\nEnd\r\n');

        // Reference: all-at-once hash
        let ref = new RelaxedHash('rsa-sha256');
        ref.update(body);
        let refHash = ref.digest('base64');

        for (let splitAt = 1; splitAt < body.length; splitAt++) {
            let s = new RelaxedHash('rsa-sha256');
            s.update(body.subarray(0, splitAt));
            s.update(body.subarray(splitAt));
            expect(s.digest('base64')).to.equal(refHash, `hash mismatch at split position ${splitAt}`);
        }
    });

    it('Should produce identical hash for random multi-chunk splits', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let ref = new RelaxedHash('rsa-sha256');
        ref.update(message);
        let refHash = ref.digest('base64');

        let chunkSizes = [1, 3, 7, 13, 37, 64, 128, 255];
        for (let sizeIdx = 0; sizeIdx < chunkSizes.length; sizeIdx++) {
            let s = new RelaxedHash('rsa-sha256');
            let pos = 0;
            let ci = sizeIdx;
            while (pos < message.length) {
                let chunkSize = chunkSizes[ci % chunkSizes.length];
                ci++;
                let end = Math.min(pos + chunkSize, message.length);
                s.update(message.subarray(pos, end));
                pos = end;
            }
            expect(s.digest('base64')).to.equal(refHash, `hash mismatch starting with chunk size ${chunkSizes[sizeIdx]}`);
        }
    });

    it('Should produce identical hash for 3-chunk splits with tab trigger', async () => {
        const body = Buffer.from('\r\n Hello\r\nWorld\r\nContent\there\r\nEnd\r\n');

        let ref = new RelaxedHash('rsa-sha256');
        ref.update(body);
        let refHash = ref.digest('base64');

        for (let i = 1; i < body.length - 1; i++) {
            for (let j = i + 1; j < body.length; j++) {
                let s = new RelaxedHash('rsa-sha256');
                s.update(body.subarray(0, i));
                s.update(body.subarray(i, j));
                s.update(body.subarray(j));
                expect(s.digest('base64')).to.equal(refHash, `hash mismatch at split positions ${i},${j}`);
            }
        }
    });

    it('Should process a very long line', async () => {
        const lineLen = 10 * 1024 * 1024;
        const message = Buffer.alloc(lineLen);
        // Fill the line with printable characters from 0x20 to 0x7E
        for (let i = 1; i < lineLen + 1; i++) {
            message[i] = (i % 95) + 0x20;
        }

        let s = new RelaxedHash('rsa-sha256');
        let buf = s.fixLineBuffer(message);

        expect(buf).to.exist;
    });
});
