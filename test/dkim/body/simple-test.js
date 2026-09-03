/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;
const crypto = require('node:crypto');

let fs = require('node:fs').promises;
let { SimpleHash } = require('../../../lib/dkim/body/simple');

chai.config.includeStack = true;

const getBody = message => {
    message = message.toString('binary');
    let match = message.match(/\r?\n\r?\n/);
    if (match) {
        message = message.substr(match.index + match[0].length);
    }
    return Buffer.from(message.replace(/\r?\n/g, '\r\n'), 'binary');
};

describe('DKIM SimpleBody Tests', () => {
    it('Should calculate sha256 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new SimpleHash('rsa-sha256');
        s.update(message);

        expect(s.digest('base64')).to.equal('frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=');
    });

    it('Should calculate sha1 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new SimpleHash('rsa-sha1');
        s.update(message);

        expect(s.digest('base64')).to.equal('uoq1oCgLlTqpdDX/iUbLy7J1Wic=');
    });

    it('Should calculate body hash byte by byte', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new SimpleHash('rsa-sha256');
        for (let i = 0; i < message.length; i++) {
            s.update(Buffer.from([message[i]]));
        }

        expect(s.digest('base64')).to.equal('GjyEkbey2OupCW5AKJv4dzTPsPHSaZjRDMqUSmhpTyQ=');
    });

    it('Should calculate body hash all at once', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new SimpleHash('rsa-sha256');
        s.update(message);

        expect(s.digest('base64')).to.equal('GjyEkbey2OupCW5AKJv4dzTPsPHSaZjRDMqUSmhpTyQ=');
    });

    it('Should calculate body hash with l=0', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new SimpleHash('rsa-sha256', 0);
        s.update(message);

        expect(s.digest('base64')).to.equal('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });

    it('Should calculate body hash with l=20', async () => {
        let s = new SimpleHash('rsa-sha256', 20);
        s.update(Buffer.from('tere tere\r\n \r\nvana kere\r\n\r\n'));

        expect(s.digest('base64')).to.equal(
            crypto
                .createHash('sha256')
                .update(Buffer.from(['tere tere\r\n', ' \r\n', 'vana k'].join('')))
                .digest('base64')
        );
    });

    describe('Canonicalization edge cases', () => {
        // reference implementation of RFC 6376 section 3.4.3, see the reasoning on
        // SimpleHash.digest in lib/dkim/body/simple.js
        const reference = body => {
            const buf = Buffer.from(body, 'binary');
            let end = buf.length;
            while (end > 0 && buf[end - 1] === 0x0a) {
                end -= 1;
                if (end > 0 && buf[end - 1] === 0x0d) {
                    end -= 1;
                }
            }
            return crypto
                .createHash('sha256')
                .update(Buffer.concat([buf.subarray(0, end), Buffer.from('\r\n')]))
                .digest('base64');
        };

        const hashChunks = chunks => {
            const s = new SimpleHash('rsa-sha256');
            for (const chunk of chunks) {
                s.update(Buffer.from(chunk, 'binary'));
            }
            return s.digest('base64');
        };

        for (const body of [
            '',
            'abc',
            'abc\r\n',
            'abc\r\n\r\n\r\n',
            // a lone <CR> is content, not a line ending
            'abc\r',
            'abc\r\r\n',
            'abc\r\r',
            'a\r\n\r',
            '\r',
            '\r\r\n',
            'x\r\ny\r',
            'a\rb\r\n'
        ]) {
            it(`Should canonicalize ${JSON.stringify(body)} as RFC 6376 section 3.4.3 does`, () => {
                expect(hashChunks([body])).to.equal(reference(body));
            });
        }

        it('Should count line endings at the end of the body instead of buffering them', () => {
            // the message parser hands over one small buffer per line, and each of those
            // pins the pool it came from, so a body of bare line breaks used to be
            // retained about two hundred times over
            const s = new SimpleHash('rsa-sha256');
            for (let i = 0; i < 5000; i++) {
                s.update(Buffer.from('\r\n'));
            }
            expect(s.pendingLineBreaks).to.equal(5000);
            expect(s.remainder).to.have.lengthOf(0);
            expect(s.digest('base64')).to.equal(reference(''));
        });

        it('Should keep held back bytes that are not whole CRLF pairs', () => {
            // a lone <CR> cannot be stood in for by the counter, so the exact bytes are
            // kept. Pairs counted before them stay counted, they are emitted first anyway
            const s = new SimpleHash('rsa-sha256');
            s.update(Buffer.from('a'));
            s.update(Buffer.from('\r\n'));
            s.update(Buffer.from('\r'));
            s.update(Buffer.from('b'));
            expect(s.digest('base64')).to.equal(reference('a\r\n\rb'));
        });

        it('Should give the same hash whatever the chunk boundaries are', () => {
            for (const body of ['abc\r', 'a\r\n\r', 'abc\r\r\n', 'x\r\ny\r\r\n\r\n', 'a\rb\r\nc']) {
                const refHash = reference(body);
                for (let i = 1; i < body.length; i++) {
                    expect(hashChunks([body.slice(0, i), body.slice(i)])).to.equal(refHash, `hash mismatch for ${JSON.stringify(body)} at split ${i}`);
                }
                // one byte at a time
                expect(hashChunks(body.split(''))).to.equal(refHash, `hash mismatch for ${JSON.stringify(body)} split bytewise`);
            }
        });
    });
});
