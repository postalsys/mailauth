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

    describe('Canonicalization edge cases', () => {
        const hashOf = body => crypto.createHash('sha256').update(Buffer.from(body, 'binary')).digest('base64');

        // hashes a body handed over in the given chunks
        const hashChunks = chunks => {
            const s = new RelaxedHash('rsa-sha256');
            for (const chunk of chunks) {
                s.update(chunk);
            }
            return s.digest('base64');
        };

        // line based reference of RFC 6376 section 3.4.4: the <CR> of a terminated line is part
        // of the line ending, a <CR> at the end of an unterminated last line is content
        const reference = body => {
            const lines = body.split('\n');
            const last = lines.pop();
            const canon = line => line.replace(/[ \t]+/g, ' ').replace(/ $/, '');
            const out = lines.map(line => canon(line.replace(/\r$/, '')));
            out.push(canon(last));
            while (out.length && out[out.length - 1] === '') {
                out.pop();
            }
            return out.length ? out.join('\r\n') + '\r\n' : '';
        };

        // small deterministic PRNG (Park-Miller minimal standard) so a failure is reproducible
        const prng = seed => () => {
            seed = (seed * 48271) % 2147483647;
            return seed / 2147483647;
        };

        // every row fails with the canonicalization this file pinned before
        const cases = [
            ['a trailing space on an unterminated last line', 'abc ', 'abc\r\n'],
            ['a space only unterminated last line', 'abc\r\n ', 'abc\r\n'],
            ['a CR at the end of the body as content', 'abc\r', 'abc\r\r\n'],
            ['a CR before the line ending CR as content', 'abc\r\r\n', 'abc\r\r\n'],
            ['whitespace before a content CR as a space', ' \r', ' \r\r\n'],
            ['whitespace between a content CR and the line ending as trailing', 'a\r \r\n', 'a\r\r\n'],
            ['a body of a single CR', '\r', '\r\r\n'],
            ['a lone CR after a line break as content, not an empty line', 'a\r\n\r', 'a\r\n\r\r\n']
        ];

        for (const [name, body, expected] of cases) {
            it('Should handle ' + name, () => {
                expect(hashChunks([Buffer.from(body, 'binary')])).to.equal(hashOf(expected));
            });
        }

        it('Should match the line based reference for generated bodies', () => {
            const random = prng(20260902);
            const pick = n => Math.floor(random() * n);
            const alphabet = ['a', 'b', ' ', ' ', '\t', '\r\n', '\r\n', '\n', '\r'];

            for (let i = 0; i < 2000; i++) {
                let body = '';
                const len = pick(24);
                for (let j = 0; j < len; j++) {
                    body += alphabet[pick(alphabet.length)];
                }
                const bytes = Buffer.from(body, 'binary');
                const chunks = [];
                for (let pos = 0; pos < bytes.length;) {
                    const size = 1 + pick(5);
                    chunks.push(bytes.subarray(pos, pos + size));
                    pos += size;
                }
                expect(hashChunks(chunks), 'body ' + JSON.stringify(body)).to.equal(hashOf(reference(body)));
            }
        });

        it('Should drop the trailing whitespace of every line it crosses', () => {
            // fixLineBuffer walks a line backwards, so it has to forget what it saw on the
            // line to the right of a line ending before it looks at the line to the left
            const s = new RelaxedHash('rsa-sha256');
            const fix = input => s.fixLineBuffer(Buffer.from(input, 'binary')).toString('binary');

            expect(fix('a \nb')).to.equal('a\r\nb');
            expect(fix('a\t\r\nb')).to.equal('a\r\nb');
            expect(fix(' \na')).to.equal('\r\na');
            expect(fix('a  \nb  \nc')).to.equal('a\r\nb\r\nc');
            expect(fix('a b \nc  d')).to.equal('a b\r\nc d');
        });

        it('Should count empty lines at the end of the body instead of buffering them', () => {
            // one buffer per empty line, each pinning the pool it was allocated from, made
            // a body of bare line breaks retain about 200 times its own size
            const s = new RelaxedHash('rsa-sha256');
            for (let i = 0; i < 5000; i++) {
                s.update(Buffer.from('\r\n'));
            }
            expect(s.pendingLineBreaks).to.equal(5000);
            expect(s.digest('base64')).to.equal(hashOf(''));
        });

        it('Should not canonicalize a last line that needs no fixing', () => {
            // counts how often the last line was handed to fixLineBuffer
            const fixCalls = body => {
                const s = new RelaxedHash('rsa-sha256');
                const fixLineBuffer = s.fixLineBuffer.bind(s);
                let calls = 0;
                s.fixLineBuffer = buf => {
                    calls++;
                    return fixLineBuffer(buf);
                };

                s.update(Buffer.from(body, 'binary'));
                // the last line is only canonicalized by digest(), so read the count after
                const digest = s.digest('base64');
                return { calls, digest };
            };

            for (const [body, expected, calls] of [
                ['abc\r\ndef', 'abc\r\ndef\r\n', 0],
                ['abc\r\ndef ', 'abc\r\ndef\r\n', 1]
            ]) {
                expect(fixCalls(body)).to.deep.equal({ calls, digest: hashOf(expected) }, 'body ' + JSON.stringify(body));
            }
        });
    });
});
