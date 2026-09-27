/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { MessageParser } = require('../../lib/dkim/message-parser');

chai.config.includeStack = true;

class Capture extends MessageParser {
    constructor() {
        super();
        this.body = [];
    }

    async nextChunk(chunk) {
        this.body.push(Buffer.from(chunk));
    }
}

// runs a message through the parser, whole or in chunks of `chunkSize` bytes
const parse = (input, chunkSize) =>
    new Promise((resolve, reject) => {
        const parser = new Capture();
        parser.on('finish', () =>
            resolve({
                headers: parser.headers.parsed.map(header => header.line.toString('binary')),
                body: Buffer.concat(parser.body).toString('binary')
            })
        );
        parser.on('error', reject);
        const buf = Buffer.from(input, 'binary');
        if (!chunkSize) {
            parser.end(buf);
            return;
        }
        for (let i = 0; i < buf.length; i += chunkSize) {
            parser.write(buf.subarray(i, i + chunkSize));
        }
        parser.end();
    });

describe('MessageParser', () => {
    describe('Line endings', () => {
        // every bare LF is a line break of its own, and becomes a CRLF
        const cases = [
            ['a\nb\n', 'a\r\nb\r\n'],
            ['a\n\nb', 'a\r\n\r\nb'],
            ['\nb', '\r\nb'],
            ['x\r\n\nb', 'x\r\n\r\nb'],
            ['x\r\n\n\nb', 'x\r\n\r\n\r\nb'],
            ['a\r\nb\n', 'a\r\nb\r\n'],
            ['a\r\n\r\nb', 'a\r\n\r\nb'],
            ['ab\n\n', 'ab\r\n\r\n']
        ];

        for (let [body, expected] of cases) {
            for (let chunkSize of [0, 1, 2]) {
                it(`Should normalize ${JSON.stringify(body)}${chunkSize ? ` in ${chunkSize} byte chunks` : ''}`, async () => {
                    let { body: parsed } = await parse(`Subject: x\r\n\r\n${body}`, chunkSize);
                    expect(parsed).to.equal(expected);
                });
            }
        }

        it('Should normalize an LF right after a CRLF in the generator itself', () => {
            const parser = new MessageParser();
            const out = Buffer.concat([...parser.ensureLinebreaks(Buffer.from('a\r\n\nb'))]).toString();
            expect(out).to.equal('a\r\n\r\nb');
        });
    });

    describe('Header section', () => {
        it('Should read a leading empty line as an empty header section (RFC 5322 section 2.1)', async () => {
            for (let input of ['\r\nFrom: fake@bank.example\r\n\r\nbody\r\n', '\nFrom: fake@bank.example\n\nbody\n']) {
                for (let chunkSize of [0, 1]) {
                    let { headers, body } = await parse(input, chunkSize);
                    expect(headers, JSON.stringify(input)).to.deep.equal([]);
                    expect(body, JSON.stringify(input)).to.equal('From: fake@bank.example\r\n\r\nbody\r\n');
                }
            }
        });

        it('Should still split an ordinary message after its first empty line', async () => {
            for (let chunkSize of [0, 1]) {
                let { headers, body } = await parse('Subject: a\r\nFrom: b@example.com\r\n\r\nbody\r\n', chunkSize);
                expect(headers).to.deep.equal(['Subject: a', 'From: b@example.com']);
                expect(body).to.equal('body\r\n');
            }
        });
    });
});
