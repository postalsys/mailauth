'use strict';

// Calculates relaxed body hash for a message body stream

const { Buffer } = require('node:buffer');
const { parseHeaders } = require('../../lib/tools');
const Writable = require('node:stream').Writable;

/**
 * Class for separating header from body
 *
 * @class
 * @extends Writable
 */
class MessageParser extends Writable {
    constructor(options) {
        super(options);

        this.byteLength = 0;

        this.state = 'header';
        this.stateBytes = [];
        // bytes of the header section seen so far
        this.headerBytes = 0;

        this.headers = false;
        this.headerChunks = [];
    }

    async nextChunk(/* chunk */) {
        // Override in child class
    }

    async finalChunk() {
        // Override in child class
    }

    async messageHeaders() {
        // Override in child class
    }

    // Parses everything collected so far as the header block and hands it over. The body
    // hash and the signatures are only ever built after this has run
    async emitHeaders(chunk) {
        this.state = 'body';
        if (chunk) {
            this.headerChunks.push(chunk);
        }
        this.headers = parseHeaders(Buffer.concat(this.headerChunks));
        await this.messageHeaders(this.headers);
    }

    async processChunk(chunk) {
        if (!chunk || !chunk.length) {
            return;
        }

        if (this.state === 'header') {
            // wait until we have found body part
            for (let i = 0; i < chunk.length; i++) {
                let c = chunk[i];
                this.stateBytes.push(c);
                if (this.stateBytes.length > 4) {
                    this.stateBytes = this.stateBytes.slice(-4);
                }
                this.headerBytes++;

                let b0 = this.stateBytes[this.stateBytes.length - 1];
                let b1 = this.stateBytes.length > 1 && this.stateBytes[this.stateBytes.length - 2];
                let b2 = this.stateBytes.length > 2 && this.stateBytes[this.stateBytes.length - 3];

                if (
                    b0 === 0x0a &&
                    (b1 === 0x0a ||
                        (b1 === 0x0d && b2 === 0x0a) ||
                        // RFC 5322 section 2.1: an empty line ends the header section, and when
                        // the very first line is empty the header section is empty. Everything
                        // after it is body, even if it looks like header fields
                        this.headerBytes === 1 ||
                        (this.headerBytes === 2 && b1 === 0x0d))
                ) {
                    // found header ending
                    if (i === chunk.length - 1) {
                        //end of chunk
                        await this.emitHeaders(chunk);
                        return;
                    }
                    await this.emitHeaders(chunk.slice(0, i + 1));
                    chunk = chunk.slice(i + 1);
                    break;
                }
            }
        }

        if (this.state !== 'body') {
            this.headerChunks.push(chunk);
            return;
        }

        await this.nextChunk(chunk);
    }

    // Rewrites every bare <LF> to <CRLF>. `lastByte` has to follow every byte, the <LF>s
    // included: an <LF> directly after a <CRLF> is a bare one too, and it was left as it was
    // when only the other bytes were tracked
    *ensureLinebreaks(input) {
        let pos = 0;
        for (let i = 0; i < input.length; i++) {
            let c = input[i];
            if (c === 0x0a && this.lastByte !== 0x0d) {
                // emit line break
                let buf;
                if (i === 0 || pos === i) {
                    buf = Buffer.from('\r\n');
                } else {
                    buf = Buffer.concat([input.slice(pos, i), Buffer.from('\r\n')]);
                }
                yield buf;

                pos = i + 1;
            }
            this.lastByte = c;
        }
        if (pos === 0) {
            yield input;
        } else if (pos < input.length) {
            let buf = input.slice(pos);
            yield buf;
        }
    }

    async writeAsync(chunk, encoding) {
        if (!chunk || !chunk.length) {
            return;
        }

        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        for (let partialChunk of this.ensureLinebreaks(chunk)) {
            // separate chunk is emitted for every line that uses \n instead of \r\n
            await this.processChunk(partialChunk);
            this.byteLength += partialChunk.length;
        }
    }

    _write(chunk, encoding, callback) {
        this.writeAsync(chunk, encoding)
            .then(() => callback())
            .catch(err => callback(err));
    }

    async finish() {
        if (!this.headers) {
            // no body, so no empty line ended the header block. Hand the headers out
            // before the final chunk, which is where signatures are checked or created.
            // An input with no bytes at all goes through here too, so that the rest of
            // the pipeline always has a header set to look at
            await this.emitHeaders();
        }

        // generate final hash and emit it
        await this.finalChunk();
    }

    _final(callback) {
        this.finish()
            .then(() => callback())
            .catch(err => callback(err));
    }
}

module.exports = { MessageParser };
