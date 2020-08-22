'use strict';

// Calculates simple body hash for a message body stream

const { parseHeaders } = require('../../../lib/tools');
const Writable = require('stream').Writable;
const crypto = require('crypto');

/**
 * Class for calculating body hash of an email message body stream using the "simple" algo
 *
 * @class
 * @extends Writable
 */
class SimpleBody extends Writable {
    /**
     * @param {Object} [options DKIM configuration options
     * @param {String} [options.algorithm="sha256"] Hashing algo, either "sha1" or "sha256"
     * @param {Number} [options.maxBodyLength] Allowed body length count, the value from the l= parameter
     */
    constructor(options) {
        super();
        options = options || {};
        this.chunkBuffer = [];
        this.chunkBufferLen = 0;
        let hashAlgo = (options.algorithm || 'sha256').split('-').pop();
        this.bodyHash = crypto.createHash(hashAlgo);
        this.remainder = []; // Array of Buffers
        this.byteLength = 0;

        this.state = 'header';
        this.stateBytes = [];

        this.headers = false;
        this.headerChunks = [];

        this.lastByte = false;

        this.bodyHashedBytes = 0;
        this.maxBodyLength = options.maxBodyLength;
    }

    updateBodyHash(chunk) {
        // the following is needed for l= option
        if (
            typeof this.maxBodyLength === 'number' &&
            !isNaN(this.maxBodyLength) &&
            this.maxBodyLength >= 0 &&
            this.bodyHashedBytes + chunk.length > this.maxBodyLength
        ) {
            if (this.bodyHashedBytes >= this.maxBodyLength) {
                // nothing to do here, skip entire chunk
                return;
            }
            // only use allowed size of bytes
            chunk = chunk.slice(0, this.maxBodyLength - this.bodyHashedBytes);
        }

        this.bodyHashedBytes += chunk.length;
        this.bodyHash.update(chunk);
    }

    processChunk(chunk, final) {
        if (final) {
            // disregard cached newline chunks, instead use a single linebreak
            this.updateBodyHash(Buffer.from('\r\n'));
            this.remainder = [];
            return;
        }

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

                let b0 = this.stateBytes[this.stateBytes.length - 1];
                let b1 = this.stateBytes.length > 1 && this.stateBytes[this.stateBytes.length - 2];
                let b2 = this.stateBytes.length > 2 && this.stateBytes[this.stateBytes.length - 3];

                if (b0 === 0x0a && (b1 === 0x0a || (b1 === 0x0d && b2 === 0x0a))) {
                    // found header ending
                    this.state = 'body';
                    if (i === chunk.length - 1) {
                        //end of chunk
                        this.headerChunks.push(chunk);
                        this.headers = parseHeaders(Buffer.concat(this.headerChunks));
                        return;
                    }
                    this.headerChunks.push(chunk.slice(0, i + 1));
                    this.headers = parseHeaders(Buffer.concat(this.headerChunks));
                    chunk = chunk.slice(i + 1);
                    break;
                }
            }
        }

        if (this.state !== 'body') {
            this.headerChunks.push(chunk);
            return;
        }

        if (this.remainder.length) {
            // see if we can release the last remainder
            for (let i = 0; i < chunk.length; i++) {
                let c = chunk[i];
                if (c !== 0x0a && c !== 0x0d) {
                    // found non-line terminator byte, can release previous chunk
                    for (let remainderChunk of this.remainder) {
                        this.updateBodyHash(remainderChunk);
                    }
                    this.remainder = [];
                }
            }
        }

        // find line terminators from the end of chunk
        let matchStart = false;
        for (let i = chunk.length - 1; i >= 0; i--) {
            let c = chunk[i];
            if (c === 0x0a || c === 0x0d) {
                // stop looking
                matchStart = i;
            } else {
                break;
            }
        }

        if (matchStart === 0) {
            // nothing but newlines in this chunk
            this.remainder.push(chunk);
            return;
        } else if (matchStart !== false) {
            this.remainder.push(chunk.slice(matchStart));
            chunk = chunk.slice(0, matchStart);
        }

        this.updateBodyHash(chunk);
    }

    *ensureLinebreaks(input) {
        let pos = 0;
        for (let i = 0; i < input.length; i++) {
            let c = input[i];
            if (c !== 0x0a) {
                this.lastByte = c;
            } else if (this.lastByte !== 0x0d) {
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
        }
        if (pos === 0) {
            yield input;
        } else if (pos < input.length) {
            let buf = input.slice(pos);
            yield buf;
        }
    }

    _write(chunk, encoding, callback) {
        if (!chunk || !chunk.length) {
            return callback();
        }

        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        for (let partialChunk of this.ensureLinebreaks(chunk)) {
            // separate chunk is emitted for every line that uses \n instead of \r\n
            this.processChunk(partialChunk);
            this.byteLength += partialChunk.length;
        }

        callback();
    }

    _final(callback) {
        // generate final hash and emit it
        this.processChunk(false, true);

        // finalize
        this.bodyHash = this.bodyHash.digest('base64');
        if (!this.headers && this.headerChunks.length) {
            this.headers = parseHeaders(Buffer.concat(this.headerChunks));
        }
        callback();
    }
}

module.exports = { SimpleBody };
