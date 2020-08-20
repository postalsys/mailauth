'use strict';

// Calculates simple body hash for a message body stream

const Transform = require('stream').Transform;
const crypto = require('crypto');

/**
 * Class for calculating body hash of an email message body stream using the "simple" algo
 *
 * @class
 * @extends Transform
 */
class SimpleBody extends Transform {
    /**
     * @param {Object} [options DKIM configuration options
     * @param {String} [options.hashAlgo="sha256"] Hashing algo, either "sha1" or "sha256"
     * @param {Number} [options.maxBodyLength] Allowed body length count, the value from the l= parameter
     */
    constructor(options) {
        super();
        options = options || {};
        this.chunkBuffer = [];
        this.chunkBufferLen = 0;
        this.bodyHash = crypto.createHash(options.hashAlgo || 'sha256');
        this.remainder = []; // Array of Buffers
        this.byteLength = 0;

        this.lastByte = false;

        this.hashedBytes = 0;
        this.maxBodyLength = options.maxBodyLength;
    }

    updateBodyHash(chunk) {
        // the following is needed for l= option
        if (
            typeof this.maxBodyLength === 'number' &&
            !isNaN(this.maxBodyLength) &&
            this.maxBodyLength >= 0 &&
            this.hashedBytes + chunk.length > this.maxBodyLength
        ) {
            if (this.hashedBytes >= this.maxBodyLength) {
                // nothing to do here, skip entire chunk
                return;
            }
            // only use allowed size of bytes
            chunk = chunk.slice(0, this.maxBodyLength - this.hashedBytes);
        }

        this.hashedBytes += chunk.length;
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

    _transform(chunk, encoding, callback) {
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
            this.push(partialChunk);
        }

        callback();
    }

    _flush(callback) {
        // generate final hash and emit it
        this.processChunk(false, true);

        if (!this.byteLength) {
            // emit empty line buffer to keep the stream flowing
            this.push(Buffer.from('\r\n'));
        }

        this.emit('hash', this.bodyHash.digest('base64'));
        callback();
    }
}

module.exports = { SimpleBody };
