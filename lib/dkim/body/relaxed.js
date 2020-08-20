'use strict';

// Calculates relaxed body hash for a message body stream

const { parseHeaders } = require('../../../lib/tools');
const Transform = require('stream').Transform;
const crypto = require('crypto');

/**
 * Class for calculating body hash of an email message body stream using the "relaxed" algo
 *
 * @class
 * @extends Transform
 */
class RelaxedBody extends Transform {
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
        this.remainder = '';
        this.byteLength = 0;

        this.state = 'header';
        this.stateBytes = [];
        this.headerChunks = [];

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

    processChunk(chunk) {
        let bodyStr;

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
                        this.emit('headers', parseHeaders(Buffer.concat(this.headerChunks)));
                        return;
                    }
                    this.headerChunks.push(chunk.slice(0, i + 1));
                    this.emit('headers', parseHeaders(Buffer.concat(this.headerChunks)));
                    chunk = chunk.slice(i + 1);
                    break;
                }
            }
        }

        if (this.state !== 'body') {
            this.headerChunks.push(chunk);
            return;
        }

        // find next remainder
        let nextRemainder = '';

        // This crux finds and removes the spaces from the last line and the newline characters after the last non-empty line
        // If we get another chunk that does not match this description then we can restore the previously processed data
        let state = 'file';
        for (let i = chunk.length - 1; i >= 0; i--) {
            let c = chunk[i];

            if (state === 'file' && (c === 0x0a || c === 0x0d)) {
                // do nothing, found \n or \r at the end of chunk, stil end of file
            } else if (state === 'file' && (c === 0x09 || c === 0x20)) {
                // switch to line ending mode, this is the last non-empty line
                state = 'line';
            } else if (state === 'line' && (c === 0x09 || c === 0x20)) {
                // do nothing, found ' ' or \t at the end of line, keep processing the last non-empty line
            } else if (state === 'file' || state === 'line') {
                // non line/file ending character found, switch to body mode
                state = 'body';
                if (i === chunk.length - 1) {
                    // final char is not part of line end or file end, so do nothing
                    break;
                }
            }

            if (i === 0) {
                // reached to the beginning of the chunk, check if it is still about the ending
                // and if the remainder also matches
                if (
                    (state === 'file' && (!this.remainder || /[\r\n]$/.test(this.remainder))) ||
                    (state === 'line' && (!this.remainder || /[ \t]$/.test(this.remainder)))
                ) {
                    // keep everything
                    this.remainder += chunk.toString('binary');
                    return;
                } else if (state === 'line' || state === 'file') {
                    // process existing remainder as normal line but store the current chunk
                    nextRemainder = chunk.toString('binary');
                    chunk = false;
                    break;
                }
            }

            if (state !== 'body') {
                continue;
            }

            // reached first non ending byte
            nextRemainder = chunk.slice(i + 1).toString('binary');
            chunk = chunk.slice(0, i + 1);
            break;
        }

        let needsFixing = !!this.remainder;
        if (chunk && !needsFixing) {
            // check if we even need to change anything
            for (let i = 0, len = chunk.length; i < len; i++) {
                if (i && chunk[i] === 0x0a && chunk[i - 1] !== 0x0d) {
                    // missing \r before \n
                    needsFixing = true;
                    break;
                } else if (i && chunk[i] === 0x0d && chunk[i - 1] === 0x20) {
                    // trailing WSP found
                    needsFixing = true;
                    break;
                } else if (i && chunk[i] === 0x20 && chunk[i - 1] === 0x20) {
                    // multiple spaces found, needs to be replaced with just one
                    needsFixing = true;
                    break;
                } else if (chunk[i] === 0x09) {
                    // TAB found, needs to be replaced with a space
                    needsFixing = true;
                    break;
                }
            }
        }

        if (needsFixing) {
            bodyStr = this.remainder + (chunk ? chunk.toString('binary') : '');
            this.remainder = nextRemainder;
            bodyStr = bodyStr
                .replace(/\r?\n/g, '\n') // use js line endings
                .replace(/[ \t]*$/gm, '') // remove line endings, rtrim
                .replace(/[ \t]+/gm, ' ') // single spaces
                .replace(/\n/g, '\r\n'); // restore rfc822 line endings
            chunk = Buffer.from(bodyStr, 'binary');
        } else if (nextRemainder) {
            this.remainder = nextRemainder;
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
        if (/[\r\n]$/.test(this.remainder) && this.hashedBytes > 0) {
            // add terminating line end
            this.updateBodyHash(Buffer.from('\r\n'));
        }

        if (!this.byteLength) {
            // emit empty line buffer to keep the stream flowing
            this.push(Buffer.from('\r\n'));
            // this.updateBodyHash(Buffer.from('\r\n'));
        }

        this.emit('hash', this.bodyHash.digest('base64'));
        callback();
    }
}

module.exports = { RelaxedBody };
