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
        this.remainder = '';
        this.byteLength = 0;

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
        // TODO: convert "*CRLF" at the end of the body to a single "CRLF"

        this.updateBodyHash(chunk);
    }

    _transform(chunk, encoding, callback) {
        if (!chunk || !chunk.length) {
            return callback();
        }

        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        this.processChunk(chunk);

        this.byteLength += chunk.length;
        this.push(chunk);
        callback();
    }

    _flush(callback) {
        // generate final hash and emit it
        if (/[\r\n]$/.test(this.remainder) && this.byteLength > 2) {
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

module.exports = { SimpleBody };
