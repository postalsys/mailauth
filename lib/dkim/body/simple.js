'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const { MimeStructureStartFinder } = require('../mime-structure-start-finder');

/**
 * Class for calculating body hash of an email message body stream
 * using the "simple" canonicalization
 *
 * @class
 */
class SimpleHash {
    /**
     * @param {String} [algorithm] Hashing algo, either "sha1" or "sha256"
     * @param {Number} [maxBodyLength] Allowed body length count, the value from the l= parameter
     */
    constructor(algorithm, maxBodyLength) {
        algorithm = (algorithm || 'sha256').split('-').pop();
        this.bodyHash = crypto.createHash(algorithm);

        this.remainder = [];

        // total body size
        this.byteLength = 0;
        // total canonicalized body size
        this.canonicalizedLength = 0;
        // hashed canonicalized body size (after l= tag)
        this.bodyHashedBytes = 0;

        this.maxBodyLength = maxBodyLength;
        this.maxSizeReached = maxBodyLength === 0;

        this.lastNewline = false;

        this.mimeStructureStartFinder = new MimeStructureStartFinder();
    }

    setContentType(contentTypeObj) {
        if (/^multipart\//i.test(contentTypeObj.value) && contentTypeObj.params.boundary) {
            this.mimeStructureStartFinder.setBoundary(contentTypeObj.params.boundary);
        }
    }

    _updateBodyHash(chunk) {
        // serach through the entire document, not just signed part
        this.mimeStructureStartFinder.update(chunk);

        this.canonicalizedLength += chunk.length;

        if (this.maxSizeReached) {
            return;
        }

        // the following is needed for l= option
        if (
            typeof this.maxBodyLength === 'number' &&
            !isNaN(this.maxBodyLength) &&
            this.maxBodyLength >= 0 &&
            this.bodyHashedBytes + chunk.length > this.maxBodyLength
        ) {
            this.maxSizeReached = true;
            if (this.bodyHashedBytes >= this.maxBodyLength) {
                // nothing to do here, skip entire chunk
                return;
            }

            // only use allowed size of bytes
            chunk = chunk.slice(0, this.maxBodyLength - this.bodyHashedBytes);
        }

        this.bodyHashedBytes += chunk.length;
        this.bodyHash.update(chunk);

        //process.stdout.write(chunk);
    }

    update(chunk) {
        this.byteLength += (chunk && chunk.length) || 0;
        if (this.maxSizeReached) {
            return;
        }

        if (this.remainder.length) {
            // see if we can release the last remainder
            for (let i = 0; i < chunk.length; i++) {
                let c = chunk[i];
                if (c !== 0x0a && c !== 0x0d) {
                    // found non-line terminator byte, can release previous chunk
                    for (let remainderChunk of this.remainder) {
                        this._updateBodyHash(remainderChunk);
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

        this._updateBodyHash(chunk);
        this.lastNewline = chunk[chunk.length - 1] === 0x0a;
    }

    digest(encoding) {
        if (!this.lastNewline || !this.bodyHashedBytes) {
            // emit empty line buffer to keep the stream flowing
            this._updateBodyHash(Buffer.from('\r\n'));
        }

        return this.bodyHash.digest(encoding);
    }

    getMimeStructureStart() {
        return this.mimeStructureStartFinder.getMimeStructureStart();
    }
}

module.exports = { SimpleHash };
