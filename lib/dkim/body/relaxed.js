'use strict';

// Calculates relaxed body hash for a message body stream

const crypto = require('crypto');

/**
 * Class for calculating body hash of an email message body stream
 * using the "relaxed" canonicalization
 *
 * @class
 */
class RelaxedHash {
    /**
     * @param {String} [algorithm] Hashing algo, either "sha1" or "sha256"
     * @param {Number} [maxBodyLength] Allowed body length count, the value from the l= parameter
     */
    constructor(algorithm, maxBodyLength) {
        algorithm = (algorithm || 'sha256').split('-').pop();
        this.bodyHash = crypto.createHash(algorithm);

        this.remainder = '';
        this.byteLength = 0;

        this.bodyHashedBytes = 0;
        this.maxBodyLength = maxBodyLength;
    }

    _updateBodyHash(chunk) {
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

    update(chunk) {
        this.byteLength += chunk.length;

        let bodyStr;

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

        this._updateBodyHash(chunk);
    }

    digest(encoding) {
        if (/[\r\n]$/.test(this.remainder) && this.bodyHashedBytes > 0) {
            // add terminating line end
            this._updateBodyHash(Buffer.from('\r\n'));
        }

        // finalize
        return this.bodyHash.digest(encoding);
    }
}

module.exports = { RelaxedHash };
