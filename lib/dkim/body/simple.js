'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const { MimeStructureStartFinder } = require('../mime-structure-start-finder');

const { CHAR_CR, CHAR_LF, CRLF, eachHeldLineBreak } = require('./line-endings');

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

        // line endings at the end of the body, held back until it is known whether content
        // follows them. Whole CRLF pairs are only counted, see ./line-endings
        this.remainder = [];
        this.pendingLineBreaks = 0;

        // total body size
        this.byteLength = 0;
        // total canonicalized body size
        this.canonicalizedLength = 0;
        // hashed canonicalized body size (after l= tag)
        this.bodyHashedBytes = 0;

        this.maxBodyLength = maxBodyLength;
        this.maxSizeReached = maxBodyLength === 0;

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
        if (!chunk || !chunk.length) {
            return;
        }

        this.byteLength += chunk.length;
        if (this.maxSizeReached) {
            return;
        }

        // Find the line endings at the end of the chunk. They may be the *CRLF that ends
        // the body, which digest() collapses, and a trailing <CR> may still pair up with
        // an <LF> that opens the next chunk, so whether they are line endings is only
        // known once something follows them. Peeling whole CRLF pairs first is what tells
        // _holdBack the run can be counted rather than kept, without a second pass over it
        let pairEnd = chunk.length;
        while (pairEnd >= 2 && chunk[pairEnd - 2] === CHAR_CR && chunk[pairEnd - 1] === CHAR_LF) {
            pairEnd -= 2;
        }

        let end = pairEnd;
        while (end > 0 && (chunk[end - 1] === CHAR_LF || chunk[end - 1] === CHAR_CR)) {
            end -= 1;
        }

        if (end) {
            this._drainHeldLineEndings();
            this._updateBodyHash(chunk.subarray(0, end));
        }

        if (end < chunk.length) {
            this._holdBack(chunk, end, pairEnd);
        }
    }

    _holdBack(chunk, end, pairEnd) {
        if (!this.remainder.length && end === pairEnd) {
            // nothing but whole CRLF pairs, and nothing kept before them to stay behind
            this.pendingLineBreaks += (chunk.length - pairEnd) / 2;
            return;
        }

        // a lone <CR> or <LF> the counter can not stand in for, so keep the exact bytes.
        // Anything counted so far stays counted, it comes first either way
        this.remainder.push(chunk.subarray(end));
    }

    _drainHeldLineEndings() {
        eachHeldLineBreak(this.pendingLineBreaks, lineBreaks => this._updateBodyHash(lineBreaks));
        this.pendingLineBreaks = 0;

        for (let heldChunk of this.remainder) {
            this._updateBodyHash(heldChunk);
        }
        this.remainder = [];
    }

    digest(encoding) {
        // RFC 6376 section 3.4.3: "simple" makes no changes to the body beyond converting
        // the *CRLF at its end to a single CRLF. A <CR> that no <LF> follows does not end
        // a line, so it is body content and stays where it is. A lone <LF> is taken as a
        // line ending, the same way RelaxedHash takes it, and mailauth's message parser
        // has already rewritten those to CRLF for anything read off the wire
        let trailer = this.remainder.length === 1 ? this.remainder[0] : Buffer.concat(this.remainder);
        let end = trailer.length;
        while (end > 0 && trailer[end - 1] === CHAR_LF) {
            end -= 1;
            if (end > 0 && trailer[end - 1] === CHAR_CR) {
                end -= 1;
            }
        }

        if (end) {
            // content survived among the kept bytes, so the pairs counted before them are
            // inside the body rather than at its end and have to be hashed after all
            eachHeldLineBreak(this.pendingLineBreaks, lineBreaks => this._updateBodyHash(lineBreaks));
            this._updateBodyHash(trailer.subarray(0, end));
        }
        // whatever is still held is the *CRLF at the end of the body, and collapses below
        this.pendingLineBreaks = 0;

        // a body with no trailing CRLF, and an empty body, both get one
        this._updateBodyHash(CRLF);

        return this.bodyHash.digest(encoding);
    }

    getMimeStructureStart() {
        return this.mimeStructureStartFinder.getMimeStructureStart();
    }
}

module.exports = { SimpleHash };
