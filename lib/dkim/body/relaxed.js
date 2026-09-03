/* eslint no-control-regex: 0 */

'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const { MimeStructureStartFinder } = require('../mime-structure-start-finder');

const { CHAR_CR, CHAR_LF, CRLF, eachHeldLineBreak } = require('./line-endings');

const CHAR_SPACE = 0x20;
const CHAR_TAB = 0x09;

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
        algorithm = (algorithm || 'sha256').split('-').pop().toLowerCase();

        this.bodyHash = crypto.createHash(algorithm);

        this.remainder = false;

        // total body size
        this.byteLength = 0;
        // total canonicalized body size
        this.canonicalizedLength = 0;
        // hashed canonicalized body size (after l= tag)
        this.bodyHashedBytes = 0;

        this.maxBodyLength = maxBodyLength;

        this.maxSizeReached = maxBodyLength === 0;

        // number of empty lines seen at the end of the body so far. They are hashed only
        // once it is known that more content follows them
        this.pendingLineBreaks = 0;

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

        // the following is needed for the l= option
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
            chunk = chunk.subarray(0, this.maxBodyLength - this.bodyHashedBytes);
        }

        this.bodyHashedBytes += chunk.length;
        this.bodyHash.update(chunk);

        //process.stdout.write(chunk);
    }

    _drainPendingEmptyLines() {
        eachHeldLineBreak(this.pendingLineBreaks, lineBreaks => this._updateBodyHash(lineBreaks));
        this.pendingLineBreaks = 0;
    }

    _pushBodyHash(chunk) {
        if (!chunk || !chunk.length) {
            return;
        }

        // Count the line endings at the end of the chunk: these are the empty lines that
        // are dropped if no more content follows. Everything that reaches this method has
        // already been canonicalized, so the run is always whole CRLF pairs, see
        // ./line-endings for why they are counted rather than kept
        let end = chunk.length;
        while (end >= 2 && chunk[end - 2] === CHAR_CR && chunk[end - 1] === CHAR_LF) {
            end -= 2;
        }

        if (!end) {
            this.pendingLineBreaks += chunk.length / 2;
            return;
        }

        this._drainPendingEmptyLines();
        this.pendingLineBreaks = (chunk.length - end) / 2;

        this._updateBodyHash(chunk.subarray(0, end));
    }

    /**
     * Performs the following modifications for a single line:
     *  - Replace all <LF> chars with <CR><LF>
     *  - Replace all spaces and tabs with a single space.
     *  - Remove trailing whitespace
     * @param {Buffer} line
     * @returns {Buffer} fixed line
     */
    fixLineBuffer(line) {
        // Allocate maximum expected buffer length
        // If the line is only filled with <LF> bytes then we need 2 times the size of the line
        let lineBuf = Buffer.alloc(line.length * 2);
        // Start processing the line from the end to beginning
        let writePos = lineBuf.length - 1;

        let nonWspFound = false;
        let prevWsp = false;

        for (let i = line.length - 1; i >= 0; i--) {
            if (line[i] === CHAR_LF) {
                lineBuf[writePos--] = CHAR_LF;
                lineBuf[writePos--] = CHAR_CR;
                if (i > 0 && line[i - 1] === CHAR_CR) {
                    // the <CR> of the line ending, any other <CR> is content
                    i--;
                }
                // the scan has crossed into the previous line, whose own trailing
                // whitespace has to go the same way
                nonWspFound = false;
                prevWsp = false;
                continue;
            }

            if (line[i] === CHAR_SPACE || line[i] === CHAR_TAB) {
                if (nonWspFound) {
                    prevWsp = true;
                }
                continue;
            }

            if (prevWsp) {
                lineBuf[writePos--] = CHAR_SPACE;
                prevWsp = false;
            }

            nonWspFound = true;
            lineBuf[writePos--] = line[i];
        }

        if (prevWsp && nonWspFound) {
            lineBuf[writePos--] = CHAR_SPACE;
        }

        return lineBuf.subarray(writePos + 1);
    }

    update(chunk, final) {
        this.byteLength += (chunk && chunk.length) || 0;
        if (this.maxSizeReached) {
            return;
        }

        // Canonicalize content by applying a and b in order:
        // a.1. Ignore all whitespace at the end of lines.
        // a.2. Reduce all sequences of WSP within a line to a single SP character.

        // b.1. Ignore all empty lines at the end of the message body.
        // b.2. If the body is non-empty but does not end with a CRLF, a CRLF is added.

        let lineEndPos = -1;
        let lineNeedsFixing = false;
        let cursorPos = 0;

        if (this.remainder && this.remainder.length) {
            if (chunk) {
                // concatting chunks might be bad for performance :S
                chunk = Buffer.concat([this.remainder, chunk]);
            } else {
                chunk = this.remainder;
            }
            this.remainder = false;
        }

        if (chunk && chunk.length) {
            for (let pos = 0; pos < chunk.length; pos++) {
                switch (chunk[pos]) {
                    case CHAR_LF:
                        if (
                            !lineNeedsFixing &&
                            // previous character is not <CR>
                            ((pos >= 1 && chunk[pos - 1] !== CHAR_CR) ||
                                // LF is the first byte on the line
                                pos === 0 ||
                                // there's a space before line break
                                (pos >= 2 && chunk[pos - 1] === CHAR_CR && chunk[pos - 2] === CHAR_SPACE))
                        ) {
                            lineNeedsFixing = true;
                        }

                        // line break
                        if (lineNeedsFixing) {
                            // emit pending bytes up to the last line break before current line
                            if (lineEndPos >= 0 && lineEndPos >= cursorPos) {
                                let chunkPart = chunk.subarray(cursorPos, lineEndPos + 1);
                                this._pushBodyHash(chunkPart);
                            }

                            let line = chunk.subarray(lineEndPos + 1, pos + 1);
                            this._pushBodyHash(this.fixLineBuffer(line));

                            lineNeedsFixing = false;

                            // move cursor to the start of next line
                            cursorPos = pos + 1;
                        }

                        lineEndPos = pos;

                        break;

                    case CHAR_SPACE:
                        if (!lineNeedsFixing && pos && chunk[pos - 1] === CHAR_SPACE) {
                            lineNeedsFixing = true;
                        }
                        break;

                    case CHAR_TAB:
                        // non-space WSP always needs replacing
                        lineNeedsFixing = true;
                        break;

                    default:
                }
            }
        }

        if (chunk && cursorPos < chunk.length && cursorPos !== lineEndPos) {
            // emit data from chunk

            let chunkPart = chunk.subarray(cursorPos, lineEndPos + 1);

            if (chunkPart.length) {
                // batch contains only complete lines verified as not needing fixing at their LFs
                this._pushBodyHash(chunkPart);
            }

            cursorPos = lineEndPos + 1;
        }

        if (chunk && !final && cursorPos < chunk.length) {
            this.remainder = chunk.subarray(cursorPos);
        }

        if (final) {
            let chunkPart = (cursorPos && chunk && chunk.subarray(cursorPos)) || chunk;
            if (chunkPart && chunkPart.length) {
                // The last line has no line ending, so the scan above never looked at its
                // trailing whitespace. A single trailing space is the only thing it can
                // have missed: a run of them, and an HTAB anywhere, both set
                // lineNeedsFixing, and nothing clears it again before the end of the line
                this._pushBodyHash(lineNeedsFixing || chunkPart[chunkPart.length - 1] === CHAR_SPACE ? this.fixLineBuffer(chunkPart) : chunkPart);
            }

            if (this.bodyHashedBytes) {
                // terminating line break for non-empty messages
                this._updateBodyHash(CRLF);
            }
        }
    }

    digest(encoding) {
        this.update(null, true);

        // finalize
        return this.bodyHash.digest(encoding);
    }

    getMimeStructureStart() {
        return this.mimeStructureStartFinder.getMimeStructureStart();
    }
}

module.exports = { RelaxedHash };
