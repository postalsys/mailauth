/* eslint no-control-regex: 0 */

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import type { BinaryToTextEncoding, Hash } from 'node:crypto';
import { MimeStructureStartFinder } from '../mime-structure-start-finder.js';

import { CHAR_CR, CHAR_LF, CRLF, eachHeldLineBreak } from './line-endings.js';
import { PrefixHashes } from './prefix-hashes.js';
import type { BodyContentType, MaxBodyLength } from './simple.js';

const CHAR_SPACE = 0x20;
const CHAR_TAB = 0x09;

/**
 * Class for calculating body hash of an email message body stream
 * using the "relaxed" canonicalization
 *
 * @class
 */
class RelaxedHash {
    declare bodyHash: Hash;
    declare byteLength: number;
    declare canonicalizedLength: number;
    declare bodyHashedBytes: number;
    declare maxBodyLength: MaxBodyLength;
    declare maxSizeReached: boolean;
    declare pendingLineBreaks: number;
    declare mimeStructureStartFinder: MimeStructureStartFinder;
    declare prefixHashes: PrefixHashes | null;
    declare digestValue: Buffer | null;
    declare remainder: Buffer | false;

    /**
     * @param {String} [algorithm] Hashing algo, either "sha1" or "sha256"
     * @param {Number} [maxBodyLength] Allowed body length count, the value from the l= parameter
     */
    constructor(algorithm?: string | null, maxBodyLength?: MaxBodyLength) {
        algorithm = (algorithm || 'sha256').split('-').pop()!.toLowerCase();

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

        // hash states at the l= limits of other signatures, see addPrefixLimit()
        this.prefixHashes = null;
        this.digestValue = null;
    }

    /**
     * Also keeps the hash of the first `limit` canonicalized bytes, the body hash of a signature
     * with l=`limit`, read with getPrefixDigest(). Only for a hasher without a limit of its own,
     * and only before the body is read
     */
    addPrefixLimit(limit: number): void {
        if (this.byteLength || typeof this.maxBodyLength === 'number') {
            throw new Error('Prefix limits are only added to an unlimited hasher before the body');
        }
        this.prefixHashes = this.prefixHashes || new PrefixHashes();
        this.prefixHashes.add(limit);
    }

    /**
     * The body hash for l=`limit`, a limit registered with addPrefixLimit(). A limit the body
     * never reached hashes the whole body
     */
    getPrefixDigest(limit: number): Buffer {
        let full = this.digest();
        return this.prefixHashes?.digest(limit) || full;
    }

    setContentType(contentTypeObj: BodyContentType): void {
        if (/^multipart\//i.test(contentTypeObj.value) && contentTypeObj.params.boundary) {
            this.mimeStructureStartFinder.setBoundary(contentTypeObj.params.boundary);
        }
    }

    _updateBodyHash(chunk: Buffer): void {
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

        if (this.prefixHashes) {
            this.prefixHashes.update(this.bodyHash, this.bodyHashedBytes, chunk);
        } else {
            this.bodyHash.update(chunk);
        }
        this.bodyHashedBytes += chunk.length;

        //process.stdout.write(chunk);
    }

    _drainPendingEmptyLines(): void {
        eachHeldLineBreak(this.pendingLineBreaks, lineBreaks => this._updateBodyHash(lineBreaks));
        this.pendingLineBreaks = 0;
    }

    _pushBodyHash(chunk: Buffer): void {
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
    fixLineBuffer(line: Buffer): Buffer {
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

    update(chunk: Buffer | null | undefined, final?: boolean): void {
        this.byteLength += (chunk && chunk.length) || 0;
        // The body is canonicalized to the end even once the l= limit has been reached.
        // Nothing past the limit is hashed (_updateBodyHash stops that), but it is counted in
        // canonicalizedLength, which is how the unsigned content after l= is reported

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

            if (this.canonicalizedLength) {
                // terminating line break for non-empty messages. A body with content is non-empty
                // even when l= keeps all of it out of the hash
                this._updateBodyHash(CRLF);
            }
        }
    }

    digest(): Buffer;
    digest(encoding: BinaryToTextEncoding): string;
    digest(encoding?: BinaryToTextEncoding): Buffer | string {
        // the hash is final after the first call, later calls return the same value, so that the
        // signatures sharing this hasher through getPrefixDigest() can each read it
        if (this.digestValue) {
            return encoding ? this.digestValue.toString(encoding) : this.digestValue;
        }

        this.update(null, true);

        // finalize
        this.digestValue = this.bodyHash.digest();
        return encoding ? this.digestValue.toString(encoding) : this.digestValue;
    }

    getMimeStructureStart(): number {
        return this.mimeStructureStartFinder.getMimeStructureStart();
    }
}

export { RelaxedHash };
