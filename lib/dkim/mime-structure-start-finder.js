'use strict';

const { Buffer } = require('node:buffer');

class MimeStructureStartFinder {
    constructor() {
        this.byteCache = [];

        this.matchFound = false;
        this.noMatch = false;
        this.lineStart = -1;

        this.prevChunks = 0;

        this.mimeStructureStart = -1;
    }

    setBoundary(boundary) {
        this.boundary = (boundary || '').toString().trim();

        this.boundaryBuf = Array.from(Buffer.from(`--${this.boundary}`));
        this.boundaryBufLen = this.boundaryBuf.length;
    }

    update(chunk) {
        if (this.matchFound || !this.boundary) {
            return;
        }

        for (let i = 0, bufLen = chunk.length; i < bufLen; i++) {
            let c = chunk[i];

            // check ending
            if (c === 0x0a || c === 0x0d) {
                if (!this.noMatch && this.byteCache.length === this.boundaryBufLen) {
                    // match found
                    this.matchFound = true;
                    this.mimeStructureStart = this.lineStart;
                    break;
                }
                // reset counter
                this.lineStart = -1;
                this.noMatch = false;
                this.byteCache = [];
                continue;
            }

            if (this.noMatch) {
                // no need to look
                continue;
            }

            if (this.lineStart < 0) {
                this.lineStart = this.prevChunks + i;
            }

            if (this.byteCache.length >= this.boundaryBufLen) {
                this.noMatch = true;
                continue;
            }

            const expectingByte = this.boundaryBuf[this.byteCache.length];
            if (expectingByte !== c) {
                this.noMatch = true;
                continue;
            }
            this.byteCache[this.byteCache.length] = c;
        }

        this.prevChunks += chunk.length;
    }

    getMimeStructureStart() {
        if (!this.boundary) {
            return 0;
        }

        if (!this.matchFound && !this.noMatch && this.byteCache.length === this.boundaryBufLen) {
            this.matchFound = true;
            this.mimeStructureStart = this.lineStart;
        }

        return this.mimeStructureStart;
    }
}

module.exports = { MimeStructureStartFinder };
