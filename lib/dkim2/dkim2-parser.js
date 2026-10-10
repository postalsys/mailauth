'use strict';

// The part of message parsing the DKIM2 signer and verifier share: the body is hashed with every
// algorithm asked for, and kept when a body Recipe has to copy lines from it

const { Buffer } = require('node:buffer');
const { MessageParser } = require('../dkim/message-parser');
const { SimpleHash } = require('../dkim/body/simple');
const { MessageState, splitBodyLines } = require('./message-state');

class Dkim2Parser extends MessageParser {
    constructor() {
        super();
        this.bodyHashers = new Map();
        this.bodyChunks = null;
    }

    // hashes the body with `algorithm` too, called from messageHeaders()
    hashBodyWith(algorithm) {
        if (!this.bodyHashers.has(algorithm)) {
            this.bodyHashers.set(algorithm, new SimpleHash(algorithm));
        }
    }

    // keeps the body in memory, called from messageHeaders()
    keepBody() {
        this.bodyChunks = this.bodyChunks || [];
    }

    async nextChunk(chunk) {
        for (let hasher of this.bodyHashers.values()) {
            hasher.update(chunk);
        }
        if (this.bodyChunks) {
            this.bodyChunks.push(chunk);
        }
    }

    // The message as it is, once the whole body has been read
    currentState() {
        let hashes = new Map();
        for (let [algorithm, hasher] of this.bodyHashers) {
            hashes.set(algorithm, hasher.digest('base64'));
        }
        let lines = this.bodyChunks ? splitBodyLines(Buffer.concat(this.bodyChunks)) : null;
        // the lines hold the body from now on
        this.bodyChunks = null;
        return MessageState.fromMessage(this.headers.parsed, { lines, hashes });
    }
}

module.exports = { Dkim2Parser };
