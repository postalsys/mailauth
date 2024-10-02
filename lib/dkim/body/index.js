'use strict';

const { SimpleHash } = require('./simple');
const { RelaxedHash } = require('./relaxed');
const { Transform } = require('node:stream');
const { MessageParser } = require('../message-parser');

const dkimBody = (canonicalization, ...options) => {
    canonicalization = (canonicalization || 'simple/simple').toString().split('/').pop().toLowerCase().trim();
    switch (canonicalization) {
        case 'simple':
            return new SimpleHash(...options);
        case 'relaxed':
            return new RelaxedHash(...options);
        default: {
            let error = new Error('Unknown body canonicalization');
            error.canonicalization = canonicalization;
            throw error;
        }
    }
};

class MessageHasher extends MessageParser {
    constructor(canonicalization, ...options) {
        super();
        this.hasher = dkimBody(canonicalization, ...options);
        this.bodyHash = null;
    }

    async nextChunk(chunk) {
        this.hasher.update(chunk);
    }

    async finalChunk() {
        this.bodyHash = this.hasher.digest('base64');
    }
}

class BodyHashStream extends Transform {
    constructor(canonicalization, ...options) {
        super();

        this.finished = false;
        this.finishCb = null;

        this.byteLength = 0;

        this.messageHasher = new MessageHasher(canonicalization, ...options);
        this.bodyHash = null;
        this.messageHasher.once('finish', () => this.finishHashing());
        this.messageHasher.once('end', () => this.finishHashing());
        this.messageHasher.once('error', err => this.destroy(err));
    }

    finishHashing() {
        if (this.finished || !this.finishCb) {
            return;
        }
        this.finished = true;
        let done = this.finishCb;
        this.finishCb = null;

        this.bodyHash = this.messageHasher.bodyHash;
        this.emit('hash', this.bodyHash);

        done();
    }

    _transform(chunk, encoding, done) {
        if (!chunk || !chunk.length) {
            return done();
        }

        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        this.byteLength += chunk.length;

        this.push(chunk);

        if (this.messageHasher.write(chunk) === false) {
            // wait for drain
            return this.messageHasher.once('drain', done);
        }

        done();
    }

    _flush(done) {
        this.finishCb = done;
        this.messageHasher.end();
    }
}

module.exports = { dkimBody, BodyHashStream };
