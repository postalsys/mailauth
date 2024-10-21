'use strict';

const { SimpleHash } = require('./simple');
const { RelaxedHash } = require('./relaxed');
const { Transform } = require('node:stream');

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

class BodyHashStream extends Transform {
    constructor(canonicalization, ...options) {
        super();

        this.byteLength = 0;

        this.hasher = dkimBody(canonicalization, ...options);

        this.bodyHash = null;
    }

    _transform(chunk, encoding, done) {
        if (!chunk || !chunk.length) {
            return done();
        }

        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        this.byteLength += chunk.length;

        this.hasher.update(chunk);
        this.push(chunk);

        done();
    }

    _flush(done) {
        this.bodyHash = this.hasher.digest('base64');
        this.emit('hash', this.bodyHash);
        done();
    }
}

module.exports = { dkimBody, BodyHashStream };
