'use strict';

const { writeToStream } = require('../../lib/tools');
const { DkimSigner } = require('./dkim-signer');
const { Transform } = require('node:stream');
const { Buffer } = require('node:buffer');

// The DKIM-Signature header lines to prepend to the message, each ending with a CRLF. An
// empty string when no signature was created: a lone CRLF in front of the message would be
// the empty line that ends the header section, and turn every header of it into body
const formatSignatures = signatureHeaders => (signatureHeaders.length ? signatureHeaders.join('\r\n') + '\r\n' : '');

const dkimSign = async (input, options) => {
    let dkimSigner = new DkimSigner(options);
    await writeToStream(dkimSigner, input);

    return {
        signatures: formatSignatures(dkimSigner.signatureHeaders),
        arc: dkimSigner.arc,
        errors: dkimSigner.errors,
        warnings: dkimSigner.warnings
    };
};

class DkimSignStream extends Transform {
    constructor(options) {
        super(options);
        this.signer = new DkimSigner(options);

        this.chunks = [];
        this.chunklen = 0;

        this.errors = null;
        this.warnings = null;

        this.finished = false;
        this.finishCb = null;
        this.signer.on('end', () => this.finishStream());
        this.signer.on('finish', () => this.finishStream());
        this.signer.on('error', err => {
            this.finished = true;
            this.destroy(err);
        });
    }

    finishStream() {
        if (this.finished || !this.finishCb) {
            return;
        }
        this.finished = true;
        let done = this.finishCb;
        this.finishCb = null;

        this.errors = this.signer.errors;
        this.warnings = this.signer.warnings;

        let signatures = formatSignatures(this.signer.signatureHeaders);
        if (signatures) {
            this.push(Buffer.from(signatures));
        }
        this.push(Buffer.concat(this.chunks, this.chunklen));
        done();
    }

    _transform(chunk, encoding, done) {
        if (!chunk || !chunk.length || this.finished) {
            return done();
        }

        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        this.chunks.push(chunk);
        this.chunklen += chunk.length;

        if (this.signer.write(chunk) === false) {
            // wait for drain
            return this.signer.once('drain', done);
        }
        done();
    }

    _flush(done) {
        if (this.finished) {
            return done();
        }
        this.finishCb = done;
        this.signer.end();
    }
}

module.exports = { dkimSign, DkimSignStream };
