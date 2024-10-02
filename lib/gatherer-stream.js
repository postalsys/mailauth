'use strict';

const { Buffer } = require('node:buffer');
const { Transform, PassThrough } = require('node:stream');

class GathererStream extends Transform {
    constructor(opts) {
        super(opts);

        this.gather = !!opts?.gather;

        this.chunks = [];
        this.datalength = 0;
    }

    replay() {
        const stream = new PassThrough();

        setImmediate(() => {
            // start piping chunks
            let pos = 0;
            let writeNext = () => {
                if (pos >= this.chunks.length) {
                    // all done
                    return stream.end();
                }

                const chunk = this.chunks[pos++];

                if (stream.write(chunk) === false) {
                    // wait for drain
                    return stream.once('drain', writeNext);
                }

                setImmediate(writeNext);
            };

            writeNext();
        });

        return stream;
    }

    _transform(chunk, encoding, done) {
        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        if (!chunk || !chunk.length) {
            return done();
        }

        if (this.gather) {
            this.chunks.push(chunk);
        }
        this.datalength += chunk.length;

        this.push(chunk);

        done();
    }

    _flush(done) {
        // not much to do here
        done();
    }
}

module.exports.GathererStream = GathererStream;
