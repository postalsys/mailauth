import { Buffer } from 'node:buffer';
import { Transform, PassThrough } from 'node:stream';
import type { TransformCallback, TransformOptions } from 'node:stream';

export interface GathererStreamOptions extends TransformOptions {
    gather?: boolean | undefined;
}

class GathererStream extends Transform {
    declare gather: boolean;
    declare chunks: Buffer[];
    declare datalength: number;

    constructor(opts?: GathererStreamOptions) {
        super(opts);

        this.gather = !!opts?.gather;

        this.chunks = [];
        this.datalength = 0;
    }

    replay(): PassThrough {
        const stream = new PassThrough();

        setImmediate(() => {
            // start piping chunks
            let pos = 0;
            let writeNext = (): PassThrough | void => {
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

    override _transform(chunk: Buffer | string, encoding: BufferEncoding, done: TransformCallback): void {
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

    override _flush(done: TransformCallback): void {
        // not much to do here
        done();
    }
}

export { GathererStream };
