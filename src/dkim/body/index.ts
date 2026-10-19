import { SimpleHash } from './simple.js';
import { RelaxedHash } from './relaxed.js';
import { Transform } from 'node:stream';
import type { TransformCallback } from 'node:stream';
import type { MaxBodyLength } from './simple.js';

/**
 * A body hasher of either canonicalization
 */
export type BodyHasher = SimpleHash | RelaxedHash;

/**
 * The hash algorithm ("sha256", "sha1" or a full "rsa-sha256") and the l= limit
 */
export type BodyHashOptions = [algorithm?: string | null, maxBodyLength?: MaxBodyLength];

const dkimBody = (canonicalization: string | null | undefined, ...options: BodyHashOptions): BodyHasher => {
    canonicalization = (canonicalization || 'simple/simple').toString().split('/').pop()!.toLowerCase().trim();
    switch (canonicalization) {
        case 'simple':
            return new SimpleHash(...options);
        case 'relaxed':
            return new RelaxedHash(...options);
        default: {
            let error: Error & { canonicalization?: string | undefined } = new Error('Unknown body canonicalization');
            error.canonicalization = canonicalization;
            throw error;
        }
    }
};

class BodyHashStream extends Transform {
    declare byteLength: number;
    declare hasher: BodyHasher;
    declare bodyHash: string | null;

    constructor(canonicalization: string | null | undefined, ...options: BodyHashOptions) {
        super();

        this.byteLength = 0;

        this.hasher = dkimBody(canonicalization, ...options);

        this.bodyHash = null;
    }

    override _transform(chunk: Buffer | string, encoding: BufferEncoding, done: TransformCallback): void {
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

    override _flush(done: TransformCallback): void {
        this.bodyHash = this.hasher.digest('base64');
        this.emit('hash', this.bodyHash);
        done();
    }
}

export { dkimBody, BodyHashStream };
