import type { BinaryToTextEncoding, Hash } from 'node:crypto';
import type { SimpleHash } from './simple.js';
import type { RelaxedHash } from './relaxed.js';

/**
 * Hash states of a canonicalized body at several l= limits, taken while one hasher reads the
 * whole body. The hash of the first N canonicalized bytes is what a hasher with l=N computes,
 * so a copy of the running hash at N gives that value without canonicalizing and hashing the
 * body again for every limit. Signatures with different l= values then cost one pass over the
 * body together, not one pass each.
 */
class PrefixHashes {
    declare added: Set<number>;
    declare limits: number[] | null;
    declare next: number;
    declare hashes: Map<number, Hash>;
    declare digests: Map<number, Buffer>;

    constructor() {
        this.added = new Set();
        // the added limits in ascending order, sorted once the body starts
        this.limits = null;
        // position in `limits` of the first limit not reached yet
        this.next = 0;
        this.hashes = new Map();
        this.digests = new Map();
    }

    add(limit: number): void {
        if (this.limits) {
            throw new Error('Prefix limits can not be added once the body is read');
        }
        this.added.add(limit);
    }

    /**
     * Feeds `chunk`, which starts at canonicalized byte `offset`, into `hash`, and copies the
     * state of `hash` at every limit the chunk reaches
     */
    update(hash: Hash, offset: number, chunk: Buffer): void {
        if (!this.limits) {
            this.limits = Array.from(this.added).sort((a, b) => a - b);
        }
        let pos = 0;
        while (this.next < this.limits.length && this.limits[this.next] <= offset + chunk.length) {
            let limit = this.limits[this.next++];
            let end = Math.max(limit - offset, pos);
            if (end > pos) {
                hash.update(chunk.subarray(pos, end));
                pos = end;
            }
            this.hashes.set(limit, hash.copy());
        }
        if (pos < chunk.length) {
            hash.update(pos ? chunk.subarray(pos) : chunk);
        }
    }

    /**
     * The final hash at `limit`, or undefined when the body never reached it
     */
    digest(limit: number): Buffer | undefined {
        if (!this.digests.has(limit) && this.hashes.has(limit)) {
            this.digests.set(limit, this.hashes.get(limit)!.digest());
        }
        return this.digests.get(limit);
    }
}

/**
 * The body hash of a signature with an l= limit, read from the hasher of the whole body that
 * every signature with the same canonicalization and hash shares (see addPrefixLimit()). The
 * values equal those of a hasher created with that limit
 */
class PrefixBodyHash {
    declare source: SimpleHash | RelaxedHash;
    declare limit: number;

    constructor(source: SimpleHash | RelaxedHash, limit: number) {
        source.addPrefixLimit(limit);
        this.source = source;
        this.limit = limit;
    }

    get byteLength(): number {
        return this.source.byteLength;
    }

    get canonicalizedLength(): number {
        return this.source.canonicalizedLength;
    }

    get bodyHashedBytes(): number {
        return Math.min(this.limit, this.source.bodyHashedBytes);
    }

    // the shared hasher reads the body and the Content-Type
    update(): void {}

    setContentType(): void {}

    digest(): Buffer;
    digest(encoding: BinaryToTextEncoding): string;
    digest(encoding?: BinaryToTextEncoding): Buffer | string {
        let value = this.source.getPrefixDigest(this.limit);
        return encoding ? value.toString(encoding) : value;
    }

    getMimeStructureStart(): number {
        return this.source.getMimeStructureStart();
    }
}

export { PrefixHashes, PrefixBodyHash };
