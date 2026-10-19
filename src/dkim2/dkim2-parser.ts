// The part of message parsing the DKIM2 signer and verifier share: the body is hashed with every
// algorithm asked for, and kept when a body Recipe has to copy lines from it

import { Buffer } from 'node:buffer';
import { MessageParser } from '../dkim/message-parser.js';
import type { ParsedHeaders } from '../dkim/message-parser.js';
import { SimpleHash } from '../dkim/body/simple.js';
import { MessageState, splitBodyLines } from './message-state.js';
import type { CurrentState } from './message-state.js';

class Dkim2Parser extends MessageParser {
    declare bodyHashers: Map<string, SimpleHash>;
    declare bodyChunks: Buffer[] | null;

    constructor() {
        super();
        this.bodyHashers = new Map();
        this.bodyChunks = null;
    }

    // hashes the body with `algorithm` too, called from messageHeaders()
    hashBodyWith(algorithm: string): void {
        if (!this.bodyHashers.has(algorithm)) {
            this.bodyHashers.set(algorithm, new SimpleHash(algorithm));
        }
    }

    // keeps the body in memory, called from messageHeaders()
    keepBody(): void {
        this.bodyChunks = this.bodyChunks || [];
    }

    override async nextChunk(chunk: Buffer): Promise<void> {
        for (let hasher of this.bodyHashers.values()) {
            hasher.update(chunk);
        }
        if (this.bodyChunks) {
            this.bodyChunks.push(chunk);
        }
    }

    // The message as it is, once the whole body has been read
    currentState(): CurrentState {
        let hashes = new Map<string, string>();
        for (let [algorithm, hasher] of this.bodyHashers) {
            hashes.set(algorithm, hasher.digest('base64'));
        }
        let lines = this.bodyChunks ? splitBodyLines(Buffer.concat(this.bodyChunks)) : null;
        // the lines hold the body from now on
        this.bodyChunks = null;
        return MessageState.fromMessage((this.headers as ParsedHeaders).parsed, { lines, hashes }) as CurrentState;
    }
}

export { Dkim2Parser };
