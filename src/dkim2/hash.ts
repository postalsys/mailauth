import { writeToStream } from '../tools.js';
import { Dkim2Parser } from './dkim2-parser.js';
import { HASH_ALGORITHMS } from './fields.js';
import type { CurrentState } from './message-state.js';
import type { DKIM2HashOptions, DKIM2HashResult, MessageInput } from '../types.js';

// HashParser keeps the message state in the `state` field of MessageParser, which holds the
// parser state ('header' or 'body') until the whole message has been read
type HashParserState = { state: CurrentState };

type HashAlgorithm = DKIM2HashResult['hashes'][number]['algorithm'];

// Reads a message and keeps its DKIM2 state: the hashed header fields and the body hashes
class HashParser extends Dkim2Parser {
    constructor(algorithms: string[]) {
        super();
        algorithms.forEach(algorithm => this.hashBodyWith(algorithm));
    }

    override async finalChunk(): Promise<void> {
        (this as unknown as HashParserState).state = this.currentState();
    }
}

/**
 * Computes the DKIM2 header and body hashes of a message as they go into the h= tag of a
 * Message-Instance header field (draft-ietf-dkim-dkim2-spec-06 sections 6 and 7.3)
 *
 * @param {ReadableStream|Buffer|String} input RFC 5322 message
 * @param {Object} [options]
 * @param {String[]} [options.algorithms=['sha256']] "sha256" and/or "sha512"
 * @returns {Object} { headers, hashes }. `headers` lists the names of the hashed header fields in
 *          the order they are hashed, `hashes` is [{ algorithm, headerHash, bodyHash }]
 * @throws {Error} For an unsupported hash algorithm
 */
const dkim2Hash = async (input: MessageInput, options?: DKIM2HashOptions): Promise<DKIM2HashResult> => {
    let algorithms = Array.from(new Set((options?.algorithms || ['sha256']).map(algorithm => String(algorithm).toLowerCase())));
    for (let algorithm of algorithms) {
        if (!HASH_ALGORITHMS.has(algorithm)) {
            let err: Error & { code?: string } = new Error(`Unsupported hash algorithm ${algorithm}, use sha256 or sha512`);
            err.code = 'EINVALIDALGO';
            throw err;
        }
    }

    let parser = new HashParser(algorithms);
    await writeToStream(parser, input);
    let { state } = parser as unknown as HashParserState;

    return {
        // section 6.2: sorted by name
        headers: Array.from(state.headers.keys()).sort(),
        hashes: (algorithms as HashAlgorithm[]).map(algorithm => ({ algorithm, headerHash: state.headerHash(algorithm), bodyHash: state.bodyHash(algorithm) }))
    };
};

export { dkim2Hash };
