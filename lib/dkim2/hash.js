'use strict';

const { writeToStream } = require('../tools');
const { Dkim2Parser } = require('./dkim2-parser');
const { HASH_ALGORITHMS } = require('./fields');

// Reads a message and keeps its DKIM2 state: the hashed header fields and the body hashes
class HashParser extends Dkim2Parser {
    constructor(algorithms) {
        super();
        algorithms.forEach(algorithm => this.hashBodyWith(algorithm));
    }

    async finalChunk() {
        this.state = this.currentState();
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
const dkim2Hash = async (input, options) => {
    let algorithms = Array.from(new Set((options?.algorithms || ['sha256']).map(algorithm => String(algorithm).toLowerCase())));
    for (let algorithm of algorithms) {
        if (!HASH_ALGORITHMS.has(algorithm)) {
            let err = new Error(`Unsupported hash algorithm ${algorithm}, use sha256 or sha512`);
            err.code = 'EINVALIDALGO';
            throw err;
        }
    }

    let parser = new HashParser(algorithms);
    await writeToStream(parser, input);
    let { state } = parser;

    return {
        // section 6.2: sorted by name
        headers: Array.from(state.headers.keys()).sort(),
        hashes: algorithms.map(algorithm => ({ algorithm, headerHash: state.headerHash(algorithm), bodyHash: state.bodyHash(algorithm) }))
    };
};

module.exports = { dkim2Hash };
