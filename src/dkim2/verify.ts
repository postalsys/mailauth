import { writeToStream } from '../tools.js';
import { Dkim2Verifier } from './dkim2-verifier.js';
import type { DKIM2VerifyOptions, DKIM2VerifyResult, MessageInput } from '../types.js';

/**
 * Verifies the DKIM2 header fields of a message (draft-ietf-dkim-dkim2-spec-06 section 11)
 *
 * @param {ReadableStream|Buffer|String} input RFC 5322 message
 * @param {Object} [options] Verification options, see Dkim2Verifier
 * @returns {Object} Verification result, see docs/dkim2.md
 */
const dkim2Verify = async (input: MessageInput, options?: DKIM2VerifyOptions): Promise<DKIM2VerifyResult> => {
    let verifier = new Dkim2Verifier(options);
    await writeToStream(verifier, input);
    // finalChunk() always sets the result once the message has been written
    return verifier.result!;
};

export { dkim2Verify };
