import { writeToStream } from '../tools.js';
import { DkimSignStream, formatSignatures } from '../dkim/sign.js';
import { Dkim2Signer } from './dkim2-signer.js';
import type { DKIM2SignOptions, DKIM2SignResult, MessageInput } from '../types.js';

/**
 * Signs a message with DKIM2: adds a DKIM2-Signature header field and, when needed, a
 * Message-Instance header field (draft-ietf-dkim-dkim2-spec-06 section 9)
 *
 * @param {ReadableStream|Buffer|String} input RFC 5322 message
 * @param {Object} options Signing options, see README
 * @returns {Object} { signatures, signature, messageInstance, i, m }. `signatures` holds the
 *          header lines to prepend to the message, each ending with CRLF
 * @throws {Error} For invalid options, an invalid DKIM2 chain on the message, or a recipe that
 *         does not recreate the previous instance
 */
const dkim2Sign = async (input: MessageInput, options: DKIM2SignOptions): Promise<DKIM2SignResult> => {
    let signer = new Dkim2Signer(options);
    await writeToStream(signer, input);

    return {
        signatures: formatSignatures(signer.signatureHeaders),
        signature: signer.signatureHeaders[0],
        messageInstance: signer.signatureHeaders[1] || null,
        i: signer.i,
        m: signer.m
    };
};

// Transform stream that outputs the message with the DKIM2 header fields on top
class Dkim2SignStream extends DkimSignStream<DKIM2SignOptions> {
    override createSigner(options: DKIM2SignOptions): Dkim2Signer {
        return new Dkim2Signer(options);
    }
}

export { dkim2Sign, Dkim2SignStream };
