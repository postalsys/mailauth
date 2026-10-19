import { writeToStream } from '../tools.js';
import { DkimVerifier } from './dkim-verifier.js';
import type { DKIMResult, DKIMVerifyOptions, DKIMVerifyResult, MessageInput } from '../types.js';

const dkimVerify = async (input: MessageInput, options?: DKIMVerifyOptions): Promise<DKIMVerifyResult> => {
    let dkimVerifier = new DkimVerifier(options);
    await writeToStream(dkimVerifier, input);

    const result: DKIMVerifyResult = {
        //headers: dkimVerifier.headers,
        headerFrom: dkimVerifier.headerFrom,
        fromFields: dkimVerifier.fromFields,
        fromSyntax: dkimVerifier.fromSyntax,
        envelopeFrom: dkimVerifier.envelopeFrom,
        // finalChunk() has added `info` to every result, and removed the comments that are false
        results: dkimVerifier.results as DKIMResult[]
    };

    if (dkimVerifier.headers) {
        Object.defineProperty(result, 'headers', {
            enumerable: false,
            configurable: false,
            writable: false,
            value: dkimVerifier.headers
        });
    }

    if (dkimVerifier.arc) {
        Object.defineProperty(result, 'arc', {
            enumerable: false,
            configurable: false,
            writable: false,
            value: dkimVerifier.arc
        });
    }

    if (dkimVerifier.seal) {
        Object.defineProperty(result, 'seal', {
            enumerable: false,
            configurable: false,
            writable: false,
            value: dkimVerifier.seal
        });
    }

    return result;
};

export { dkimVerify };
