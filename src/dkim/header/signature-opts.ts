import type { Buffer } from 'node:buffer';
import { formatSignatureHeaderLine, getCurTime } from '../../tools.js';

/**
 * The header fields a signature covers, as returned by getSigningHeaderLines()
 */
export interface SigningHeaderLines {
    /** The h= value, the field names joined with ": " */
    keys: string;
    /** The header rows to hash, in the order they are hashed */
    headers: Array<{ line: Buffer | string }>;
}

/**
 * The options of the header canonicalization. The verifier passes the signature header line
 * it read, the signer passes the values of the signature that is being created
 */
export interface HeaderCanonicalizationOptions {
    /** c= value, only its header part is used here */
    canonicalization?: string | undefined;
    /** The signature header line to hash, when the signature already exists */
    signatureHeaderLine?: string | Buffer | undefined;
    /** Read the tag names of the signature header case-sensitively */
    strict?: boolean | undefined;
    signingDomain?: string | undefined;
    selector?: string | undefined;
    algorithm?: string | undefined;
    bodyHash?: string | null | undefined;
    signTime?: Parameters<typeof getCurTime>[0] | undefined;
    signature?: string | undefined;
    /** ARC only, the instance number */
    instance?: string | number | false | undefined;
    /** DKIM only, the AUID */
    identity?: string | undefined;
    bodyHashedBytes?: number | undefined;
    expires?: Parameters<typeof getCurTime>[0] | undefined;
    /** The validated t= value, false leaves the tag out */
    timestamp?: number | false | undefined;
    /** The validated x= value, false leaves the tag out */
    expiration?: number | false | undefined;
}

/**
 * The tags of a signature header that is being created
 */
export interface SignatureOpts {
    a: string | undefined;
    c: string | undefined;
    s: string | undefined;
    d: string | undefined;
    h: string;
    bh: string | null | undefined;
    l?: number;
    i?: string | number;
    t?: number | null;
    x?: number;
    /** set by the signer once the signature exists */
    b?: string;
}

/**
 * The result of the header canonicalization
 */
export interface CanonicalizedHeader {
    canonicalizedHeader: Buffer;
    signatureHeaderLine: string | Buffer;
    /** The tags of the signature header, false when the header line was given */
    dkimHeaderOpts: SignatureOpts | false;
}

/**
 * Builds the tags of a signature header that is being created, and the header line that the
 * header canonicalization hashes for it. Shared by the relaxed and the simple canonicalization.
 *
 * @param {String} type 'DKIM', 'ARC' or 'AS'
 * @param {Object} signingHeaderLines { keys } as returned by getSigningHeaderLines()
 * @param {Object} options The options of the canonicalization
 * @returns {Object} { opts, signatureHeaderLine }
 */
const buildSignatureOpts = (
    type: string,
    signingHeaderLines: SigningHeaderLines,
    options: HeaderCanonicalizationOptions | undefined
): { opts: SignatureOpts; signatureHeaderLine: string } => {
    let {
        signingDomain,
        selector,
        algorithm,
        canonicalization,
        bodyHash,
        signTime,
        signature,
        instance,
        identity,
        bodyHashedBytes,
        expires,
        timestamp,
        expiration
    }: HeaderCanonicalizationOptions = options || {};

    let opts: SignatureOpts = {
        a: algorithm,
        c: canonicalization,
        s: selector,
        d: signingDomain,
        h: signingHeaderLines.keys,
        bh: bodyHash
    };

    if (typeof bodyHashedBytes === 'number') {
        opts.l = bodyHashedBytes;
    }

    if (instance && type === 'ARC') {
        // ARC only, the i= of an ARC-Message-Signature is the instance number
        opts.i = instance;
    } else if (identity && type === 'DKIM') {
        // DKIM only, the i= of a DKIM-Signature is the AUID
        opts.i = identity;
    }

    // The same opts object formats the line that gets signed here and, once the
    // signature exists, the line that is emitted. Leaving t= out of it lets
    // formatSignatureHeaderLine read the clock again for the second one, and a second
    // boundary falling between the two reads signs one timestamp and publishes another.
    // `timestamp` and `expiration` are the values the signer already validated, false
    // leaves the tag out (an explicit null keeps formatSignatureHeaderLine from adding
    // a t= of its own). Callers that do not pass them get the values from signTime and
    // expires
    if (typeof timestamp === 'number' || timestamp === false) {
        opts.t = timestamp === false ? null : timestamp;
    } else {
        opts.t = Math.floor(getCurTime(signTime).getTime() / 1000);
    }

    if (typeof expiration === 'number') {
        opts.x = expiration;
    } else if (expiration !== false && expires) {
        opts.x = Math.floor(getCurTime(expires).getTime() / 1000);
    }

    let signatureHeaderLine = formatSignatureHeaderLine(
        type,
        Object.assign(
            {
                // make sure that b= always has a value, otherwise folding would be different
                b: signature || 'a'.repeat(73)
            },
            opts
        ),
        true
    );

    return { opts, signatureHeaderLine };
};

export { buildSignatureOpts };
