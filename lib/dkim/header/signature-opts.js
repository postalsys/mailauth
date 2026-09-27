'use strict';

const { formatSignatureHeaderLine, getCurTime } = require('../../tools');

/**
 * Builds the tags of a signature header that is being created, and the header line that the
 * header canonicalization hashes for it. Shared by the relaxed and the simple canonicalization.
 *
 * @param {String} type 'DKIM', 'ARC' or 'AS'
 * @param {Object} signingHeaderLines { keys } as returned by getSigningHeaderLines()
 * @param {Object} options The options of the canonicalization
 * @returns {Object} { opts, signatureHeaderLine }
 */
const buildSignatureOpts = (type, signingHeaderLines, options) => {
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
    } = options || {};

    let opts = {
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

module.exports = { buildSignatureOpts };
