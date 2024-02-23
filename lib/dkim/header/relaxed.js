'use strict';

const { Buffer } = require('node:buffer');
const { formatSignatureHeaderLine, formatRelaxedLine, getCurTime } = require('../../../lib/tools');

// generate headers for signing
const relaxedHeaders = (type, signingHeaderLines, options) => {
    let { signatureHeaderLine, signingDomain, selector, algorithm, canonicalization, bodyHash, signTime, signature, instance, bodyHashedBytes, expires } =
        options || {};
    let chunks = [];

    for (let signedHeaderLine of signingHeaderLines.headers) {
        chunks.push(formatRelaxedLine(signedHeaderLine.line, '\r\n'));
    }

    let opts = false;

    if (!signatureHeaderLine) {
        opts = {
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

        if (instance) {
            // ARC only
            opts.i = instance;
        }

        if (signTime) {
            opts.t = Math.floor(getCurTime(signTime).getTime() / 1000);
        }

        if (expires) {
            opts.x = Math.floor(getCurTime(expires).getTime() / 1000);
        }

        signatureHeaderLine = formatSignatureHeaderLine(
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
    }

    chunks.push(
        Buffer.from(
            formatRelaxedLine(signatureHeaderLine)
                .toString('binary')
                // remove value from b= key
                .replace(/([;:\s]+b=)[^;]+/, '$1'),
            'binary'
        )
    );

    return { canonicalizedHeader: Buffer.concat(chunks), signatureHeaderLine, dkimHeaderOpts: opts };
};

module.exports = { relaxedHeaders };
