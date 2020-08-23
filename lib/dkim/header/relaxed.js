'use strict';

const { formatDKIMHeaderLine } = require('../../../lib/tools');

const formatRelaxedLine = (line, suffix) => {
    return Buffer.from(
        line
            .toString('binary')
            // unfold
            .replace(/\r?\n/g, '')
            // key to lowercase, trim around :
            .replace(/^([^:]*):\s*/, (m, k) => k.toLowerCase().trim() + ':')
            // single WSP
            .replace(/\s+/g, ' ')
            .trim() + (suffix ? suffix : ''),
        'binary'
    );
};

// generate headers for signing
const relaxedHeaders = (signedHeaderLines, options) => {
    let { dkimHeaderLine, signingDomain, selector, algorithm, canonicalization, bodyHash, signTime, signature } = options || {};
    let chunks = [];

    for (let signedHeaderLine of signedHeaderLines.headers) {
        chunks.push(formatRelaxedLine(signedHeaderLine.line, '\r\n'));
    }

    let opts = false;

    if (!dkimHeaderLine) {
        opts = {
            a: algorithm,
            c: canonicalization,
            s: selector,
            d: signingDomain,
            h: signedHeaderLines.keys,
            bh: bodyHash
        };

        if (signTime) {
            if (typeof signTime === 'string' || typeof signTime === 'number') {
                signTime = new Date(signTime);
            }

            if (Object.prototype.toString.call(signTime) === '[object Date]' && signTime.toString() !== 'Invalid Date') {
                // we need a unix timestamp value
                signTime = Math.round(signTime.getTime() / 1000);
                opts.t = signTime;
            }
        }

        dkimHeaderLine = formatDKIMHeaderLine(
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
            formatRelaxedLine(dkimHeaderLine)
                .toString('binary')
                // remove value from b= key
                .replace(/([;:\s]+b=)[^;]+/, '$1'),
            'binary'
        )
    );

    return { signingHeaders: Buffer.concat(chunks), dkimHeaderLine, dkimHeaderOpts: opts };
};

module.exports = { relaxedHeaders };
