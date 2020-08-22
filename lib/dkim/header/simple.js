'use strict';

const { formatDKIMHeaderLine } = require('../../../lib/tools');

const formatSimpleLine = (line, suffix) => {
    return Buffer.from(line.toString('binary') + (suffix ? suffix : ''), 'binary');
};

// generate headers for signing
const simpleHeaders = (signedHeaderLines, options) => {
    let { dkimHeaderLine, signingDomain, selector, algorithm, canonicalization, bodyHash, signTime, signature } = options || {};
    let chunks = [];

    for (let signedHeaderLine of signedHeaderLines.headers) {
        chunks.push(formatSimpleLine(signedHeaderLine.line, '\r\n'));
    }

    let opts = false;

    if (!dkimHeaderLine) {
        opts = {
            a: algorithm,
            c: canonicalization,
            s: selector,
            d: signingDomain,
            h: signedHeaderLines.keys,
            bh: bodyHash,
            b: signature || ''
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

        dkimHeaderLine = formatDKIMHeaderLine(opts, true);
    }

    chunks.push(
        Buffer.from(
            formatSimpleLine(dkimHeaderLine)
                .toString('binary')
                // remove value from b= key
                .replace(/([;:\s]+b=)[^;]+/, '$1'),
            'binary'
        )
    );

    return { signingHeaders: Buffer.concat(chunks), dkimHeaderLine, dkimHeaderOpts: opts };
};

module.exports = { simpleHeaders };
