'use strict';

const { Buffer } = require('node:buffer');
const { formatRelaxedLine, stripSignatureValue } = require('../../../lib/tools');
const { buildSignatureOpts } = require('./signature-opts');

// generate headers for signing
const relaxedHeaders = (type, signingHeaderLines, options) => {
    let { signatureHeaderLine, strict } = options || {};
    let chunks = [];

    for (let signedHeaderLine of signingHeaderLines.headers) {
        chunks.push(formatRelaxedLine(signedHeaderLine.line, '\r\n'));
    }

    let opts = false;

    if (!signatureHeaderLine) {
        ({ opts, signatureHeaderLine } = buildSignatureOpts(type, signingHeaderLines, options));
    }

    // the strict mode reads the tag names of a signature header case-sensitively
    chunks.push(stripSignatureValue(formatRelaxedLine(signatureHeaderLine), strict));

    return { canonicalizedHeader: Buffer.concat(chunks), signatureHeaderLine, dkimHeaderOpts: opts };
};

module.exports = { relaxedHeaders };
