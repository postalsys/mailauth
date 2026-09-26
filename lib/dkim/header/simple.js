'use strict';

const { Buffer } = require('node:buffer');
const { stripSignatureValue } = require('../../../lib/tools');
const { buildSignatureOpts } = require('./signature-opts');

const formatSimpleLine = (line, suffix) => Buffer.from(line.toString('binary') + (suffix ? suffix : ''), 'binary');

// generate headers for signing
const simpleHeaders = (type, signingHeaderLines, options) => {
    let { signatureHeaderLine, strict } = options || {};
    let chunks = [];

    for (let signedHeaderLine of signingHeaderLines.headers) {
        chunks.push(formatSimpleLine(signedHeaderLine.line, '\r\n'));
    }

    let opts = false;

    if (!signatureHeaderLine) {
        ({ opts, signatureHeaderLine } = buildSignatureOpts(type, signingHeaderLines, options));
    }

    // the strict mode reads the tag names of a signature header case-sensitively
    chunks.push(stripSignatureValue(formatSimpleLine(signatureHeaderLine), strict));

    return { canonicalizedHeader: Buffer.concat(chunks), signatureHeaderLine, dkimHeaderOpts: opts };
};

module.exports = { simpleHeaders };
