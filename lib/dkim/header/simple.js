'use strict';

const { Buffer } = require('node:buffer');
const { stripSignatureValue } = require('../../../lib/tools');
const { buildSignatureOpts } = require('./signature-opts');

// a string is a header line built here, and it is written out as UTF-8, so it is hashed as the
// same UTF-8 bytes. A Buffer holds the bytes of the message as they are
const formatSimpleLine = (line, suffix) => Buffer.concat([typeof line === 'string' ? Buffer.from(line) : line, Buffer.from(suffix ? suffix : '', 'binary')]);

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
