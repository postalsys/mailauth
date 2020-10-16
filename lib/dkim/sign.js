'use strict';

const { writeToStream } = require('../../lib/tools');
const { DkimSigner } = require('./dkim-signer');

const validateCanonicalization = canonicalization => {
    let [header, body] = canonicalization.split('/');

    if (!['relaxed', 'simple'].includes(header)) {
        throw new Error('Unknown header canonicalization: ' + header);
    }

    if (!['relaxed', 'simple'].includes(body)) {
        throw new Error('Unknown header canonicalization: ' + body);
    }
};

const dkimSign = async (input, options) => {
    let { canonicalization } = options || {};

    canonicalization = (canonicalization || 'relaxed/relaxed').toLowerCase().trim();
    validateCanonicalization(canonicalization);

    let dkimSigner = new DkimSigner(options);
    await writeToStream(dkimSigner, input);

    return { signatures: dkimSigner.signatureHeaders.join('\r\n') + '\r\n', errors: dkimSigner.errors };
};

module.exports = { dkimSign };
