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

const validateAlgorithm = algorithm => {
    let [signing, hashing] = algorithm.split('-');

    if (!['rsa', 'ed25519'].includes(signing)) {
        throw new Error('Unknown signing algorithm: ' + signing);
    }

    if (!['sha256', 'sha1'].includes(hashing)) {
        throw new Error('Unknown hashing algorithm: ' + hashing);
    }
};

const dkimSign = async (input, options) => {
    let { algorithm, canonicalization } = options || {};

    canonicalization = (canonicalization || 'relaxed/relaxed').toLowerCase().trim();
    algorithm = (algorithm || 'rsa-sha256').toLowerCase().trim();

    validateCanonicalization(canonicalization);
    validateAlgorithm(algorithm);

    let dkimSigner = new DkimSigner(options);
    await writeToStream(dkimSigner, input);

    return dkimSigner.signatureHeaders;
};

module.exports = { dkimSign };
