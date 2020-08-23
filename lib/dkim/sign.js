'use strict';

const { writeToStream, getSignedHeaderLines, formatDKIMHeaderLine } = require('../../lib/tools');
const { DkimSigner } = require('./dkim-signer');
const crypto = require('crypto');

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

const sign = async (input, options) => {
    let { algorithm, canonicalization } = options || {};

    canonicalization = (canonicalization || 'relaxed/relaxed').toLowerCase().trim();
    algorithm = (algorithm || 'rsa-sha256').toLowerCase().trim();

    validateCanonicalization(canonicalization);
    validateAlgorithm(algorithm);

    let dkimSigner = new DkimSigner(options);
    await writeToStream(dkimSigner, input);

    console.log(dkimSigner);

    return dkimSigner.signatureHeaders;
};

const fs = require('fs');

const time = 1598079221278;

sign(fs.createReadStream('./test/fixtures/message1.eml'), {
    algorithm: 'rsa-SHA256',
    canonicalization: 'simple/relaxed',
    signTime: time,

    signatureData: [
        {
            signingDomain: 'mail.projectpending.com',
            selector: 'test123',
            privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
        },
        {
            signingDomain: 'zmail.projectpending.com',
            selector: 'test122',
            privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
        }
    ]
})
    .then(res => console.log('result', res))
    .catch(err => console.error(err));
