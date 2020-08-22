'use strict';

const { writeToStream, getSignedHeaderLines, formatDKIMHeaderLine } = require('../../lib/tools');
const bodyHash = require('./body');
const { dkimHeader } = require('./header');
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
    let { algorithm, canonicalization, signTime, headerList, signatureData } = options || {};

    canonicalization = (canonicalization || 'relaxed/relaxed').toLowerCase().trim();
    algorithm = (algorithm || 'rsa-sha256').toLowerCase().trim();

    validateCanonicalization(canonicalization);
    validateAlgorithm(algorithm);

    let bodyHasher = bodyHash({ canonicalization });
    await writeToStream(bodyHasher, input);

    if (!bodyHasher.headers) {
        throw new Error('Invalid or empty message');
    }

    let signedHeaderLines = getSignedHeaderLines(bodyHasher.headers.parsed, headerList);
    let signatureHeaders = [];

    for (let data of signatureData || []) {
        let { signingHeaders, dkimHeaderOpts } = dkimHeader(
            signedHeaderLines,
            Object.assign({ algorithm, canonicalization, signTime, bodyHash: bodyHasher.bodyHash }, data)
        );

        let signature = crypto
            .sign(
                // use `null` as algorithm to detect it from the key file
                algorithm.split('-').shift() === 'rsa' ? algorithm : null,
                signingHeaders,
                data.privateKey
            )
            .toString('base64');

        dkimHeaderOpts.b = signature;
        signatureHeaders.push(formatDKIMHeaderLine(dkimHeaderOpts, true));
    }

    return signatureHeaders;
};

const fs = require('fs');

const time = 1598079221278;

sign(fs.createReadStream('./test/fixtures/message1.eml'), {
    algorithm: 'rsa-SHA256',
    canonicalization: 'simple/simple',
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
