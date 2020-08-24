'use strict';

const { writeToStream } = require('../../lib/tools');
const { DkimVerifier } = require('./dkim-verifier');

const dkimVerify = async input => {
    let dkimVerifier = new DkimVerifier();
    await writeToStream(dkimVerifier, input);
    return {
        headerFrom: dkimVerifier.headerFrom,
        envelopeFrom: dkimVerifier.envelopeFrom,
        results: dkimVerifier.results
    };
};

module.exports = { dkimVerify };
