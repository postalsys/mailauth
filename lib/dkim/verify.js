'use strict';

const { writeToStream } = require('../../lib/tools');
const { DkimVerifier } = require('./dkim-verifier');

const dkimVerify = async (input, options) => {
    let dkimVerifier = new DkimVerifier(options);
    await writeToStream(dkimVerifier, input);

    const result = {
        //headers: dkimVerifier.headers,
        headerFrom: dkimVerifier.headerFrom,
        envelopeFrom: dkimVerifier.envelopeFrom,
        results: dkimVerifier.results
    };

    if (dkimVerifier.headers) {
        Object.defineProperty(result, 'headers', {
            enumerable: false,
            configurable: false,
            writable: false,
            value: dkimVerifier.headers
        });
    }

    if (dkimVerifier.arc) {
        Object.defineProperty(result, 'arc', {
            enumerable: false,
            configurable: false,
            writable: false,
            value: dkimVerifier.arc
        });
    }

    if (dkimVerifier.seal) {
        Object.defineProperty(result, 'seal', {
            enumerable: false,
            configurable: false,
            writable: false,
            value: dkimVerifier.seal
        });
    }

    return result;
};

module.exports = { dkimVerify };
