'use strict';

const { writeToStream } = require('../tools');
const { Dkim2Verifier } = require('./dkim2-verifier');

/**
 * Verifies the DKIM2 header fields of a message (draft-ietf-dkim-dkim2-spec-06 section 11)
 *
 * @param {ReadableStream|Buffer|String} input RFC 5322 message
 * @param {Object} [options] Verification options, see Dkim2Verifier
 * @returns {Object} Verification result, see docs/dkim2.md
 */
const dkim2Verify = async (input, options) => {
    let verifier = new Dkim2Verifier(options);
    await writeToStream(verifier, input);
    return verifier.result;
};

module.exports = { dkim2Verify };
