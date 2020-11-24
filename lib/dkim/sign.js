'use strict';

const { writeToStream } = require('../tools');
const { DkimSigner } = require('./dkim-signer');

const dkimSign = async (input, options) => {
    let dkimSigner = new DkimSigner(options);
    await writeToStream(dkimSigner, input);

    return { signatures: dkimSigner.signatureHeaders.join('\r\n') + '\r\n', arc: dkimSigner.arc, errors: dkimSigner.errors };
};

module.exports = { dkimSign };
