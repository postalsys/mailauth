'use strict';

const { dkimVerify } = require('./dkim/verify');
//const { spf } = require('./spf');

const authenticate = async (input, opts) => {
    const dkimResult = await dkimVerify(input, { resolver: opts.resolver });
    for (let { info } of dkimResult.results) {
        console.log(info);
    }
};

module.exports = { authenticate };
