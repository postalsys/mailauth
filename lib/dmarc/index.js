'use strict';

const verifyDmarc = require('./verify');

const dmarc = async opts => {
    return await verifyDmarc(opts);
};

module.exports = { dmarc };
