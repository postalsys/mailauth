'use strict';

const verifyDmarc = require('./verify');

const dmarc = async opts => verifyDmarc(opts);

module.exports = { dmarc };
