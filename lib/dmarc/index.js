'use strict';

const verifyDmarc = require('./verify');
const { evaluateDmarc } = verifyDmarc;

const dmarc = async opts => verifyDmarc(opts);

module.exports = { dmarc, evaluateDmarc };
