'use strict';

const verifyDmarc = require('./verify');

const dmarc = async opts => {
    let result = await verifyDmarc(opts);

    switch (result && result.status) {
        case 'pass':
        case 'fail':
        case 'none':
        case 'temperror':
        case 'permerror':
            {
                let p = result.p;
                let sp = result.sp || result.p;
                let policyInfo = [].concat(p ? `p=${p.toUpperCase()}` : []).concat(sp ? `sp=${sp.toUpperCase()}` : []);
                result.info = `dmarc=${result.status}${policyInfo.length ? ` (${policyInfo.join(' ')})` : ''} header.from=${result.domain}`;
            }
            break;
    }

    return result;
};

module.exports = { dmarc };
