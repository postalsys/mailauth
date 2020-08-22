'use strict';

let { SimpleBody } = require('./simple');
let { RelaxedBody } = require('./relaxed');

const bodyHash = options => {
    let canonicalization = (options.canonicalization || 'relaxed/relaxed').toString().split('/').pop().toLowerCase().trim();
    switch (canonicalization) {
        case 'simple':
            return new SimpleBody(options);
        case 'relaxed':
            return new RelaxedBody(options);
        default:
            throw new Error('Unknown body canonicalization');
    }
};

module.exports = bodyHash;
