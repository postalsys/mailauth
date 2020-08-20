'use strict';

let { SimpleBody } = require('./simple');
let { RelaxedBody } = require('./relaxed');

const bodyHash = (algo, options) => {
    algo = (algo || 'relaxed').toString().split('/').pop().toLowerCase().trim();
    switch (algo) {
        case 'simple':
            return new SimpleBody(options);
        case 'relaxed':
            return new RelaxedBody(options);
        default:
            throw new Error('Unknown body hash algorithm');
    }
};

module.exports = bodyHash;
