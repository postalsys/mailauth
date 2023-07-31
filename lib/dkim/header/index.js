'use strict';

let { relaxedHeaders } = require('./relaxed');
let { simpleHeaders } = require('./simple');

const generateCanonicalizedHeader = (type, signingHeaderLines, options) => {
    options = options || {};
    let canonicalization = (options.canonicalization || 'simple/simple').toString().split('/').shift().toLowerCase().trim();
    switch (canonicalization) {
        case 'simple':
            return simpleHeaders(type, signingHeaderLines, options);
        case 'relaxed':
            return relaxedHeaders(type, signingHeaderLines, options);
        default: {
            let error = new Error('Unknown header canonicalization');
            error.canonicalization = canonicalization;
            throw error;
        }
    }
};

module.exports = { generateCanonicalizedHeader };
