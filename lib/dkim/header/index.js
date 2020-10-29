'use strict';

let { relaxedHeaders } = require('./relaxed');
let { simpleHeaders } = require('./simple');

const generateCanonicalizedHeader = (type, signingHeaderLines, options) => {
    options = options || {};
    let canonicalization = (options.canonicalization || 'relaxed/relaxed').toString().split('/').shift().toLowerCase().trim();
    switch (canonicalization) {
        case 'simple':
            return simpleHeaders(type, signingHeaderLines, options);
        case 'relaxed':
            return relaxedHeaders(type, signingHeaderLines, options);
        default:
            throw new Error('Unknown header canonicalization');
    }
};

module.exports = { generateCanonicalizedHeader };
