'use strict';

let { relaxedHeaders } = require('./relaxed');
let { simpleHeaders } = require('./simple');

const dkimHeader = (signedHeaderLines, options) => {
    options = options || {};
    let canonicalization = (options.canonicalization || 'relaxed/relaxed').toString().split('/').shift().toLowerCase().trim();
    switch (canonicalization) {
        case 'simple':
            return simpleHeaders(signedHeaderLines, options);
        case 'relaxed':
            return relaxedHeaders(signedHeaderLines, options);
        default:
            throw new Error('Unknown header canonicalization');
    }
};

module.exports = { dkimHeader };
