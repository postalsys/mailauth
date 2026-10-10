'use strict';

const { dkim2Hash } = require('../dkim2/hash');
const fs = require('node:fs');

const cmd = async argv => {
    let source = argv.email;
    if (argv.verbose) {
        console.error(`Reading email message from ${source || 'standard input'}`);
    }

    let { headers, hashes } = await dkim2Hash(source ? fs.createReadStream(source) : process.stdin, { algorithms: argv.algo });

    if (argv.verbose) {
        console.error(`Hashed header fields: ${headers.join(', ') || '(none)'}`);
        console.error('--------');
    }

    // the hash-sets of the h= tag of a Message-Instance (section 7.3)
    for (let { algorithm, headerHash, bodyHash } of hashes) {
        process.stdout.write(`${algorithm}:${headerHash}:${bodyHash}\n`);
    }
};

module.exports = cmd;
