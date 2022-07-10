'use strict';

const { validateVMC } = require('../bimi');

const fs = require('fs').promises;

const cmd = async argv => {
    let bimiData = {};
    if (argv.authorityPath) {
        bimiData.authorityPath = await fs.readFile(argv.authorityPath);
    }

    if (argv.authority) {
        bimiData.authority = argv.authority;
    }

    if (argv.domain) {
        bimiData.status = { header: { d: argv.domain } };
    }

    const result = await validateVMC(bimiData);
    process.stdout.write(JSON.stringify(result.authority, false, 2) + '\n');
};

module.exports = cmd;
