'use strict';

const { validateVMC } = require('../bimi');

const fs = require('fs').promises;

const cmd = async argv => {
    let bimiData = {};
    if (argv.authorityFile) {
        bimiData.authorityFile = await fs.readFile(argv.authorityFile);
    }
    if (argv.authority) {
        bimiData.authority = argv.authority;
    }

    const result = await validateVMC(bimiData);
    process.stdout.write(JSON.stringify(result.authority, false, 2) + '\n');
};

module.exports = cmd;
