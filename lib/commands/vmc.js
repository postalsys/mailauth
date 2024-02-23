'use strict';

const { validateVMC } = require('../bimi');

const fs = require('node:fs').promises;

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

    let opts = {};
    if (argv.date) {
        let date = new Date(argv.date);
        if (date.toString() !== 'Invalid Date') {
            opts.now = date;
            if (argv.verbose) {
                console.error(`Setting date to: ${argv.date}`);
            }
        } else if (argv.verbose) {
            console.error(`Invalid date argument: ${argv.date}`);
        }
    }

    const result = await validateVMC(bimiData, opts);
    process.stdout.write(JSON.stringify(result.authority, false, 2) + '\n');
};

module.exports = cmd;
