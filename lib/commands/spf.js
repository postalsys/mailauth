'use strict';

const { spf } = require('../spf');
const fs = require('node:fs');
const { resolve } = require('node:dns').promises;

const cmd = async argv => {
    let address = argv.sender;

    if (argv.verbose) {
        console.error(`Checking SPF for ${address}`);
        if (argv.maxLookups) {
            console.error(`Maximum DNS lookups: ${argv.maxLookups}`);
        }
        if (argv.dnsCache) {
            console.error(`Using DNS cache:      ${argv.dnsCache}`);
        }
        console.error('--------');
    }

    let opts = {};

    if (argv.clientIp) {
        opts.ip = argv.clientIp;
    }

    if (argv.maxLookups) {
        opts.maxResolveCount = argv.maxLookups;
    }

    if (argv.maxVoidLookups) {
        opts.maxVoidCount = argv.maxVoidLookups;
    }

    for (let key of ['sender', 'helo', 'mta']) {
        if (argv[key]) {
            opts[key] = argv[key];
        }
    }

    if (argv.dnsCache) {
        let dnsCache = JSON.parse(await fs.promises.readFile(argv.dnsCache, 'utf-8'));

        opts.resolver = async (name, rr) => {
            let match = dnsCache?.[name]?.[rr];

            if (argv.verbose) {
                console.error(`DNS query for ${rr} ${name}: ${match ? JSON.stringify(match) : 'not found'} (using cache)`);
            }

            if (!match) {
                let err = new Error('Error');
                err.code = 'ENOTFOUND';
                throw err;
            }

            return match;
        };
    } else if (argv.verbose) {
        opts.resolver = async (name, rr) => {
            let match;
            try {
                match = await resolve(name, rr);
                console.error(`DNS query for ${rr} ${name}: ${match ? JSON.stringify(match) : 'not found'}`);
                return match;
            } catch (err) {
                console.error(`DNS query for ${rr} ${name}: ${err.message}${err.code ? ` [${err.code}]` : ''}`);
                throw err;
            }
        };
    }

    let result;
    try {
        result = await spf(opts);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }

    if (argv.headersOnly) {
        process.stdout.write(result.header + '\r\n');
        return;
    }

    process.stdout.write(JSON.stringify(result, false, 2) + '\n');
};

module.exports = cmd;
