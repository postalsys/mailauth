'use strict';

const { spf } = require('../spf');
const { createResolver } = require('./resolver');

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

    if (typeof argv.maxLookups === 'number') {
        opts.maxResolveCount = argv.maxLookups;
    }

    if (typeof argv.maxVoidLookups === 'number') {
        opts.maxVoidCount = argv.maxVoidLookups;
    }

    if (argv.strict) {
        opts.strict = true;
    }

    if (argv.maxElapsedTime) {
        opts.maxElapsedTime = Number(argv.maxElapsedTime);
    }

    for (let key of ['sender', 'helo', 'mta']) {
        if (argv[key]) {
            opts[key] = argv[key];
        }
    }

    opts.resolver = await createResolver(argv);

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
