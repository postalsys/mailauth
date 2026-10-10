'use strict';

const { authenticate } = require('../mailauth');
const fs = require('node:fs');
const { createResolver } = require('./resolver');

const cmd = async argv => {
    let source = argv.email;
    let useStdin = false;
    let stream;

    if (!source) {
        useStdin = true;
        source = 'standard input';
    }

    if (argv.verbose) {
        console.error(`Reading email message from ${source}`);
    }

    if (useStdin) {
        stream = process.stdin;
    } else {
        stream = fs.createReadStream(source);
    }

    const opts = {
        trustReceived: true,
        strict: !!argv.strict,
        rejectRsaSha1: !!argv.rejectRsaSha1,
        dkim2: !!argv.dkim2
    };

    if (argv.rcptTo) {
        opts.rcptTo = argv.rcptTo;
    }

    if (argv.clientIp) {
        opts.ip = argv.clientIp;
    }

    if (typeof argv.maxLookups === 'number') {
        opts.maxResolveCount = argv.maxLookups;
    }

    if (typeof argv.maxVoidLookups === 'number') {
        opts.maxVoidCount = argv.maxVoidLookups;
    }

    for (let key of ['mta', 'helo', 'sender']) {
        if (argv[key]) {
            opts[key] = argv[key];
        }
    }

    opts.resolver = await createResolver(argv);

    let result = await authenticate(stream, opts);
    process.stdout.write(JSON.stringify(result, false, 2) + '\n');
};

module.exports = cmd;
