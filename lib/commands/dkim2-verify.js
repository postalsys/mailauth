'use strict';

const { dkim2Verify } = require('../dkim2/verify');
const { createResolver } = require('./resolver');
const fs = require('node:fs');

const cmd = async argv => {
    let source = argv.email;

    if (argv.verbose) {
        console.error(`Reading email message from ${source || 'standard input'}`);
    }

    let stream = source ? fs.createReadStream(source) : process.stdin;

    let opts = {
        resolver: await createResolver(argv),
        rcptTo: argv.rcptTo
    };

    if (typeof argv.mailFrom === 'string') {
        opts.mailFrom = argv.mailFrom;
    }

    if (typeof argv.time === 'number') {
        opts.curTime = new Date(argv.time * 1000);
    }

    if (typeof argv.maxAge === 'number') {
        // 0 turns the expiration check off
        opts.maxSignatureAge = argv.maxAge || false;
    }

    if (typeof argv.maxFuture === 'number') {
        opts.maxFutureTime = argv.maxFuture;
    }

    if (typeof argv.maxInstances === 'number') {
        opts.maxInstances = argv.maxInstances;
    }

    let result = await dkim2Verify(stream, opts);

    if (argv.verbose) {
        for (let warning of result.status.warnings || []) {
            console.error(`Warning: ${warning}`);
        }
    }

    if (argv.headersOnly) {
        process.stdout.write(result.info + '\n');
        return;
    }

    process.stdout.write(JSON.stringify(result, false, 2) + '\n');
};

module.exports = cmd;
