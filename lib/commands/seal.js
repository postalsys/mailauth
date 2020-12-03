'use strict';

const { authenticate } = require('../mailauth');
const fs = require('fs');
const { GathererStream } = require('../gatherer-stream');

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

    let gatherer = new GathererStream({ gather: !argv.headersOnly });
    stream.pipe(gatherer);
    stream.on('error', err => gatherer.emit('error', err));

    let privateKey = await fs.promises.readFile(argv.privateKey, 'utf-8');
    let signatureOpts = {
        signingDomain: argv.domain,
        selector: argv.selector,
        privateKey,
        canonicalization: argv.canonicalization,
        algorithm: argv.algo,
        signTime: argv.time ? new Date(argv.time * 1000) : new Date()
    };

    if (argv.verbose) {
        if (signatureOpts.signingDomain) {
            console.error(`Signing domain:             ${signatureOpts.signingDomain}`);
        }
        if (signatureOpts.selector) {
            console.error(`Key selector:               ${signatureOpts.selector}`);
        }
        if (signatureOpts.canonicalization) {
            console.error(`Canonicalization algorithm: ${signatureOpts.canonicalization}`);
        }
        if (signatureOpts.algorithm) {
            console.error(`Hashing algorithm:          ${signatureOpts.algorithm}`);
        }
        if (signatureOpts.signTime) {
            console.error(`Signing time:               ${signatureOpts.signTime.toISOString()}`);
        }
        console.error('--------');
    }

    const opts = {
        trustReceived: true,
        seal: signatureOpts
    };

    if (argv.clientIp) {
        opts.ip = argv.clientIp;
    }

    for (let key of ['mta', 'helo', 'sender']) {
        if (argv[key]) {
            opts[key] = argv[key];
        }
    }

    if (argv.dnsCache) {
        let dnsCache = JSON.parse(await fs.promises.readFile(argv.dnsCache, 'utf-8'));

        opts.resolver = async (name, rr) => {
            let match = dnsCache?.[name]?.[rr];

            if (argv.verbose) {
                console.error(`DNS query for ${rr} ${name}: ${match ? JSON.stringify(match) : 'not found'}`);
            }

            if (!match) {
                let err = new Error('Error');
                err.code = 'ENOTFOUND';
                throw err;
            }

            return match;
        };
    }

    let result = await authenticate(gatherer, opts);

    process.stdout.write(result.headers);
    if (!argv.headersOnly) {
        // print full message as well
        await new Promise((resolve, reject) => {
            let msgStream = gatherer.replay();

            msgStream.pipe(process.stdout, { end: false });
            msgStream.on('end', () => {
                resolve();
            });

            msgStream.on('error', err => {
                reject(err);
            });
        });
    }
};

module.exports = cmd;
