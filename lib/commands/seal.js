'use strict';

const { authenticate } = require('../mailauth');
const { sealMessage } = require('../arc');
const fs = require('node:fs');
const { GathererStream } = require('../gatherer-stream');
const { resolve } = require('node:dns').promises;

const writeMessageBody = async gatherer =>
    new Promise((resolve, reject) => {
        let msgStream = gatherer.replay();

        msgStream.pipe(process.stdout, { end: false });
        msgStream.on('end', () => {
            resolve();
        });

        msgStream.on('error', err => {
            reject(err);
        });
    });

const printSignatureInfo = opts => {
    if (opts.signingDomain) {
        console.error(`Signing domain:             ${opts.signingDomain}`);
    }
    if (opts.selector) {
        console.error(`Key selector:               ${opts.selector}`);
    }
    if (opts.algorithm) {
        console.error(`Hashing algorithm:          ${opts.algorithm}`);
    }
    if (opts.signTime) {
        console.error(`Signing time:               ${opts.signTime.toISOString()}`);
    }
};

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
        algorithm: argv.algo,
        headerList: argv.headerFields,
        signTime: argv.time ? new Date(argv.time * 1000) : new Date()
    };

    if (argv.authResults || argv.authResultsFile) {
        // Seal-only mode: embed the caller-provided Authentication-Results value without authenticating the message
        let authResults = argv.authResultsFile ? (await fs.promises.readFile(argv.authResultsFile, 'utf-8')).trim() : argv.authResults;

        let sealOpts = Object.assign({}, signatureOpts, {
            authResults,
            cv: argv.cv || 'none'
        });

        if (argv.instance) {
            sealOpts.i = argv.instance;
        }

        if (argv.verbose) {
            console.error('Seal-only mode: sealing with provided authentication results, skipping authentication');
            printSignatureInfo(sealOpts);
            console.error(`Chain validation status:    ${sealOpts.cv}`);
            if (sealOpts.i) {
                console.error(`ARC instance:               ${sealOpts.i}`);
            }
            console.error('--------');
        }

        let sealHeaders = await sealMessage(gatherer, sealOpts);

        // createSeal writes the instance it actually used back into the seal options
        if (sealOpts.i > 1 && !argv.cv) {
            console.error(`warning: sealed with i=${sealOpts.i} and cv=none; a chain with i>1 only validates when cv=pass (use --cv pass)`);
        }

        process.stdout.write(sealHeaders);
        if (!argv.headersOnly) {
            // print full message as well
            await writeMessageBody(gatherer);
        }
        return;
    }

    if (argv.verbose) {
        printSignatureInfo(signatureOpts);
        if (signatureOpts.headerList) {
            console.error(`Header fields to seal:      ${signatureOpts.headerList}`);
        }
        if (argv.dnsCache) {
            console.error(`Using DNS cache:             ${argv.dnsCache}`);
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

    let result = await authenticate(gatherer, opts);

    process.stdout.write(result.headers);
    if (!argv.headersOnly) {
        // print full message as well
        await writeMessageBody(gatherer);
    }
};

module.exports = cmd;
