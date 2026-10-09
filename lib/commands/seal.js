'use strict';

const { Buffer } = require('node:buffer');
const { authenticate } = require('../mailauth');
const { createSeal } = require('../arc');
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
        signTime: argv.time ? new Date(argv.time * 1000) : new Date(),
        strict: !!argv.strict
    };

    if (argv.authResults || argv.authResultsFile) {
        // Seal-only mode: embed the caller-provided Authentication-Results value without authenticating the message
        let authResults = argv.authResultsFile ? (await fs.promises.readFile(argv.authResultsFile, 'utf-8')).trim() : argv.authResults;
        // a folded value from a file usually has LF line endings, header folding needs CRLF.
        // createSeal refuses any line break that does not continue the header with whitespace
        authResults = authResults.replace(/\r?\n/g, '\r\n');

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

        let { headers, errors, warnings } = await createSeal(gatherer, { seal: sealOpts });

        if (!headers.length) {
            // nothing was sealed, say why instead of printing the message as if it had been
            let err = errors?.[0]?.err || new Error('The message could not be sealed');
            throw err;
        }

        // the instance createSeal actually used, from the ARC-Authentication-Results header it created
        let instance = Number((headers[2].match(/^ARC-Authentication-Results: i=(\d+);/) || [])[1]);

        if (instance > 1 && !argv.cv) {
            console.error(`warning: sealed with i=${instance} and cv=none; a chain with i>1 only validates when cv=pass (use --cv pass)`);
        }

        for (let warning of warnings || []) {
            switch (warning) {
                case 'arc-instance-gap':
                    console.error(`warning: sealed with i=${instance}, which does not follow the existing ARC chain`);
                    break;
                case 'arc-cv-instance':
                    // covered by the message above for the default cv
                    if (argv.cv) {
                        console.error(`warning: cv=${argv.cv} is not valid for i=${instance} (i=1 takes cv=none, later sets take cv=pass or cv=fail)`);
                    }
                    break;
                default:
                    console.error(`warning: ${warning}`);
            }
        }

        process.stdout.write(Buffer.from(headers.join('\r\n') + '\r\n'));
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
        seal: signatureOpts,
        strict: !!argv.strict
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

    for (let sealError of result.arc?.sealErrors || []) {
        // the message is printed without a seal
        console.error(`warning: the message was not sealed: ${sealError?.err?.message || sealError?.err}`);
    }

    process.stdout.write(result.headers);
    if (!argv.headersOnly) {
        // print full message as well
        await writeMessageBody(gatherer);
    }
};

module.exports = cmd;
