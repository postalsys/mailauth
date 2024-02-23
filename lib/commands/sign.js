'use strict';

const { dkimSign } = require('../dkim/sign');
const { GathererStream } = require('../gatherer-stream');
const fs = require('node:fs');

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
        maxBodyLength: argv.bodyLength,
        headerList: argv.headerFields
    };

    let signTime = argv.time ? new Date(argv.time * 1000) : new Date();

    if (argv.verbose) {
        if (signatureOpts.signingDomain) {
            console.error(`Signing domain:             ${signatureOpts.signingDomain}`);
        }
        if (signatureOpts.selector) {
            console.error(`Key selector:               ${signatureOpts.selector}`);
        }
        if (signatureOpts.algorithm) {
            console.error(`Hashing algorithm:          ${signatureOpts.algorithm}`);
        }
        if (signatureOpts.canonicalization) {
            console.error(`Canonicalization algorithm: ${signatureOpts.canonicalization}`);
        }
        if (signatureOpts.maxBodyLength) {
            console.error(`Maximum body length:        ${signatureOpts.maxBodyLength}`);
        }
        if (signatureOpts.headerList) {
            console.error(`Header fields to sign:      ${signatureOpts.headerList}`);
        }
        if (signTime) {
            console.error(`Signing time:               ${signTime.toISOString()}`);
        }
        console.error('--------');
    }

    let signResult = await dkimSign(gatherer, {
        signTime,
        signatureData: [signatureOpts]
    });

    if (signResult.errors?.length) {
        if (argv.verbose) {
            for (let error of signResult.errors) {
                console.error(`Signing error for ${error.signingDomain}/${error.selector}: ${error.err.message}`);
            }
        }
        let err = new Error('Failed to sign message');
        err.suppress = true;
        throw err;
    }

    process.stdout.write(signResult.signatures);
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
