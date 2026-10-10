'use strict';

const { dkim2Sign } = require('../dkim2/sign');
const { GathererStream } = require('../gatherer-stream');
const fs = require('node:fs');

const cmd = async argv => {
    let source = argv.email;
    let stream;

    if (argv.verbose) {
        console.error(`Reading email message from ${source || 'standard input'}`);
    }

    stream = source ? fs.createReadStream(source) : process.stdin;

    let privateKeys = argv.privateKey || [];
    let selectors = argv.selector || [];
    if (privateKeys.length !== selectors.length) {
        let err = new Error('Every --private-key needs a --selector, in the same order');
        throw err;
    }

    let gatherer = new GathererStream({ gather: !argv.headersOnly });
    stream.pipe(gatherer);
    stream.on('error', err => gatherer.emit('error', err));

    let signatureData = [];
    for (let i = 0; i < privateKeys.length; i++) {
        signatureData.push({ selector: selectors[i], privateKey: await fs.promises.readFile(privateKeys[i], 'utf-8') });
    }

    let options = {
        signingDomain: argv.domain,
        signatureData,
        signTime: argv.time ? new Date(argv.time * 1000) : new Date(),
        flags: argv.flag,
        nonce: argv.nonce
    };

    if (argv.hash?.length) {
        options.hashAlgorithms = argv.hash;
    }

    if (argv.nextDomain) {
        options.nextDomain = argv.nextDomain;
    } else {
        options.mailFrom = argv.mailFrom;
        options.rcptTo = argv.rcptTo;
    }

    if (argv.recipe) {
        options.recipe = JSON.parse(await fs.promises.readFile(argv.recipe, 'utf-8'));
    }

    if (argv.verbose) {
        console.error(`Signing domain: ${options.signingDomain}`);
        console.error(`Selectors:      ${selectors.join(', ')}`);
        console.error(`Signing time:   ${options.signTime.toISOString()}`);
        console.error('--------');
    }

    let signResult = await dkim2Sign(gatherer, options);

    process.stdout.write(signResult.signatures);
    if (!argv.headersOnly) {
        // print the full message as well
        await new Promise((resolve, reject) => {
            let msgStream = gatherer.replay();
            msgStream.pipe(process.stdout, { end: false });
            msgStream.on('end', resolve);
            msgStream.on('error', reject);
        });
    }
};

module.exports = cmd;
