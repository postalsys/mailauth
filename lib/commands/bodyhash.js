'use strict';

const { DkimSigner } = require('../dkim/dkim-signer');
const { writeToStream } = require('../tools');
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

    if (isNaN(argv.bodyLength) || argv.bodyLength < 0) {
        argv.bodyLength = null;
    }

    let signatureOpts = {
        type: 'DKIM',
        privateKey: true, // force hash calculation
        canonicalization: argv.canonicalization && (argv.canonicalization.includes('/') ? argv.canonicalization : `/${argv.canonicalization}`),
        algorithm: argv.algo,
        maxBodyLength: argv.bodyLength
    };

    let dkimSigner = new DkimSigner({ signatureData: [signatureOpts] });

    let { hashAlgo } = dkimSigner.getAlgorithm(signatureOpts);
    let { bodyCanon } = dkimSigner.getCanonicalization(signatureOpts);

    if (argv.verbose) {
        if (hashAlgo) {
            console.error(`Hashing algorithm:               ${hashAlgo}`);
        }
        if (bodyCanon) {
            console.error(`Body canonicalization algorithm: ${bodyCanon}`);
        }
        if (signatureOpts.maxBodyLength) {
            console.error(`Maximum body length:             ${signatureOpts.maxBodyLength}`);
        }
        console.error('--------');
    }

    await writeToStream(dkimSigner, stream);

    let hashKey = `${bodyCanon}:${hashAlgo}:${typeof argv.bodyLength === 'number' ? argv.bodyLength : ''}`;
    const bodyHash = dkimSigner.bodyHashes.get(hashKey)?.hash;
    if (bodyHash) {
        process.stdout.write(bodyHash);
    }
};

module.exports = cmd;
