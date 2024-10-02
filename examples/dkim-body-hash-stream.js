'use strict';

// sign and verify:
//   $ node sign-and-verify.js /path/to/message.eml

const fs = require('node:fs');
const { BodyHashStream } = require('../lib/dkim/body');

let file = process.argv[2];
let eml = fs.createReadStream(file);

let algo = process.argv[3] || false; // allowed: 'rsa-sha256', 'rsa-sha1', 'ed25519-sha256'

let signer = new BodyHashStream('relaxed/relaxed', algo);

eml.on('error', err => {
    console.error(err);
});

signer.once('hash', hash => {
    console.error('BODY HASH: ' + hash);
});

eml.pipe(signer).pipe(process.stdout);
