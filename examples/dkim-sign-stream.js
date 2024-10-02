'use strict';

// sign and verify:
//   $ node sign-and-verify.js /path/to/message.eml

const fs = require('node:fs');
const { Buffer } = require('node:buffer');
const { DkimSignStream } = require('../lib/dkim/sign');

let file = process.argv[2];
let eml = fs.createReadStream(file);

let algo = process.argv[3] || false; // allowed: 'rsa-sha256', 'rsa-sha1', 'ed25519-sha256'

let signer = new DkimSignStream({
    canonicalization: 'relaxed/relaxed',
    signTime: Date.now(),
    //expires: Date.now() + 1000,
    signatureData: [
        {
            algorithm: algo,
            signingDomain: 'tahvel.info',
            selector: 'test.invalid',
            privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
        },

        {
            algorithm: algo,
            signingDomain: 'tahvel.info',
            selector: 'test.rsa',
            privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
        },

        {
            algorithm: algo,
            signingDomain: 'tahvel.info',
            selector: 'test.small',
            privateKey: fs.readFileSync('./test/fixtures/private-small.pem')
        },

        {
            algorithm: algo,
            signingDomain: 'tahvel.info',
            selector: 'test.small',
            privateKey: fs.readFileSync('./test/fixtures/private-small.pem'),
            maxBodyLength: 12
        },

        {
            // PEM
            //canonicalization: 'relaxed/relaxed',
            algorithm: algo,
            signingDomain: 'tahvel.info',
            selector: 'test.ed25519',
            privateKey: fs.readFileSync('./test/fixtures/private-ed25519.pem')
        },

        {
            // Raw key
            //canonicalization: 'relaxed/relaxed',
            algorithm: algo,
            signingDomain: 'tahvel.info',
            selector: 'test.ed25519',
            privateKey: Buffer.from('YgsMTASxKi7M+Rxg+h9H4UTUNOGsAer6LaQgCwcl3mY=', 'base64')
        }
    ]
});

eml.on('error', err => {
    console.error(err);
});

eml.pipe(signer).pipe(process.stdout);
