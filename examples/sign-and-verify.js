'use strict';

// sign and verify:
//   $ node sign-and-verify.js /path/to/message.eml

const fs = require('fs');

const { dkimSign } = require('../lib/dkim/sign');
const { dkimVerify } = require('../lib/dkim/verify');

let file = process.argv[2];
let eml = fs.readFileSync(file);

let algo = process.argv[3] || false; // allowed: 'rsa-sha256', 'rsa-sha1', 'ed25519-sha256'

dkimSign(eml, {
    canonicalization: 'simple/simple',
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
})
    .then(signResult => {
        // show signing errors
        if (signResult.errors.length) {
            console.log(signResult.errors);
        }
        // output signed message
        process.stdout.write(signResult.signatures);
        return dkimVerify(Buffer.concat([Buffer.from(signResult.signatures), eml]), {
            // change value to compare expiration timestamps
            curTime: new Date()
        });
    })
    .then(res => {
        console.log('result', res);
        for (let { info } of res.results) {
            console.log(info);
        }
    })
    .catch(err => console.error(err));
