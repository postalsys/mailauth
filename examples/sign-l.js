'use strict';

// sign and verify:
//   $ node sign-and-verify.js /path/to/message.eml

const fs = require('fs');

const { dkimSign } = require('../lib/dkim/sign');

let file = process.argv[2];
let eml = fs.readFileSync(file);

let main = async () => {
    let signResult = await dkimSign(eml, {
        signTime: Date.now(),
        signatureData: [
            {
                canonicalization: 'simple/relaxed',
                signingDomain: 'tahvel.info',
                selector: 'test.rsa',
                privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
            },
            {
                canonicalization: 'simple/relaxed',
                signingDomain: 'tahvel.info',
                selector: 'test.rsa',
                privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem'),
                maxBodyLength: 100
            }
        ]
    });

    // show signing errors
    if (signResult.errors?.length) {
        console.error(signResult.errors);
    }

    // output signed message
    process.stdout.write(Buffer.concat([Buffer.from(signResult.signatures), eml]));
};

main().catch(err => console.error(err));
