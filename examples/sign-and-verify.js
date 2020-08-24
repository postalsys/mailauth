'use strict';

const fs = require('fs');
const message = fs.readFileSync(__dirname + '/../test/fixtures/message1.eml');

const { dkimSign } = require('../lib/dkim/sign');
const { dkimVerify } = require('../lib/dkim/verify');

const time = 1598079221278;

dkimSign(message, {
    algorithm: 'rsa-sha256',
    canonicalization: 'simple/simple',
    signTime: time,

    signatureData: [
        {
            signingDomain: 'tahvel.info',
            selector: 'test.invalid',
            privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
        },
        {
            signingDomain: 'tahvel.info',
            selector: 'test.rsa',
            privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
        },
        {
            signingDomain: 'tahvel.info',
            selector: 'test.small',
            privateKey: fs.readFileSync('./test/fixtures/private-small.pem')
        },

        {
            signingDomain: 'tahvel.info',
            selector: 'test.ed25519',
            privateKey: fs.readFileSync('./test/fixtures/private-ed25519.pem')
        }
    ]
})
    .then(res => {
        console.log(res.join('\n'));
        return dkimVerify(Buffer.concat([Buffer.from(res.join('\r\n') + '\r\n'), message]));
    })
    .then(res => console.log('result', res))
    .catch(err => console.error(err));
