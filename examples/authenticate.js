'use strict';

const { authenticate } = require('../lib/mailauth');
const { dkimSign } = require('../lib/dkim/sign');

const fs = require('fs');

const main = async () => {
    let message = await fs.promises.readFile(process.argv[2] || __dirname + '/../test/fixtures/message4.eml');
    let res = await authenticate(message, {
        ip: '217.146.67.33',
        helo: 'uvn-67-33.tll01.zonevs.eu',
        mta: 'mx.ethereal.email',
        sender: 'andris@ekiri.ee'
    });
    console.log(JSON.stringify(res, false, 2));

    console.log('----');
    console.log(res.headers.trim());
    console.log('----');

    let signed = await dkimSign(message, {
        signTime: Date.now(),
        arc: {
            instance: 1,
            algorithm: 'rsa-sha256',
            signingDomain: 'tahvel.info',
            selector: 'test.rsa',
            privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
        }
    });

    console.log(signed);
};

main()
    .then(() => {
        console.log('done');
    })
    .catch(err => {
        console.error(err);
    });
