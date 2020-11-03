'use strict';

const { authenticate } = require('../lib/mailauth');
const { sealMessage } = require('../lib/arc');
const dns = require('dns');

const fs = require('fs');

const main = async () => {
    let message = await fs.promises.readFile(process.argv[2] || __dirname + '/../test/fixtures/message4.eml');
    let res = await authenticate(message, {
        ip: '217.146.67.33',
        helo: 'uvn-67-33.tll01.zonevs.eu',
        mta: 'mx.ethereal.email',
        sender: 'andris@ekiri.ee',
        resolver: async (name, rr) => {
            console.log('DNS', rr, name);
            return await dns.promises.resolve(name, rr);
        }
    });

    console.log(JSON.stringify(res, false, 2));

    console.log('----');
    console.log(res.headers.trim());
    console.log('----');

    let seal = await sealMessage(message, {
        signingDomain: 'tahvel.info',
        selector: 'test.rsa',
        privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem'),

        authResults: res.arc.authResults,
        cv: res.arc.status.result,

        signTime: new Date(1604396942500)
    });

    process.stdout.write(seal);
    process.stdout.write(res.headers);
    process.stdout.write(message);
};

main()
    .then(() => {
        console.log('done');
    })
    .catch(err => {
        console.error(err);
    });
