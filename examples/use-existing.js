'use strict';

const { authenticate } = require('../lib/mailauth');
const dns = require('dns');

const fs = require('fs');

const main = async () => {
    let message = await fs.promises.readFile(process.argv[2] || __dirname + '/../test/fixtures/message4.eml');
    let res = await authenticate(message, {
        trustReceived: true,
        resolver: async (name, rr) => {
            console.log('DNS', rr, name);
            return await dns.promises.resolve(name, rr);
        }
    });

    console.log(JSON.stringify(res, false, 2));
};

main()
    .then(() => {
        console.log('done');
    })
    .catch(err => {
        console.error(err);
    });
