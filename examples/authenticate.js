'use strict';

const { authenticate } = require('../lib/mailauth');
const fs = require('fs');

const main = async () => {
    let message = fs.createReadStream(__dirname + '/../test/fixtures/authtest.eml');
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
};

main()
    .then(() => {
        console.log('done');
    })
    .catch(err => {
        console.error(err);
    });
