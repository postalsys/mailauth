'use strict';

// verify signed message:
//   $ node verify-dkim.js /path/to/message.eml

const fs = require('fs');
const { dkimVerify } = require('../lib/dkim/verify');

let file = process.argv[2];
let eml = fs.readFileSync(file);

if (process.argv[3]) {
    eml = Buffer.concat([eml, Buffer.from('\r\n')]);
}

dkimVerify(eml)
    .then(res => {
        console.log(JSON.stringify(res, false, 2));
    })
    .catch(err => {
        console.error(err);
    });
