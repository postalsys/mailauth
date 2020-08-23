'use strict';

const fs = require('fs');
const { dkimVerify } = require('../lib/dkim/verify');

let file = process.argv[2];
let eml = fs.readFileSync(file);

dkimVerify(eml)
    .then(res => console.log('result', res))
    .catch(err => console.error(err));
