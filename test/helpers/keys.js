'use strict';

const fs = require('node:fs');

const fixturePath = file => __dirname + `/../fixtures/${file}`;

// Reads a PEM fixture and returns it as the base64 body of a DKIM/ARC public key record
const dkimTxtRecord = file => `v=DKIM1; k=rsa; p=${fs.readFileSync(fixturePath(file), 'utf8').replace(/-----[^-]+-----|\s/g, '')}`;

const privateKey = file => fs.readFileSync(fixturePath(file));

module.exports = { dkimTxtRecord, privateKey };
