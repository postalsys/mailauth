'use strict';

const fs = require('fs');
const crypto = require('crypto');
const subtle = crypto.subtle;

const data = Buffer.from(
    fs
        .readFileSync(__dirname + '/canon-header.bin', 'binary')
        .replace(/[ \t]/g, ' ')
        .replace(/\r?\n/g, '\r\n')
        .replace(/\s*$/, ''),
    'binary'
);

const secretKeyBuf = Buffer.from(fs.readFileSync(__dirname + '/ed.key', 'ascii'), 'base64');
const pubKeyBuf = Buffer.from('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=', 'base64');
const signature = Buffer.from('/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11BusFa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==', 'base64');

//let verifier = crypto.createVerify('ed25519');
//verifier.update(data);

console.log(data.toString());
console.log(data.toString('base64'));

let main = async () => {
    const pubkey = await subtle.importKey('raw', pubKeyBuf, 'Ed25519', false, ['verify']);

    console.log(pubkey);

    let res = await subtle.verify('Ed25519', pubkey, signature, data);
    console.log(res);
};

main().catch(err => console.error(err));
