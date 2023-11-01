'use strict';

const crypto = require('crypto');
const fs = require('fs');

function edPemToDkim(pemKey) {
    console.log('PPP', pemKey);
    console.log(pemKey.toString());
    const privateKey = crypto.createPrivateKey(pemKey);
    return privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64');
}

function edToDkim(privateKey) {
    return privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64');
}

function edToPem(privateKey) {
    return privateKey.export({ format: 'pem', type: 'pkcs8' });
}

function edFromDkim(keyStr) {
    const derKey = Buffer.concat([Buffer.from('MC4CAQAwBQYDK2VwBCIEIA==', 'base64'), Buffer.from(keyStr, 'base64')]);
    return crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' });
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
console.log(edToPem(privateKey));
let dk = edToDkim(privateKey);
console.log(dk);
console.log(edFromDkim(dk).export({ format: 'pem', type: 'pkcs8' }));
