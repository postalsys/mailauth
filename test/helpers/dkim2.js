'use strict';

// Keys, key records and a resolver for the DKIM2 tests

const crypto = require('node:crypto');
const { privateKey } = require('./keys');
const { zoneResolver } = require('./dns-zone');
const { dkim2Sign } = require('../../lib/dkim2/sign');

const rsaKey = privateKey('private-rsa.pem');
const ed25519Key = privateKey('private-ed25519.pem');

// the base64 key data of a key record: SubjectPublicKeyInfo for RSA, the bare key for Ed25519
const publicKeyData = key => {
    let publicKey = crypto.createPublicKey(key);
    let spki = publicKey.export({ format: 'der', type: 'spki' });
    return (publicKey.asymmetricKeyType === 'ed25519' ? spki.subarray(-32) : spki).toString('base64');
};

const keyRecord = (key, extra) => {
    let type = crypto.createPublicKey(key).asymmetricKeyType;
    return `v=DKIM1; k=${type}; ${extra ? extra + '; ' : ''}p=${publicKeyData(key)}`;
};

// a second set of keys for the other domains of a chain
const generated = {
    rsa: crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }),
    ed25519: crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' })
};

// records for example.com (rsa, ed), list.example.org (lrsa, led) and fwd.example.net (frsa)
const defaultZone = () => ({
    'rsa._domainkey.example.com': { TXT: [[keyRecord(rsaKey)]] },
    'ed._domainkey.example.com': { TXT: [[keyRecord(ed25519Key)]] },
    'lrsa._domainkey.list.example.org': { TXT: [[keyRecord(generated.rsa)]] },
    'led._domainkey.list.example.org': { TXT: [[keyRecord(generated.ed25519)]] },
    'frsa._domainkey.fwd.example.net': { TXT: [[keyRecord(generated.rsa)]] },
    'frsa._domainkey.example.net': { TXT: [[keyRecord(generated.rsa)]] }
});

const resolver = zone => zoneResolver(Object.assign(defaultZone(), zone || {}));

const message = (extraHeaders, body) =>
    Buffer.from(
        [
            'From: Sender <sender@example.com>',
            'To: rcpt@example.net',
            'Subject: Hello DKIM2',
            'Date: Sat, 10 Oct 2026 10:00:00 +0000',
            'Message-ID: <dkim2-test@example.com>',
            ...(extraHeaders || []),
            '',
            body === undefined ? 'Hello world!\r\n\r\nSecond paragraph.\r\n' : body
        ].join('\r\n')
    );

// the originator hop: example.com sends to rcpt@example.net
const originatorOptions = extra =>
    Object.assign(
        {
            signingDomain: 'example.com',
            signatureData: [
                { selector: 'rsa', privateKey: rsaKey },
                { selector: 'ed', privateKey: ed25519Key }
            ],
            mailFrom: 'sender@example.com',
            rcptTo: 'rcpt@example.net'
        },
        extra || {}
    );

// signs and returns the message with the new header fields on top
const signMessage = async (input, options) => {
    let result = await dkim2Sign(input, options);
    return Buffer.concat([Buffer.from(result.signatures), Buffer.from(input)]);
};

module.exports = { rsaKey, ed25519Key, generated, keyRecord, publicKeyData, resolver, message, originatorOptions, signMessage };

// Signs a hand written DKIM2-Signature with the reference implementation, so that tests can
// build header fields the library signer refuses to create. `header` has empty signature values
// ("s=rsa:rsa-sha256:"), `keys` maps a selector to its private key. Returns the message with the
// signed header field on top
const craftSignature = (input, header, keys) => {
    const reference = require('./dkim2-reference');
    let str = `${header}\r\n${Buffer.from(input).toString('binary')}`;
    let i = Number(reference.getTag(header.slice(header.indexOf(':') + 1), 'i'));
    let data = reference.signatureInput(str, i);
    let signed = header.replace(/([A-Za-z0-9._-]+):(rsa-sha256|ed25519-sha256):(?=[,;]|$)/g, (m, selector, algorithm) => {
        let key = crypto.createPrivateKey(keys[selector]);
        let signature =
            algorithm === 'ed25519-sha256' ? crypto.sign(null, crypto.createHash('sha256').update(data).digest(), key) : crypto.sign('sha256', data, key);
        return `${selector}:${algorithm}:${signature.toString('base64')}`;
    });
    return Buffer.from(`${signed}\r\n${Buffer.from(input).toString('binary')}`, 'binary');
};

const b64 = value => Buffer.from(value).toString('base64');

module.exports.craftSignature = craftSignature;
module.exports.b64 = b64;
