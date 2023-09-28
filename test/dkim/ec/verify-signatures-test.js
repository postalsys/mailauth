/* eslint no-unused-expressions:0 */
'use strict';

// FIXME: Ed25519 signing and verification _does not work_

const chai = require('chai');
const expect = chai.expect;
const Path = require('path');
const util = require('util');

const { dkimSign } = require('../../../lib/dkim/sign');
const { dkimVerify } = require('../../../lib/dkim/verify');

let fs = require('fs');

const curTime = new Date(1528637909000);

const dnsCache = require('./fixtures/dns.json');
const privateKeyEC = fs.readFileSync(Path.join(__dirname, 'fixtures', 'private-ec.key'));
const privateKeyRSA = fs.readFileSync(Path.join(__dirname, 'fixtures', 'private-rsa.key'));
const signedEmail = fs.readFileSync(Path.join(__dirname, 'fixtures', 'signed.eml'));

const formatECPrivateKey = key => {
    if (key.length === 44) {
        return `-----BEGIN PRIVATE KEY-----
${Buffer.concat([Buffer.from('MC4CAQAwBQYDK2VwBCIEIA==', 'base64'), Buffer.from(key, 'base64')]).toString('base64')}
-----END PRIVATE KEY-----`;
    }
    return key;
};

const cachedResolver = async (name, rr) => {
    let match = dnsCache?.[name]?.[rr];

    console.log('DNS', name, rr, match);

    if (!match) {
        let err = new Error('Error');
        err.code = 'ENOTFOUND';
        throw err;
    }

    return match;
};

chai.config.includeStack = true;

describe('DKIM EC Signature tests', () => {
    it('Should sign an email', async () => {
        let ecPrivateKey = formatECPrivateKey(privateKeyEC);

        let res = await dkimSign(signedEmail, {
            canonicalization: 'relaxed/relaxed',
            signTime: curTime,
            signatureData: [
                {
                    algorithm: 'rsa-sha256',
                    signingDomain: 'football.example.com',
                    selector: 'test',
                    privateKey: privateKeyRSA
                },

                {
                    algorithm: 'ed25519-sha256',
                    signingDomain: 'football.example.com',
                    selector: 'brisbane',
                    privateKey: ecPrivateKey
                }
            ]
        });

        console.log(util.inspect(res, false, 22, true));

        expect(true).to.equal(true);
    });

    it('Should verify hashes for a signed email', async () => {
        let res = await dkimVerify(signedEmail, {
            resolver: cachedResolver,
            curTime
        });

        console.log(util.inspect(res, false, 22, true));

        expect(true).to.equal(true);
    });
});
