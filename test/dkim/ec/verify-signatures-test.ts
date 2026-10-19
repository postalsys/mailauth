/* eslint @typescript-eslint/no-unused-expressions:0 */
import { describe, it } from 'node:test';
import { expect, config } from 'chai';
import { Buffer } from 'node:buffer';
import Path from 'node:path';
import { fileURLToPath } from 'node:url';
import { dkimSign } from '../../../src/dkim/sign.js';
import { dkimVerify } from '../../../src/dkim/verify.js';
import fs from 'node:fs';

const curTime = new Date(1528637909000);

const __dirname = Path.dirname(fileURLToPath(import.meta.url));

const dnsCache = JSON.parse(fs.readFileSync(Path.join(__dirname, 'fixtures', 'dns.json'), 'utf8'));
const privateKeyEC = fs.readFileSync(Path.join(__dirname, 'fixtures', 'private-ec.key'));
const privateKeyRSA = fs.readFileSync(Path.join(__dirname, 'fixtures', 'private-rsa.key'));
const signedEmail = fs.readFileSync(Path.join(__dirname, 'fixtures', 'signed.eml'));

const formatECPrivateKey = (key: any) => {
    if (key.length === 44) {
        return `-----BEGIN PRIVATE KEY-----
${Buffer.concat([Buffer.from('MC4CAQAwBQYDK2VwBCIEIA==', 'base64'), Buffer.from(key, 'base64')]).toString('base64')}
-----END PRIVATE KEY-----`;
    }
    return key;
};

const cachedResolver = async (name: string, rr: string) => {
    let match = dnsCache?.[name]?.[rr];

    if (!match) {
        let err: NodeJS.ErrnoException = new Error('Error');
        err.code = 'ENOTFOUND';
        throw err;
    }

    return match;
};

config.includeStack = true;

// FIXME: EC signing does not work!

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

        expect(res.signatures).to.exist;
    });

    it('Should verify hashes for a signed email', async () => {
        let res = await dkimVerify(signedEmail, {
            resolver: cachedResolver,
            curTime
        });

        expect(res.results[0].status.result).equal('pass');
        expect(res.results[1].status.result).equal('pass');

        expect(true).to.equal(true);
    });
});
