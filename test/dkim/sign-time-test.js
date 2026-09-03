/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { authenticate, dkimSign, dkimVerify, sealMessage } = require('../../lib/mailauth');
const { zoneResolver } = require('../helpers/dns-zone');
const { dkimTxtRecord, privateKey } = require('../helpers/keys');
const { buildMessage } = require('../helpers/message');

chai.config.includeStack = true;

// A signature header is built twice: once with an empty b= to be hashed and signed, and
// once more with the signature in it to be emitted. Both have to carry the same t=, so the
// timestamp may only be read from the clock once. Reading it per call signed one second
// and published the next whenever a second boundary fell between the two, which produced
// a DKIM-Signature that verifies nowhere.
//
// Every read of the clock below jumps a full second, so a value read twice is always
// different and the test does not depend on the timing of the run
const RealDate = Date;

class TickingDate extends RealDate {
    constructor(...args) {
        if (args.length === 0) {
            super(TickingDate.now());
        } else {
            super(...args);
        }
    }

    static now() {
        TickingDate.ticks++;
        return RealDate.now() + TickingDate.ticks * 1000;
    }
}

TickingDate.ticks = 0;

const withTickingClock = async fn => {
    TickingDate.ticks = 0;
    global.Date = TickingDate;
    try {
        return await fn();
    } finally {
        global.Date = RealDate;
    }
};

describe('Signature timestamp Tests', () => {
    const message = buildMessage({ from: 'sender@example.com', to: 'rcpt@example.net' });
    const resolver = zoneResolver({ 'test._domainkey.example.com': { TXT: [[dkimTxtRecord('public-rsa.pem')]] } });

    for (const canonicalization of ['relaxed/relaxed', 'simple/simple', 'relaxed/simple', 'simple/relaxed']) {
        it(`Should emit the t= it signed with ${canonicalization} while the clock moves`, async () => {
            const { signatures } = await withTickingClock(() =>
                dkimSign(message, {
                    canonicalization,
                    signatureData: [
                        {
                            signingDomain: 'example.com',
                            selector: 'test',
                            privateKey: privateKey('private-rsa.pem'),
                            algorithm: 'rsa-sha256'
                        }
                    ]
                })
            );

            const result = await dkimVerify(Buffer.concat([Buffer.from(signatures), message]), { resolver });

            expect(result.results).to.have.lengthOf(1);
            expect(result.results[0].status.result).to.equal('pass');
        });
    }

    it('Should keep an explicit signTime', async () => {
        const { signatures } = await withTickingClock(() =>
            dkimSign(message, {
                signTime: new RealDate(1700000000000),
                signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: privateKey('private-rsa.pem'), algorithm: 'rsa-sha256' }]
            })
        );

        expect(signatures).to.include('t=1700000000;');

        const result = await dkimVerify(Buffer.concat([Buffer.from(signatures), message]), { resolver });
        expect(result.results[0].status.result).to.equal('pass');
    });

    it('Should not date a signature into the future', async () => {
        const before = Math.floor(RealDate.now() / 1000);
        const { signatures } = await dkimSign(message, {
            signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: privateKey('private-rsa.pem'), algorithm: 'rsa-sha256' }]
        });

        const timestamp = Number(signatures.match(/[;\s]t=(\d+);/)[1]);
        expect(timestamp).to.be.at.least(before);
        expect(timestamp).to.be.at.most(Math.floor(RealDate.now() / 1000));

        const result = await dkimVerify(Buffer.concat([Buffer.from(signatures), message]), { resolver });
        expect(result.results[0].signatureTimeValid).to.be.true;
    });

    it('Should emit an ARC set that validates while the clock moves', async () => {
        const sealHeaders = await withTickingClock(() =>
            sealMessage(message, {
                signingDomain: 'example.com',
                selector: 'test',
                privateKey: privateKey('private-rsa.pem'),
                algorithm: 'rsa-sha256',
                cv: 'none',
                i: 1,
                authResults: 'mx.example.com; dkim=none'
            })
        );

        const result = await authenticate(Buffer.concat([sealHeaders, message]), {
            ip: '198.51.100.1',
            helo: 'example.com',
            sender: 'sender@example.com',
            mta: 'mx.example.net',
            disableDmarc: true,
            disableBimi: true,
            resolver
        });

        expect(result.arc.status.result).to.equal('pass');
    });
});
