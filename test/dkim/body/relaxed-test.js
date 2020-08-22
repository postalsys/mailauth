/* eslint no-unused-expressions:0 */
'use strict';

const { writeToStream } = require('../../../lib/tools');
const chai = require('chai');
const expect = chai.expect;

let fs = require('fs').promises;
let { RelaxedBody } = require('../../../lib/dkim/body/relaxed');

chai.config.includeStack = true;

describe('DKIM RelaxedBody Tests', () => {
    it('Should calculate sha256 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new RelaxedBody({
            algorithm: 'sha256'
        });

        await writeToStream(s, message, 1);
        expect(s.bodyHash).to.equal('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });

    it('Should calculate sha1 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new RelaxedBody({
            algorithm: 'sha1'
        });

        await writeToStream(s, message, 1);
        expect(s.bodyHash).to.equal('2jmj7l5rSw0yVb/vlWAYkK/YBwk=');
    });

    it('Should calculate body hash byte by byte', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');

        let s = new RelaxedBody({
            algorithm: 'sha256'
        });

        await writeToStream(s, message, 1);
        expect(s.bodyHash).to.equal('D2H5TEwtUgM2u8Ew0gG6vnt/Na6L+Zep7apmSmfy8IQ=');
    });

    it('Should calculate body hash all at once', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');

        let s = new RelaxedBody({
            algorithm: 'sha256'
        });

        await writeToStream(s, message, 1000000);
        expect(s.bodyHash).to.equal('D2H5TEwtUgM2u8Ew0gG6vnt/Na6L+Zep7apmSmfy8IQ=');
    });
});
