/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;
const crypto = require('node:crypto');

let fs = require('node:fs').promises;
let { SimpleHash } = require('../../../lib/dkim/body/simple');

chai.config.includeStack = true;

const getBody = message => {
    message = message.toString('binary');
    let match = message.match(/\r?\n\r?\n/);
    if (match) {
        message = message.substr(match.index + match[0].length);
    }
    return Buffer.from(message.replace(/\r?\n/g, '\r\n'), 'binary');
};

describe('DKIM SimpleBody Tests', () => {
    it('Should calculate sha256 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new SimpleHash('rsa-sha256');
        s.update(message);

        expect(s.digest('base64')).to.equal('frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=');
    });

    it('Should calculate sha1 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new SimpleHash('rsa-sha1');
        s.update(message);

        expect(s.digest('base64')).to.equal('uoq1oCgLlTqpdDX/iUbLy7J1Wic=');
    });

    it('Should calculate body hash byte by byte', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new SimpleHash('rsa-sha256');
        for (let i = 0; i < message.length; i++) {
            s.update(Buffer.from([message[i]]));
        }

        expect(s.digest('base64')).to.equal('GjyEkbey2OupCW5AKJv4dzTPsPHSaZjRDMqUSmhpTyQ=');
    });

    it('Should calculate body hash all at once', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new SimpleHash('rsa-sha256');
        s.update(message);

        expect(s.digest('base64')).to.equal('GjyEkbey2OupCW5AKJv4dzTPsPHSaZjRDMqUSmhpTyQ=');
    });

    it('Should calculate body hash with l=0', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new SimpleHash('rsa-sha256', 0);
        s.update(message);

        expect(s.digest('base64')).to.equal('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });

    it('Should calculate body hash with l=20', async () => {
        let s = new SimpleHash('rsa-sha256', 20);
        s.update(Buffer.from('tere tere\r\n \r\nvana kere\r\n\r\n'));

        expect(s.digest('base64')).to.equal(
            crypto
                .createHash('sha256')
                .update(Buffer.from(['tere tere\r\n', ' \r\n', 'vana k'].join('')))
                .digest('base64')
        );
    });
});
