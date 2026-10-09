/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { dkimSign, dkimVerify } = require('../../lib/mailauth');
const { zoneResolver } = require('../helpers/dns-zone');
const { dkimTxtRecord, privateKey } = require('../helpers/keys');

chai.config.includeStack = true;

// mimeStructureStart is the offset in the canonicalized body where the first MIME boundary line
// starts, so that the part of a multipart body before the MIME structure can be told apart

describe('DKIM mimeStructureStart', () => {
    const resolver = zoneResolver({ 'test._domainkey.example.com': { TXT: [[dkimTxtRecord('public-rsa.pem')]] } });

    const verify = async (contentType, body, canonicalization) => {
        const message = `From: user@example.com\r\nSubject: test\r\n${contentType ? `Content-Type: ${contentType}\r\n` : ''}\r\n${body}`;
        const { signatures } = await dkimSign(Buffer.from(message), {
            canonicalization,
            signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: privateKey('private-rsa.pem') }]
        });
        const result = await dkimVerify(Buffer.from(signatures + message), { resolver });
        expect(result.results[0].status.result).to.equal('pass');
        return result.results[0].mimeStructureStart;
    };

    const multipartBody = 'preamble  text\r\n--xyz\r\nContent-Type: text/plain\r\n\r\nhello\r\n--xyz--\r\n';

    it('Should find the first boundary line of a multipart body', async () => {
        // "preamble  text\r\n" is 16 bytes with simple and 15 with relaxed, which collapses the spaces
        expect(await verify('multipart/mixed; boundary="xyz"', multipartBody, 'relaxed/simple')).to.equal(16);
        expect(await verify('multipart/mixed; boundary="xyz"', multipartBody, 'relaxed/relaxed')).to.equal(15);
    });

    it('Should find a boundary on the first line and at the end of the body', async () => {
        expect(await verify('multipart/mixed; boundary=xyz', '--xyz\r\n\r\nhello\r\n--xyz--\r\n', 'relaxed/relaxed')).to.equal(0);
        expect(await verify('multipart/mixed; boundary=xyz', 'text\r\n--xyz', 'simple/simple')).to.equal(6);
    });

    it('Should not match a line that only starts with the boundary', async () => {
        expect(await verify('multipart/mixed; boundary=xyz', 'a\r\n--xyzz\r\n--xy\r\n--xyz\r\nb\r\n', 'simple/simple')).to.equal(17);
        expect(await verify('multipart/mixed; boundary=xyz', 'a\r\n--xyzz\r\n', 'simple/simple')).to.equal(-1);
    });

    it('Should report 0 for a body that is not multipart', async () => {
        expect(await verify('text/plain', multipartBody, 'relaxed/relaxed')).to.equal(0);
        expect(await verify(false, multipartBody, 'simple/simple')).to.equal(0);
    });
});
