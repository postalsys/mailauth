/* eslint no-unused-expressions:0 */
'use strict';

const { resolveStream } = require('../../../lib/tools');
const chai = require('chai');
const expect = chai.expect;

let fs = require('fs').promises;
let { SimpleBody } = require('../../../lib/dkim/body/simple');

chai.config.includeStack = true;

describe('DKIM SimpleBody Tests', () => {
    it('Should calculate sha256 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new SimpleBody({
            hashAlgo: 'sha256'
        });

        let hash;
        // 'hash' is triggered before stream end
        s.on('hash', h => {
            hash = h;
        });

        await resolveStream(s, message, 1);
        expect(hash).to.equal('frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=');
    });

    it('Should calculate sha1 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new SimpleBody({
            hashAlgo: 'sha1'
        });

        let hash;
        // 'hash' is triggered before stream end
        s.on('hash', h => {
            hash = h;
        });

        await resolveStream(s, message, 1);
        expect(hash).to.equal('uoq1oCgLlTqpdDX/iUbLy7J1Wic=');
    });

    it('Should calculate body hash byte by byte', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');

        let s = new SimpleBody({
            hashAlgo: 'sha256'
        });

        let hash;
        // 'hash' is triggered before stream end
        s.on('hash', h => {
            hash = h;
        });

        s.on('headers', d => console.log(d));

        await resolveStream(s, message, 1);
        expect(hash).to.equal('ESwKBtV2kJ5cP058Rw3B6BZLVaL2SNau6GDddaItvi4=');
    });

    it('Should calculate body hash all at once', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');

        message = Buffer.from(message.toString().replace(/\r?\n/g, '\r\n'));

        let s = new SimpleBody({
            hashAlgo: 'sha256'
        });

        let hash;
        // 'hash' is triggered before stream end
        s.on('hash', h => {
            hash = h;
        });

        await resolveStream(s, message, 1000000);
        expect(hash).to.equal('ESwKBtV2kJ5cP058Rw3B6BZLVaL2SNau6GDddaItvi4=');
    });
});
