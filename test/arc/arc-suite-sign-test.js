/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;
const fs = require('node:fs');

let { authenticate } = require('../../lib/mailauth');

const tests = JSON.parse(fs.readFileSync(__dirname + '/../fixtures/arc/arc-draft-sign-tests.json', 'utf8'));

const ignoreTests = [];

let replyErr = code => {
    // default response
    let err = new Error('Error');
    switch (code) {
        case 'NONE':
            err.code = 'ENOTFOUND';
            break;
        case 'TIMEOUT':
            err.code = 'ETIMEOUT';
            break;
        default:
            err.code = code;
    }
    throw err;
};

let getResolver = txtRecords => {
    let resolver = async (domain, type) => {
        domain = domain.toLowerCase().trim();

        if (txtRecords?.[domain] && type === 'TXT') {
            return [[txtRecords[domain]]];
        }

        //Default
        return replyErr('NONE');
    };

    return resolver;
};

describe(`ARC Signing Suite`, () => {
    for (let file of tests) {
        let resolver = getResolver(file['txt-records']);
        describe(`${file.description}`, () => {
            for (let test of Object.keys(file.tests)) {
                if (ignoreTests.includes(test)) {
                    // skip this test
                    continue;
                }
                let testdata = file.tests[test];
                it(test, async () => {
                    // 1st step - Seal the message
                    let { headers } = await authenticate(Buffer.from(testdata.message || ''), {
                        ip: '127.0.0.1', // SMTP client IP
                        helo: 'example.com', // EHLO/HELO hostname
                        mta: testdata['srv-id'], // server processing this message, defaults to os.hostname()
                        sender: 'jqd@d1.example', // MAIL FROM address

                        seal: {
                            signingDomain: file.domain,
                            selector: file.sel,
                            privateKey: file.privatekey,
                            signTime: new Date(testdata.t * 1000),
                            headerList: testdata['sig-headers']
                        },

                        disableDmarc: true,
                        resolver
                    });

                    expect(headers).to.exist;

                    if (!testdata.AS) {
                        // no added header
                        expect(/^arc-seal/im.test(headers.toString())).to.be.false;
                        return;
                    }

                    expect(/^arc-seal/im.test(headers.toString())).to.be.true;

                    let expectToFail = testdata.AS.match(/\bcv=(\w+)\b/)?.[1] === 'fail';

                    // step 2. validate signatures

                    let { arc } = await authenticate(Buffer.from(headers.toString() + testdata.message || ''), {
                        ip: '127.0.0.1', // SMTP client IP
                        helo: 'example.com', // EHLO/HELO hostname
                        mta: testdata['srv-id'], // server processing this message, defaults to os.hostname()
                        sender: 'jqd@d1.example', // MAIL FROM address
                        disableDmarc: true,
                        resolver
                    });

                    expect(arc).to.exist;
                    expect(arc.status.result).to.equal(expectToFail ? 'fail' : 'pass');
                });
            }
        });
    }
});
