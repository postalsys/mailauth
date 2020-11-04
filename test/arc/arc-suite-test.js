/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;
const fs = require('fs');

let { authenticate } = require('../../lib/mailauth');

const tests = JSON.parse(fs.readFileSync(__dirname + '/../fixtures/arc/arc-draft-validation-tests.json', 'utf8'));

const ignoreTests = [
    // test rejects if ARC-Seal has extra semicolon
    'as_format_tags_sc',
    // test requires ARC-Seal tag names to use lowercase (s= vs S=)
    'as_format_tags_key_case',
    // test does not allow duplicate tags (s=dummy; s=dummy;)
    'as_format_tags_dup',
    // test does not allow unknown tags in ARC-Seal
    'as_format_inv_tag_key',
    // ARC-Message-Signature h includes a non-existing field
    'ams_fields_h_empty_added'
];

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

describe(`ARC Validation Suite`, () => {
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
                    let result = await authenticate(Buffer.from(testdata.message || ''), {
                        resolver
                    });

                    expect(result?.arc).to.exist;
                    let expected = testdata?.cv?.toLowerCase();
                    if (expected === '') {
                        // special case with broken chain
                        expected = 'fail';
                    }

                    expect(result?.arc?.status?.result).to.equal(expected);
                });
            }
        });
    }
});
