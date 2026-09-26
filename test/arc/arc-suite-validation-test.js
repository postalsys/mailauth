/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;
const fs = require('node:fs');

let { authenticate } = require('../../lib/mailauth');

const tests = JSON.parse(fs.readFileSync(__dirname + '/../fixtures/arc/arc-draft-validation-tests.json', 'utf8'));

// Cases the lenient mode does not follow: the ARC-Seal tag-list syntax errors are accepted by
// default (with an `arc-tag-syntax` warning), the strict mode rejects them as the suite expects
const laxIgnoreTests = [
    // test rejects if ARC-Seal has extra semicolon
    'as_format_tags_sc',
    // test requires ARC-Seal tag names to use lowercase (s= vs S=)
    'as_format_tags_key_case',
    // test does not allow duplicate tags (s=dummy; s=dummy;)
    'as_format_tags_dup',
    // test does not allow invalid tag names in ARC-Seal (_=)
    'as_format_inv_tag_key'
];

const ignoreTests = [
    // ARC-Message-Signature h includes a non-existing field
    'ams_fields_h_empty_added'
];

// Cases where the suite, which was written against the ARC drafts, disagrees with RFC 8617
const expectedOverrides = {
    // The AMS has an empty h= tag. RFC 8617 section 4.1.2 gives the AMS the DKIM-Signature
    // semantics, where h= "MUST NOT be empty" (RFC 6376 section 3.5) and a signature whose h=
    // does not include From MUST be ignored with PERMFAIL (RFC 6376 section 6.1.1). The draft
    // suite expects pass
    ams_fields_h_empty: { lax: 'fail', strict: 'fail' },
    // The AMS has no c= tag and was signed relaxed/relaxed, the default of the ARC drafts. The
    // RFC default is the DKIM-Signature one, simple/simple (RFC 6376 section 3.5), so the strict
    // mode fails it. The lenient mode falls back to relaxed/relaxed with an `ams-c-default`
    // warning
    ams_fields_c_na: { lax: 'pass', strict: 'fail' }
};

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

for (let mode of [
    { name: 'lax', strict: false },
    { name: 'strict', strict: true }
]) {
    describe(`ARC Validation Suite (${mode.name})`, () => {
        for (let file of tests) {
            let resolver = getResolver(file['txt-records']);
            describe(`${file.description}`, () => {
                for (let test of Object.keys(file.tests)) {
                    if (ignoreTests.includes(test) || (!mode.strict && laxIgnoreTests.includes(test))) {
                        // skip this test
                        continue;
                    }
                    let testdata = file.tests[test];
                    it(test, async () => {
                        let result = await authenticate(Buffer.from(testdata.message || ''), {
                            resolver,
                            disableDmarc: true,
                            strict: mode.strict
                        });

                        expect(result?.arc).to.exist;
                        let expected = testdata?.cv?.toLowerCase();
                        if (expected === '') {
                            // special case with broken chain
                            expected = 'fail';
                        }

                        if (expectedOverrides[test]) {
                            expected = expectedOverrides[test][mode.name];
                        }

                        expect(result?.arc?.status?.result).to.equal(expected);
                    });
                }
            });
        }
    });
}
