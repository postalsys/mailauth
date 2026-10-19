/* eslint @typescript-eslint/no-unused-expressions:0 */
import { describe, it } from 'node:test';
import { Buffer } from 'node:buffer';
import { expect } from 'chai';
import fs from 'node:fs';

import { authenticate } from '../../src/mailauth.js';
import type { ARCResult } from '../../src/types.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const tests = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'arc', 'arc-draft-validation-tests.json'), 'utf8'));

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

const ignoreTests: any = [];

// Cases where the suite, which was written against the ARC drafts, disagrees with RFC 8617
const expectedOverrides: Record<string, any> = {
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

let replyErr = (code: any) => {
    // default response
    let err: any = new Error('Error');
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

let getResolver = (txtRecords: any) => {
    let resolver = async (domain: any, type: any) => {
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

                        expect((result?.arc as ARCResult | undefined)?.status?.result).to.equal(expected);
                    });
                }
            });
        }
    });
}
