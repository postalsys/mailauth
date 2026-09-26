/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const yaml = require('js-yaml');
const fs = require('node:fs');

let { spf } = require('../../lib/spf');

const suiteFile = fs.readFileSync(__dirname + '/../fixtures/spf/rfc7208-tests.yml', 'utf8');
const files = suiteFile
    .split(/^-{2,}$/m)
    .filter(f => f.match(/^[^#\s]/m))
    .map(f => yaml.load(f));

// The default (lax) mode evaluates records lazily and keeps a few lenient rules, so these
// cases give a different, documented result there. Strict mode must pass every case.
const laxResults = {
    // syntax errors after the matching term are not detected
    'bare-ip6': 'fail',
    'exp-syntax-error': 'neutral',
    'exp-twice': 'fail',
    // c, r and t are accepted outside of explanation text
    'exp-only-macro-char': 'fail',
    // an invalid name after macro expansion is a permerror (RFC 7208 section 4.8 allows both)
    'invalid-hello-macro': 'permerror',
    'hello-domain-literal': 'permerror',
    'require-valid-helo': 'permerror'
};

// the case of the hex digits in %{i} is not specified, the suite expects them in upper case
const caseInsensitiveExplanation = ['v-macro-ip6'];

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

let getResolver = zonedata => {
    let resolver = async (domain, type) => {
        domain = domain.toLowerCase().trim();

        // make sure we can run case insensitive queries
        for (let key of Object.keys(zonedata)) {
            if (key.toLowerCase() !== key && !zonedata[key.toLowerCase()]) {
                zonedata[key.toLowerCase()] = zonedata[key];
            }
        }

        if (zonedata[domain]) {
            let list = zonedata[domain].filter(e => e && e[type]);

            if (type === 'TXT' && (!list || !list.length)) {
                return resolver(domain, 'SPF');
            }

            if (list && list.length) {
                let result = [];
                for (let match of list) {
                    let val = match[type];

                    if (['TIMEOUT', 'NONE'].includes(val)) {
                        if (val === 'NONE' && zonedata[domain][zonedata[domain].length - 1] === 'TIMEOUT') {
                            return replyErr('TIMEOUT');
                        }
                        return replyErr(val);
                    }

                    let formatStr = str => str.replace(/\\0/g, '\x00').replace(/\\x([0-9A-F]{2})/g, (m, c) => unescape(`%${c}`));

                    switch (type) {
                        case 'TXT':
                        case 'SPF':
                            result.push([formatStr([].concat(val).join(''))]);
                            break;
                        case 'MX':
                            result.push({ priority: val[0], exchange: formatStr(val[1]) });
                            break;

                        default:
                            result.push(formatStr(val));
                    }
                }

                return result;
            } else {
                // error?
                let match = zonedata[domain].find(e => e && typeof e === 'string');
                if (match) {
                    return replyErr(match);
                }
            }
        }

        //Default
        return replyErr('NONE');
    };

    return resolver;
};

const checkExplanation = (test, testdata, result) => {
    if (!testdata.explanation) {
        return;
    }
    if (testdata.explanation === 'DEFAULT') {
        // no explanation string, the default comment is used
        expect(result.explanation).to.not.exist;
    } else if (caseInsensitiveExplanation.includes(test)) {
        expect((result.explanation || '').toLowerCase()).to.equal(testdata.explanation.toLowerCase());
    } else {
        expect(result.explanation).to.equal(testdata.explanation);
    }
};

for (let strict of [true, false]) {
    describe(`SPF Suite (${strict ? 'strict' : 'default'} mode)`, () => {
        for (let file of files) {
            let resolver = getResolver(file.zonedata);
            describe(`${file.description}`, () => {
                for (let test of Object.keys(file.tests)) {
                    let testdata = file.tests[test];
                    let expected = [].concat(testdata.result);
                    if (!strict && laxResults[test]) {
                        expected = [laxResults[test]];
                    }
                    it(test, async () => {
                        let result = await spf({
                            ip: testdata.host,
                            sender: testdata.mailfrom,
                            helo: testdata.helo,
                            mta: 'receiver.test',
                            resolver,
                            strict
                        });

                        expect(expected).to.include(result?.status?.result);
                        if ([].concat(testdata.result).includes(result.status.result)) {
                            checkExplanation(test, testdata, result);
                        }
                    });
                }
            });
        }
    });
}
