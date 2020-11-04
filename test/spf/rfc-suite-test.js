/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const yaml = require('js-yaml');
const fs = require('fs');

let { spf } = require('../../lib/spf');

const suiteFile = fs.readFileSync(__dirname + '/../fixtures/spf/rfc7208-tests.yml', 'utf8');
const files = suiteFile
    .split(/^-{2,}$/m)
    .filter(f => f.match(/^[^#\s]/m))
    .map(f => yaml.safeLoad(f));

const ignoreTests = [
    // SPF record specific issue
    /^non-ascii-non-spf$/,

    // PTR not supported
    /^ptr-/,
    /^bytes-bug$/,

    // this implementation is more relaxed
    /^two-spaces$/,
    /^trailing-space$/,

    // should fail but does not as failing ip6 is not tested
    /^bare-ip6$/,

    // failing ip6 address is not tested for ip4 check
    /^cidr6-129$/,

    // exp is not supported
    /^exp-/,

    // validated domain macros are not perfect
    /^p-/,

    // macro domain implementation not compatible
    /^invalid-hello-macro$/,
    /^hello-domain-literal$/,
    /^require-valid-helo$/,

    // implementation has higher limits
    /-limit$/
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

let getResolver = zonedata => {
    let resolver = async (domain, type) => {
        domain = domain.toLowerCase().trim();

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

                    let formatStr = str => {
                        return str.replace(/\\0/g, '\x00').replace(/\\x([0-9A-F]{2})/g, (m, c) => unescape(`%${c}`));
                    };

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

describe(`SPF Suite`, () => {
    for (let file of files) {
        let resolver = getResolver(file.zonedata);
        describe(`${file.description}`, () => {
            for (let test of Object.keys(file.tests)) {
                if (ignoreTests.some(re => re.test(test))) {
                    continue;
                }
                let testdata = file.tests[test];
                it(test, async () => {
                    let result = await spf({
                        ip: testdata.host,
                        sender: testdata.mailfrom,
                        helo: testdata.helo,
                        resolver
                    });

                    if (Array.isArray(testdata.result)) {
                        expect(testdata.result).to.include(result?.status?.result);
                    } else {
                        expect(testdata.result).to.equal(result?.status?.result);
                    }
                });
            }
        });
    }
});
