/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

let { bimi } = require('../lib/bimi');

chai.config.includeStack = true;

// NB! these tests perform live DNS and HTTPS queries

const dnsReject = () => {
    let err = new Error('Error');
    err.code = 'ENOTFOUND';
    throw err;
};

describe('BIMI Tests', () => {
    it('Should resolve BIMI location', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject'
            },
            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'default._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            }
        });

        expect(res?.status?.result).to.equal('pass');
        expect(res?.status?.header).to.deep.equal({ selector: 'default', d: 'gmail.com' });
        expect(res?.location).to.equal('https://cldup.com/a6t0ORNG2z.svg');
    });

    it('Should resolve author BIMI location', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'sub.gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject'
            },
            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'default._bimi.sub.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2y.svg']];
                    case 'default._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            }
        });

        expect(res?.status?.result).to.equal('pass');
        expect(res?.status?.header).to.deep.equal({ selector: 'default', d: 'sub.gmail.com' });
        expect(res?.location).to.equal('https://cldup.com/a6t0ORNG2y.svg');
    });

    it('Should resolve organization BIMI location', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'sub.gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject'
            },
            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'default._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            }
        });

        expect(res?.status?.result).to.equal('pass');
        expect(res?.status?.header).to.deep.equal({ selector: 'default', d: 'gmail.com' });
        expect(res?.location).to.equal('https://cldup.com/a6t0ORNG2z.svg');
    });

    it('Should resolve BIMI location with specific selector', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject'
            },

            headers: {
                parsed: [
                    {
                        key: 'bimi-selector',
                        line: 'v=BIMI1; s=test'
                    }
                ]
            },

            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'test._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            }
        });

        expect(res?.status?.result).to.equal('pass');
        expect(res?.status?.header).to.deep.equal({ selector: 'test', d: 'gmail.com' });
        expect(res?.location).to.equal('https://cldup.com/a6t0ORNG2z.svg');
    });
});
