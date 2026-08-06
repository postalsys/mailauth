/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const getDmarcRecord = require('../../lib/dmarc/get-dmarc-record');
const { zoneResolver } = require('../helpers/dns-zone');

chai.config.includeStack = true;

describe('getDmarcRecord Tests', () => {
    describe('DNS resolution', () => {
        it('Should resolve DMARC record from _dmarc.domain.com', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result).to.be.an('object');
            expect(result.v).to.equal('DMARC1');
            expect(result.p).to.equal('reject');
        });

        it('Should return false when no DMARC record exists', async () => {
            const stubResolver = () => {
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result).to.be.false;
        });

        it('Should return false for empty TXT response', async () => {
            const stubResolver = () => {
                return [];
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result).to.be.false;
        });

        it('Should return false for ENODATA error', async () => {
            const stubResolver = () => {
                const err = new Error('No data');
                err.code = 'ENODATA';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result).to.be.false;
        });

        it('Should throw on DNS server errors', async () => {
            const stubResolver = () => {
                const err = new Error('DNS timeout');
                err.code = 'ETIMEOUT';
                throw err;
            };

            try {
                await getDmarcRecord('example.com', stubResolver);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('ETIMEOUT');
            }
        });
    });

    describe('Record parsing', () => {
        it('Should parse all standard tags', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [
                        [
                            'v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r; fo=1; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; ri=3600'
                        ]
                    ];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.v).to.equal('DMARC1');
            expect(result.p).to.equal('quarantine');
            expect(result.sp).to.equal('reject');
            expect(result.pct).to.equal(50);
            expect(result.adkim).to.equal('s');
            expect(result.aspf).to.equal('r');
            expect(result.fo).to.equal('1');
            expect(result.rua).to.equal('mailto:dmarc@example.com');
            expect(result.ruf).to.equal('mailto:forensic@example.com');
            expect(result.ri).to.equal(3600);
        });

        it('Should handle whitespace around values', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1 ;  p = reject  ; pct = 100 ']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.v).to.equal('DMARC1');
            // *WSP is allowed around "=", so the value is "reject", not " reject"
            expect(result.p).to.equal('reject');
            expect(result.pct).to.equal(100);
        });

        it('Should handle split TXT records', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=re', 'ject; pct=100']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.p).to.equal('reject');
            expect(result.pct).to.equal(100);
        });

        it('Should convert pct to integer', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; pct=75']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.pct).to.equal(75);
            expect(typeof result.pct).to.equal('number');
        });

        it('Should convert ri to integer', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; ri=86400']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.ri).to.equal(86400);
            expect(typeof result.ri).to.equal('number');
        });

        it('Should handle invalid pct value as 0', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; pct=invalid']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.pct).to.equal(0);
        });

        it('Should include raw record in rr field', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.rr).to.equal('v=DMARC1; p=reject');
        });

        it('Should handle tags with no value', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; tagonly']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.tagonly).to.be.false;
        });

        it('Should handle tags starting with equals', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; =value']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.false).to.equal('=value');
        });

        it('Should lowercase tag names', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['V=DMARC1; P=reject; ADKIM=s']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.v).to.equal('DMARC1');
            expect(result.p).to.equal('reject');
            expect(result.adkim).to.equal('s');
        });
    });

    describe('Org domain fallback', () => {
        it('Should fallback to org domain when subdomain has no record', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.mail.example.com') {
                    const err = new Error('Not found');
                    err.code = 'ENOTFOUND';
                    throw err;
                }
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=quarantine']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('mail.example.com', stubResolver);

            expect(result.p).to.equal('quarantine');
            expect(result.isOrgRecord).to.be.true;
        });

        it('Should not fallback when subdomain has its own record', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.mail.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=none']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('mail.example.com', stubResolver);

            expect(result.p).to.equal('reject');
            expect(result.isOrgRecord).to.be.false;
        });

        it('Should set isOrgRecord to false for direct domain', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.isOrgRecord).to.be.false;
        });

        it('Should not query "_dmarc.null" when no org domain can be derived', async () => {
            // tldts returns null for single labels and IPs; the fallback used to coerce
            // that into a lookup for the literal hostname "_dmarc.null"
            const resolver = zoneResolver({});

            for (let domain of ['localhost', '192.0.2.1']) {
                const result = await getDmarcRecord(domain, resolver);
                expect(result).to.be.false;
            }

            expect(resolver.calls.map(call => call.name)).to.deep.equal(['_dmarc.localhost', '_dmarc.192.0.2.1']);
        });

        it('Should not fallback when org domain equals the domain', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    const err = new Error('Not found');
                    err.code = 'ENOTFOUND';
                    throw err;
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result).to.be.false;
        });
    });

    describe('Record validation', () => {
        it('Should return false when no v=DMARC1 record', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=spf1 include:example.com -all']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result).to.be.false;
        });

        it('Should return false when multiple DMARC records exist', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject'], ['v=DMARC1; p=none']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result).to.be.false;
        });

        it('Should accept an upper-case tag name with an exact version value (V=DMARC1)', async () => {
            // the tag name is a quoted ABNF literal (case insensitive), the value is not
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['V=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.v).to.equal('DMARC1');
            expect(result.p).to.equal('reject');
        });

        it('Should reject a version value that is not exactly DMARC1 (v=dmarc1)', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=dmarc1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result).to.be.false;
        });

        it('Should filter non-DMARC records from response', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['some-other-txt-record'], ['v=DMARC1; p=reject'], ['another-record']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await getDmarcRecord('example.com', stubResolver);

            expect(result.p).to.equal('reject');
        });
    });
});
