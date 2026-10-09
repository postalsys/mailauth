/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const getDmarcRecord = require('../../lib/dmarc/get-dmarc-record');
const { domainExists } = getDmarcRecord;
const { dmarc } = require('../../lib/dmarc');
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

            // not a tag, the syntax error is discarded (RFC 9989 4.8)
            expect(result).to.not.have.property('tagonly');
            expect(result.p).to.equal('reject');
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

            expect(result).to.not.have.property('false');
            expect(result.p).to.equal('reject');
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

        it('Should only accept whitespace before the version tag in the default mode', async () => {
            // RFC 9989 4.10: records that do not start with a "v" tag are discarded
            for (let rr of [' v=DMARC1; p=reject', '\tv=DMARC1; p=reject']) {
                let resolver = zoneResolver({ '_dmarc.bank.example': { TXT: [[rr]] } });

                let result = await dmarc({ headerFrom: 'ceo@bank.example', spfDomains: [], dkimDomains: [], resolver, strict: true });
                expect(result.status.result, JSON.stringify(rr)).to.equal('none');
                expect(result.policy, JSON.stringify(rr)).to.not.exist;
                expect(result.warnings, JSON.stringify(rr)).to.not.exist;

                result = await dmarc({ headerFrom: 'ceo@bank.example', spfDomains: [], dkimDomains: [], resolver });
                expect(result.status.result, JSON.stringify(rr)).to.equal('fail');
                expect(result.policy, JSON.stringify(rr)).to.equal('reject');
                expect(result.warnings, JSON.stringify(rr)).to.deep.equal(['record-whitespace']);
            }

            let resolver0 = zoneResolver({ '_dmarc.bank.example': { TXT: [[' v=DMARC1; p=reject']] } });
            expect((await getDmarcRecord('bank.example', resolver0)).p).to.equal('reject');
            expect(await getDmarcRecord('bank.example', resolver0, { strict: true })).to.be.false;

            // trailing whitespace is part of the last tag value, which is trimmed, so it needs no warning
            let resolver = zoneResolver({ '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject ']] } });
            for (let strict of [false, true]) {
                let result = await dmarc({ headerFrom: 'ceo@bank.example', spfDomains: [], dkimDomains: [], resolver, strict });
                expect(result.policy).to.equal('reject');
                expect(result.rr).to.equal('v=DMARC1; p=reject');
                expect(result.warnings).to.not.exist;
            }
        });

        it('Should discard a fragment without "=" instead of letting it override a tag', async () => {
            // RFC 9989 4.8: syntax errors in the record are discarded or ignored
            for (let strict of [false, true]) {
                let resolver = zoneResolver({ '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject; p']] } });
                let result = await dmarc({ headerFrom: 'ceo@bank.example', spfDomains: [], dkimDomains: [], resolver, strict });
                expect(result.status.result, String(strict)).to.equal('fail');
                expect(result.policy, String(strict)).to.equal('reject');

                resolver = zoneResolver({ '_dmarc.bank.example': { TXT: [['v=DMARC1; p=reject; adkim=s; adkim']] } });
                result = await dmarc({ headerFrom: 'ceo@bank.example', spfDomains: [], dkimDomains: [{ domain: 'mail.bank.example' }], resolver, strict });
                expect(result.status.result, String(strict)).to.equal('fail');
                expect(result.policy, String(strict)).to.equal('reject');
                expect(result.alignment.dkim.strict, String(strict)).to.be.true;
            }

            for (let record of ['v=DMARC1; p=reject; =none', 'v=DMARC1; p=reject; = none; p ; adkim']) {
                let parsed = getDmarcRecord.parseDmarcRecord(record);
                expect(parsed, record).to.deep.equal({ v: 'DMARC1', p: 'reject', rr: record });
            }
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

        it('Should not query "_dmarc.null" or walk an address', async () => {
            // a single label has no parent to walk to, and an IP address or a domain literal
            // is not a DNS name that could publish a record
            const resolver = zoneResolver({});

            for (let domain of ['localhost', '192.0.2.1', '[192.0.2.1]', '2001:db8::1']) {
                const result = await getDmarcRecord(domain, resolver);
                expect(result).to.be.false;
            }

            expect(resolver.calls.map(call => call.name)).to.deep.equal(['_dmarc.localhost']);
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

    describe('Domain existence test', () => {
        const queries = resolver => resolver.calls.map(call => `${call.name} ${call.type}`);

        it('Should treat a name with a dangling CNAME as existing', async () => {
            // the A query follows the CNAME and gets the NXDOMAIN of the missing target
            const resolver = zoneResolver({ 'shop.example.com': { CNAME: ['gone.example.net'] } });
            expect(await domainExists('shop.example.com', resolver)).to.be.true;
            expect(queries(resolver)).to.deep.equal(['shop.example.com A', 'shop.example.com CNAME']);
        });

        it('Should query the CNAME after an NXDOMAIN and keep it when there is none', async () => {
            const resolver = zoneResolver({});
            expect(await domainExists('missing.example.com', resolver)).to.be.false;
            expect(queries(resolver)).to.deep.equal(['missing.example.com A', 'missing.example.com CNAME']);
        });

        it('Should keep the NXDOMAIN when a resolver has no answer for CNAME', async () => {
            // a custom resolver that only knows some record types
            const zone = zoneResolver({});
            const resolver = async (name, type) => (type === 'CNAME' ? undefined : zone(name, type));
            expect(await domainExists('missing.example.com', resolver)).to.be.false;
        });

        it('Should pass a failed CNAME query on to the caller', async () => {
            const zone = zoneResolver({});
            const resolver = async (name, type) => {
                if (type === 'CNAME') {
                    const err = new Error('SERVFAIL');
                    err.code = 'ESERVFAIL';
                    throw err;
                }
                return zone(name, type);
            };
            try {
                await domainExists('missing.example.com', resolver);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('ESERVFAIL');
            }
        });
    });
});
