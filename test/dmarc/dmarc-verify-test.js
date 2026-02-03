/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const verifyDmarc = require('../../lib/dmarc/verify');

chai.config.includeStack = true;

describe('DMARC Verify Tests', () => {
    describe('Basic DMARC lookup', () => {
        it('Should return pass when DKIM aligns', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
            expect(result.policy).to.equal('reject');
        });

        it('Should return pass when SPF aligns', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=quarantine']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [],
                spfDomains: [{ domain: 'example.com' }],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
            expect(result.policy).to.equal('quarantine');
        });

        it('Should return fail when neither DKIM nor SPF aligns', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'otherdomain.com' }],
                spfDomains: [{ domain: 'anotherdomain.com' }],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('fail');
        });

        it('Should return none when no DMARC record exists', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    const err = new Error('Not found');
                    err.code = 'ENOTFOUND';
                    throw err;
                }
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('none');
        });

        it('Should return temperror on DNS failure', async () => {
            const stubResolver = () => {
                const err = new Error('DNS timeout');
                err.code = 'ETIMEOUT';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('temperror');
            expect(result.error).to.equal('DNS timeout');
        });
    });

    describe('DMARC record parsing', () => {
        it('Should parse all common tags', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.p).to.equal('quarantine');
            expect(result.sp).to.equal('reject');
            expect(result.pct).to.equal(50);
        });

        it('Should handle minimal DMARC record', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=none']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('fail');
            expect(result.p).to.equal('none');
        });

        it('Should handle split TXT records', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=rej', 'ect; pct=100']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.p).to.equal('reject');
            expect(result.pct).to.equal(100);
        });
    });

    describe('Policy evaluation', () => {
        it('Should use p= policy for direct domain', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; sp=quarantine']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.policy).to.equal('reject');
        });

        it('Should use sp= policy for subdomain with org domain record', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.sub.example.com') {
                    const err = new Error('Not found');
                    err.code = 'ENOTFOUND';
                    throw err;
                }
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; sp=quarantine']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@sub.example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.policy).to.equal('quarantine');
        });

        it('Should use p= policy for subdomain when sp= not set', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.sub.example.com') {
                    const err = new Error('Not found');
                    err.code = 'ENOTFOUND';
                    throw err;
                }
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@sub.example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.policy).to.equal('reject');
        });
    });

    describe('Alignment modes', () => {
        it('Should use relaxed DKIM alignment by default', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
            expect(result.alignment.dkim.strict).to.be.false;
        });

        it('Should use strict DKIM alignment when adkim=s', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; adkim=s']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
            expect(result.alignment.dkim.strict).to.be.true;
        });

        it('Should fail strict DKIM alignment for different org domain', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; adkim=s']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            // With strict alignment, signing domain must have same org domain as header from
            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'otherdomain.net' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('fail');
        });

        it('Should use relaxed SPF alignment by default', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                spfDomains: [{ domain: 'example.com' }],
                dkimDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
            expect(result.alignment.spf.strict).to.be.false;
        });

        it('Should use strict SPF alignment when aspf=s', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; aspf=s']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                spfDomains: [{ domain: 'example.com' }],
                dkimDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
            expect(result.alignment.spf.strict).to.be.true;
        });
    });

    describe('Organizational domain fallback', () => {
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

            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
            expect(result.domain).to.equal('example.com');
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

            const result = await verifyDmarc({
                headerFrom: 'user@mail.example.com',
                dkimDomains: [],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.policy).to.equal('reject');
        });
    });

    describe('Edge cases', () => {
        it('Should handle headerFrom without @ symbol', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
        });

        it('Should handle headerFrom array with single element', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: ['user@example.com'],
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
        });

        it('Should return false for headerFrom array with multiple elements', async () => {
            const stubResolver = () => {
                return [['v=DMARC1; p=reject']];
            };

            const result = await verifyDmarc({
                headerFrom: ['user1@example.com', 'user2@example.com'],
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result).to.be.false;
        });

        it('Should handle IDN domains', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.xn--e1afmkfd.xn--p1ai') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@xn--e1afmkfd.xn--p1ai',
                dkimDomains: [{ domain: 'xn--e1afmkfd.xn--p1ai' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
        });

        it('Should handle domains with string DKIM/SPF entries', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: ['example.com'],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
        });

        it('Should include ARC result in comment when provided', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                arcResult: { status: { result: 'pass' } },
                resolver: stubResolver
            });

            expect(result.status.comment).to.include('arc=pass');
        });

        it('Should track undersized DKIM signatures', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com', underSized: 100 }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.alignment.dkim.underSized).to.equal(100);
        });

        it('Should return raw record in rr field', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject; pct=100']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.rr).to.equal('v=DMARC1; p=reject; pct=100');
        });

        it('Should generate formatted info string', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === '_dmarc.example.com') {
                    return [['v=DMARC1; p=reject']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await verifyDmarc({
                headerFrom: 'user@example.com',
                dkimDomains: [{ domain: 'example.com' }],
                spfDomains: [],
                resolver: stubResolver
            });

            expect(result.info).to.be.a('string');
            expect(result.info).to.include('dmarc=pass');
        });
    });
});
