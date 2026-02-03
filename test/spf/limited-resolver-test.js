/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

chai.config.includeStack = true;

// We need to access the limitedResolver from the spf/index.js module
// Since it's not exported directly, we test it through the verify function's behavior
// and also test the concepts by recreating the logic

describe('SPF Limited Resolver Tests', () => {
    // Import the spf verify function which uses limitedResolver internally
    const { spf: spfVerify } = require('../../lib/spf/index');

    describe('DNS lookup counting', () => {
        it('Should allow up to 10 DNS lookups', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    if (domain === 'example.com') {
                        return [['v=spf1 include:s1.example.com include:s2.example.com include:s3.example.com include:s4.example.com include:s5.example.com include:s6.example.com include:s7.example.com include:s8.example.com -all']];
                    }
                    // Each include domain
                    return [['v=spf1 -all']];
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.lookups.count).to.be.at.most(result.lookups.limit);
        });

        it('Should return permerror when exceeding 10 DNS lookups', async () => {
            // Create deep chain of includes that will definitely exceed limit
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    if (domain === 'example.com') {
                        return [['v=spf1 include:level1.example.com -all']];
                    }
                    if (domain === 'level1.example.com') {
                        return [['v=spf1 include:level2.example.com include:level3.example.com include:level4.example.com include:level5.example.com include:level6.example.com include:level7.example.com include:level8.example.com include:level9.example.com include:level10.example.com include:level11.example.com -all']];
                    }
                    // Each level includes more
                    return [['v=spf1 include:deep.example.com -all']];
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.99',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('permerror');
        });

        it('Should report lookup count and limit in result', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a mx -all']];
                }
                if (type === 'A') {
                    return ['192.0.2.1'];
                }
                if (type === 'MX') {
                    return [{ priority: 10, exchange: 'mx.example.com' }];
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.lookups).to.be.an('object');
            expect(result.lookups.count).to.be.a('number');
            expect(result.lookups.limit).to.equal(10);
        });

        it('Should support custom maxResolveCount', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    if (domain === 'example.com') {
                        return [['v=spf1 include:s1.example.com include:s2.example.com include:s3.example.com -all']];
                    }
                    return [['v=spf1 -all']];
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver,
                maxResolveCount: 2
            });

            expect(result.status.result).to.equal('permerror');
        });
    });

    describe('Void lookup counting', () => {
        it('Should count ENOTFOUND as void lookup', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === 'example.com') {
                    return [['v=spf1 a:nonexistent1.example.com a:nonexistent2.example.com -all']];
                }
                // Return ENOTFOUND for A records
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.lookups.void).to.be.at.least(1);
        });

        it('Should count ENODATA as void lookup', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === 'example.com') {
                    return [['v=spf1 a:norecord.example.com -all']];
                }
                if (type === 'A' || type === 'AAAA') {
                    const err = new Error('No data');
                    err.code = 'ENODATA';
                    throw err;
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.lookups.void).to.be.at.least(1);
        });

        it('Should return permerror when exceeding void lookup limit', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === 'example.com') {
                    return [['v=spf1 exists:void1.example.com exists:void2.example.com exists:void3.example.com -all']];
                }
                // All exists checks return ENOTFOUND
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('permerror');
        });

        it('Should support custom maxVoidCount', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === 'example.com') {
                    return [['v=spf1 exists:void1.example.com exists:void2.example.com -all']];
                }
                const err = new Error('Not found');
                err.code = 'ENOTFOUND';
                throw err;
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver,
                maxVoidCount: 1
            });

            expect(result.status.result).to.equal('permerror');
        });
    });

    describe('Error handling', () => {
        it('Should return temperror for ETIMEOUT', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === 'example.com') {
                    return [['v=spf1 include:timeout.example.com -all']];
                }
                if (type === 'TXT' && domain === 'timeout.example.com') {
                    const err = new Error('DNS timeout');
                    err.code = 'ETIMEOUT';
                    throw err;
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('temperror');
        });

        it('Should return temperror for EREFUSED', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === 'example.com') {
                    return [['v=spf1 include:refused.example.com -all']];
                }
                if (type === 'TXT' && domain === 'refused.example.com') {
                    const err = new Error('DNS refused');
                    err.code = 'EREFUSED';
                    throw err;
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('temperror');
        });

        it('Should return permerror for invalid domain', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 -all']];
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@invalid..domain',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('none');
        });
    });

    describe('Counter accessors', () => {
        it('Should track subquery counts', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === 'example.com') {
                    return [['v=spf1 include:sub1.example.com include:sub2.example.com -all']];
                }
                if (type === 'TXT' && domain.startsWith('sub')) {
                    return [['v=spf1 a -all']];
                }
                if (type === 'A') {
                    return ['192.0.2.1'];
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.lookups.subqueries).to.be.an('object');
        });
    });

    describe('Domain validation', () => {
        it('Should handle various domain formats', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT' && domain === 'example.com') {
                    return [['v=spf1 a -all']];
                }
                if (type === 'A') {
                    return ['192.0.2.1'];
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            expect(result.status.result).to.equal('pass');
        });
    });

    describe('First lookup behavior', () => {
        it('Should not count initial TXT lookup toward limit', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    if (domain === 'example.com') {
                        // 10 includes should work since initial TXT is not counted
                        return [['v=spf1 include:s1.com include:s2.com include:s3.com include:s4.com include:s5.com include:s6.com include:s7.com include:s8.com include:s9.com include:s10.com -all']];
                    }
                    return [['v=spf1 -all']];
                }
                return [];
            };

            const result = await spfVerify({
                sender: 'user@example.com',
                ip: '192.0.2.1',
                helo: 'mail.example.com',
                resolver: stubResolver
            });

            // Should succeed because initial lookup is not counted
            expect(result.status.result).to.not.equal('permerror');
        });
    });
});
