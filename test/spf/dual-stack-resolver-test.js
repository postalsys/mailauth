/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const { spfVerify } = require('../../lib/spf/spf-verify');

chai.config.includeStack = true;

describe('SPF Dual-Stack Resolver Tests', () => {
    describe('IPv4 client behavior', () => {
        it('Should return only A records for IPv4 client', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a -all']];
                }
                if (type === 'A') {
                    return ['192.0.2.10'];
                }
                if (type === 'AAAA') {
                    return ['2001:db8::10'];
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '192.0.2.10',
                sender: 'user@example.com',
                resolver: stubResolver
            });

            expect(result.qualifier).to.equal('+');
        });

        it('Should not match IPv4 client against AAAA records', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a -all']];
                }
                if (type === 'A') {
                    return ['192.0.2.20'];
                }
                if (type === 'AAAA') {
                    return ['2001:db8::10'];
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '192.0.2.10',
                sender: 'user@example.com',
                resolver: stubResolver
            });

            expect(result.qualifier).to.equal('-');
        });

        it('Should ignore AAAA errors when A has records (IPv4 client)', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a -all']];
                }
                if (type === 'A') {
                    return ['192.0.2.10'];
                }
                if (type === 'AAAA') {
                    const err = new Error('AAAA timeout');
                    err.code = 'ETIMEOUT';
                    throw err;
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '192.0.2.10',
                sender: 'user@example.com',
                resolver: stubResolver
            });

            expect(result.qualifier).to.equal('+');
        });

        it('Should ignore AAAA ENODATA when A has records', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a -all']];
                }
                if (type === 'A') {
                    return ['192.0.2.10'];
                }
                if (type === 'AAAA') {
                    const err = new Error('No AAAA data');
                    err.code = 'ENODATA';
                    throw err;
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '192.0.2.10',
                sender: 'user@example.com',
                resolver: stubResolver
            });

            expect(result.qualifier).to.equal('+');
        });
    });

    describe('IPv6 client behavior', () => {
        it('Should return only AAAA records for IPv6 client', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a -all']];
                }
                if (type === 'A') {
                    return ['192.0.2.10'];
                }
                if (type === 'AAAA') {
                    return ['2001:db8::10'];
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '2001:db8::10',
                sender: 'user@example.com',
                resolver: stubResolver
            });

            expect(result.qualifier).to.equal('+');
        });

        it('Should not match IPv6 client against A records', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a -all']];
                }
                if (type === 'A') {
                    return ['192.0.2.10'];
                }
                if (type === 'AAAA') {
                    return ['2001:db8::20'];
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '2001:db8::10',
                sender: 'user@example.com',
                resolver: stubResolver
            });

            expect(result.qualifier).to.equal('-');
        });

        it('Should ignore A errors when AAAA has records (IPv6 client)', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a -all']];
                }
                if (type === 'A') {
                    const err = new Error('A timeout');
                    err.code = 'ETIMEOUT';
                    throw err;
                }
                if (type === 'AAAA') {
                    return ['2001:db8::10'];
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '2001:db8::10',
                sender: 'user@example.com',
                resolver: stubResolver
            });

            expect(result.qualifier).to.equal('+');
        });

        it('Should ignore A ENODATA when AAAA has records', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a -all']];
                }
                if (type === 'A') {
                    const err = new Error('No A data');
                    err.code = 'ENODATA';
                    throw err;
                }
                if (type === 'AAAA') {
                    return ['2001:db8::10'];
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '2001:db8::10',
                sender: 'user@example.com',
                resolver: stubResolver
            });

            expect(result.qualifier).to.equal('+');
        });
    });

    describe('Void handling - tested via spf-verify-test.js', () => {
        // Note: Dual-stack void handling is tested more thoroughly in spf-verify-test.js
        // The dual-stack resolver is internal to limitedResolver and is exercised via the
        // main SPF verification path.

        it('Should handle single host with both A and AAAA empty', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a:test.example.com -all']];
                }
                // Synchronous resolver - errors thrown directly
                if (type === 'A' || type === 'AAAA') {
                    return [];  // Return empty arrays instead of throwing
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '192.0.2.10',
                sender: 'user@example.com',
                resolver: stubResolver
            });

            expect(result.qualifier).to.equal('-');
        });
    });

    describe('Error propagation', () => {
        it('Should propagate A timeout error for IPv4 client when both error', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a:timeout.example.com -all']];
                }
                if (type === 'A') {
                    const err = new Error('A timeout');
                    err.code = 'ETIMEOUT';
                    throw err;
                }
                if (type === 'AAAA') {
                    const err = new Error('AAAA timeout');
                    err.code = 'ETIMEOUT';
                    throw err;
                }
                return [];
            };

            try {
                await spfVerify('example.com', {
                    ip: '192.0.2.10',
                    sender: 'user@example.com',
                    resolver: stubResolver
                });
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('ETIMEOUT');
            }
        });

        it('Should propagate AAAA timeout error for IPv6 client when both error', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a:timeout.example.com -all']];
                }
                if (type === 'A') {
                    const err = new Error('A timeout');
                    err.code = 'ETIMEOUT';
                    throw err;
                }
                if (type === 'AAAA') {
                    const err = new Error('AAAA timeout');
                    err.code = 'ETIMEOUT';
                    throw err;
                }
                return [];
            };

            try {
                await spfVerify('example.com', {
                    ip: '2001:db8::10',
                    sender: 'user@example.com',
                    resolver: stubResolver
                });
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('ETIMEOUT');
            }
        });

        it('Should propagate A error for IPv4 client even when AAAA is void', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a:error.example.com -all']];
                }
                if (type === 'A') {
                    const err = new Error('A refused');
                    err.code = 'EREFUSED';
                    err.spfResult = { error: 'temperror', text: 'DNS refused' };
                    throw err;
                }
                if (type === 'AAAA') {
                    const err = new Error('Not found');
                    err.code = 'ENOTFOUND';
                    throw err;
                }
                return [];
            };

            try {
                await spfVerify('example.com', {
                    ip: '192.0.2.10',
                    sender: 'user@example.com',
                    resolver: stubResolver
                });
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('EREFUSED');
            }
        });

        it('Should propagate AAAA error for IPv6 client even when A is void', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a:error.example.com -all']];
                }
                if (type === 'A') {
                    const err = new Error('Not found');
                    err.code = 'ENOTFOUND';
                    throw err;
                }
                if (type === 'AAAA') {
                    const err = new Error('AAAA refused');
                    err.code = 'EREFUSED';
                    err.spfResult = { error: 'temperror', text: 'DNS refused' };
                    throw err;
                }
                return [];
            };

            try {
                await spfVerify('example.com', {
                    ip: '2001:db8::10',
                    sender: 'user@example.com',
                    resolver: stubResolver
                });
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('EREFUSED');
            }
        });

        it('Should handle multiple hosts returning empty arrays', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 a:host.example.com -all']];
                }
                if (type === 'A') {
                    return [];  // Empty but not an error
                }
                if (type === 'AAAA') {
                    return [];  // Empty but not an error
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '192.0.2.10',
                sender: 'user@example.com',
                resolver: stubResolver
            });

            expect(result.qualifier).to.equal('-');
        });
    });

    describe('MX mechanism with dual-stack', () => {
        it('Should handle IPv4 client with IPv4-only MX hosts', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 mx -all']];
                }
                if (type === 'MX') {
                    return [{ priority: 10, exchange: 'mx.example.com' }];
                }
                if (type === 'A') {
                    return ['192.0.2.10'];
                }
                if (type === 'AAAA') {
                    const err = new Error('No AAAA');
                    err.code = 'ENODATA';
                    throw err;
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '192.0.2.10',
                sender: 'user@example.com',
                resolver: stubResolver,
                createSubResolver: () => stubResolver
            });

            expect(result.qualifier).to.equal('+');
        });

        it('Should handle IPv6 client with IPv6-only MX hosts', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 mx -all']];
                }
                if (type === 'MX') {
                    return [{ priority: 10, exchange: 'mx.example.com' }];
                }
                if (type === 'A') {
                    const err = new Error('No A');
                    err.code = 'ENODATA';
                    throw err;
                }
                if (type === 'AAAA') {
                    return ['2001:db8::10'];
                }
                return [];
            };

            const result = await spfVerify('example.com', {
                ip: '2001:db8::10',
                sender: 'user@example.com',
                resolver: stubResolver,
                createSubResolver: () => stubResolver
            });

            expect(result.qualifier).to.equal('+');
        });

        it('Should handle MX hosts with A records for IPv6 client', async () => {
            const stubResolver = (domain, type) => {
                if (type === 'TXT') {
                    return [['v=spf1 mx -all']];
                }
                if (type === 'MX') {
                    return [{ priority: 10, exchange: 'mx.example.com' }];
                }
                if (type === 'A') {
                    return ['192.0.2.1'];
                }
                if (type === 'AAAA') {
                    return [];  // Empty AAAA, but A exists
                }
                return [];
            };

            // IPv6 client - MX host has no AAAA but has A
            const result = await spfVerify('example.com', {
                ip: '2001:db8::99',
                sender: 'user@example.com',
                resolver: stubResolver,
                createSubResolver: () => stubResolver
            });

            expect(result.qualifier).to.equal('-');
        });
    });
});
