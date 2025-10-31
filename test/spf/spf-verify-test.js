/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

let { spfVerify } = require('../../lib/spf/spf-verify');

chai.config.includeStack = true;

describe('SPF Verifier Tests', () => {
    it('Should pass all IPs', async () => {
        const stubResolver = () => [['v=spf1 +all']];

        let result = await spfVerify('example.com', { ip: '1.2.3.4', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');
    });

    it('Should fail all IPs', async () => {
        const stubResolver = () => [['v=spf1 -all']];

        let result = await spfVerify('example.com', { ip: '1.2.3.4', resolver: stubResolver });
        expect(result.qualifier).to.equal('-');
    });

    it('Should pass A records', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 a -all']];
                case 'A':
                    return ['192.0.2.10', '192.0.2.11'];
            }
        };

        let result;

        result = await spfVerify('example.com', { ip: '1.2.3.4', sender: 'user@example.com', resolver: stubResolver });
        expect(result.qualifier).to.equal('-');

        result = await spfVerify('example.com', { ip: '192.0.2.10', sender: 'user@example.com', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');

        result = await spfVerify('example.com', { ip: '192.0.2.11', sender: 'user@example.com', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');
    });

    it('Should pass MX records', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 mx -all']];
                case 'A':
                    return ['192.0.2.10', '192.0.2.11'];
                case 'MX':
                    return [{ priority: 1, exchange: 'example.com' }];
            }
        };

        let result;

        result = await spfVerify('example.com', { ip: '1.2.3.4', resolver: stubResolver });
        expect(result.qualifier).to.equal('-');

        result = await spfVerify('example.com', { ip: '192.0.2.10', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');

        result = await spfVerify('example.com', { ip: '192.0.2.11', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');
    });

    it('Should pass MX/CIDR records', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 mx/24 -all']];
                case 'A':
                    return ['192.0.2.10', '192.0.2.11'];
                case 'MX':
                    return [{ priority: 1, exchange: 'example.com' }];
            }
        };

        let result;

        result = await spfVerify('example.com', { ip: '1.2.3.4', resolver: stubResolver });
        expect(result.qualifier).to.equal('-');

        result = await spfVerify('example.com', { ip: '192.0.2.10', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');

        result = await spfVerify('example.com', { ip: '192.0.2.11', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');

        result = await spfVerify('example.com', { ip: '192.0.2.56', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');
    });

    it('Should pass exists rule', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all']];
                case 'A': {
                    switch (domain) {
                        case '4.3.2.1.some._spf.example.com':
                            return ['127.0.0.1'];
                        default:
                            return [];
                    }
                }
            }
        };

        let result;
        result = await spfVerify('example.com', { ip: '1.2.3.4', sender: 'some+user@example.com', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');

        result = await spfVerify('example.com', { ip: '1.2.2.4', sender: 'some+user@example.com', resolver: stubResolver });
        expect(result.qualifier).to.equal('-');
    });

    it('Should expand macros in MX mechanism', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    if (domain === 'spf.lcn.com') {
                        // Real-world case with mx:%{o} macro
                        return [['v=spf1 mx:%{o} -all']];
                    }
                    break;
                case 'MX':
                    if (domain === 'skinanalytics.co.uk') {
                        return [{ priority: 10, exchange: 'mail.skinanalytics.co.uk' }];
                    }
                    break;
                case 'A':
                    if (domain === 'mail.skinanalytics.co.uk') {
                        return ['209.85.208.173'];
                    }
                    break;
            }
            return [];
        };

        // Test with %{o} macro - sender domain should be used for MX lookup
        let result = await spfVerify('spf.lcn.com', {
            ip: '209.85.208.173',
            sender: 'test@skinanalytics.co.uk',
            resolver: stubResolver
        });
        expect(result.qualifier).to.equal('+');

        // Test with non-matching IP
        result = await spfVerify('spf.lcn.com', {
            ip: '192.0.2.20',
            sender: 'test@skinanalytics.co.uk',
            resolver: stubResolver
        });
        expect(result.qualifier).to.equal('-');
    });

    it('Should not count IPv4-only MX hosts as void when checking IPv6 client', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 mx -all']];
                case 'MX':
                    return [
                        { priority: 10, exchange: 'mx1.example.com' },
                        { priority: 10, exchange: 'mx2.example.com' },
                        { priority: 10, exchange: 'mx3.example.com' }
                    ];
                case 'A':
                    // All MX hosts have A records
                    if (domain === 'mx1.example.com') return ['192.0.2.10'];
                    if (domain === 'mx2.example.com') return ['192.0.2.11'];
                    if (domain === 'mx3.example.com') return ['192.0.2.12'];
                    return [];
                case 'AAAA':
                    // No AAAA records exist - return empty array (void)
                    return [];
            }
        };

        // IPv6 client should not match (no AAAA records)
        // But should also NOT hit void limit error
        let result = await spfVerify('example.com', {
            ip: '2001:db8::1',
            sender: 'user@example.com',
            resolver: stubResolver,
            createSubResolver: () => stubResolver
        });
        expect(result.qualifier).to.equal('-');
    });

    it('Should not count IPv6-only MX hosts as void when checking IPv4 client', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 mx -all']];
                case 'MX':
                    return [
                        { priority: 10, exchange: 'mx1.example.com' },
                        { priority: 10, exchange: 'mx2.example.com' },
                        { priority: 10, exchange: 'mx3.example.com' }
                    ];
                case 'AAAA':
                    // All MX hosts have AAAA records
                    if (domain === 'mx1.example.com') return ['2001:db8::10'];
                    if (domain === 'mx2.example.com') return ['2001:db8::11'];
                    if (domain === 'mx3.example.com') return ['2001:db8::12'];
                    return [];
                case 'A':
                    // No A records exist - return empty array (void)
                    return [];
            }
        };

        // IPv4 client should not match (no A records)
        // But should also NOT hit void limit error
        let result = await spfVerify('example.com', {
            ip: '192.0.2.50',
            sender: 'user@example.com',
            resolver: stubResolver,
            createSubResolver: () => stubResolver
        });
        expect(result.qualifier).to.equal('-');
    });

    it('Should not count IPv4-only A records as void when checking IPv6 client', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 a:host1.example.com a:host2.example.com a:host3.example.com -all']];
                case 'A':
                    // All hosts have A records
                    if (domain === 'host1.example.com') return ['192.0.2.10'];
                    if (domain === 'host2.example.com') return ['192.0.2.11'];
                    if (domain === 'host3.example.com') return ['192.0.2.12'];
                    return [];
                case 'AAAA':
                    // No AAAA records exist - return empty array (void)
                    return [];
            }
        };

        // IPv6 client should not match (no AAAA records)
        // But should also NOT hit void limit error
        let result = await spfVerify('example.com', {
            ip: '2001:db8::1',
            sender: 'user@example.com',
            resolver: stubResolver
        });
        expect(result.qualifier).to.equal('-');
    });

    it('Should match IPv6 client with dual-stack MX host', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 mx -all']];
                case 'MX':
                    return [{ priority: 10, exchange: 'mx.example.com' }];
                case 'A':
                    if (domain === 'mx.example.com') return ['192.0.2.10'];
                    return [];
                case 'AAAA':
                    if (domain === 'mx.example.com') return ['2001:db8::10'];
                    return [];
            }
        };

        // IPv6 client should match AAAA record
        let result = await spfVerify('example.com', {
            ip: '2001:db8::10',
            sender: 'user@example.com',
            resolver: stubResolver,
            createSubResolver: () => stubResolver
        });
        expect(result.qualifier).to.equal('+');
    });

    it('Should match IPv4 client with dual-stack MX host', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 mx -all']];
                case 'MX':
                    return [{ priority: 10, exchange: 'mx.example.com' }];
                case 'A':
                    if (domain === 'mx.example.com') return ['192.0.2.10'];
                    return [];
                case 'AAAA':
                    if (domain === 'mx.example.com') return ['2001:db8::10'];
                    return [];
            }
        };

        // IPv4 client should match A record
        let result = await spfVerify('example.com', {
            ip: '192.0.2.10',
            sender: 'user@example.com',
            resolver: stubResolver,
            createSubResolver: () => stubResolver
        });
        expect(result.qualifier).to.equal('+');
    });

    it('Should count as void only when both A and AAAA are missing', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 a:host1.example.com a:host2.example.com a:nonexistent.example.com -all']];
                case 'A':
                    if (domain === 'host1.example.com') return ['192.0.2.10'];
                    if (domain === 'host2.example.com') return [];
                    if (domain === 'nonexistent.example.com') return [];
                    return [];
                case 'AAAA':
                    if (domain === 'host1.example.com') return [];
                    if (domain === 'host2.example.com') return ['2001:db8::11'];
                    if (domain === 'nonexistent.example.com') return [];
                    return [];
            }
        };

        // host1: has A, no AAAA (not void - has A)
        // host2: no A, has AAAA (not void - has AAAA)
        // nonexistent: no A, no AAAA (void - counts as 1)
        // Total void count should be 1, which is within limit
        let result = await spfVerify('example.com', {
            ip: '2001:db8::11',
            sender: 'user@example.com',
            resolver: stubResolver
        });
        expect(result.qualifier).to.equal('+');
    });

    it('Should throw ETIMEOUT error when A query times out (with AAAA void)', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 a:timeout.example.com -all']];
                case 'A':
                    if (domain === 'timeout.example.com') {
                        const err = new Error('DNS timeout');
                        err.code = 'ETIMEOUT';
                        err.spfResult = { error: 'temperror', text: 'DNS timeout' };
                        throw err;
                    }
                    return [];
                case 'AAAA':
                    if (domain === 'timeout.example.com') {
                        const err = new Error('ENODATA');
                        err.code = 'ENODATA';
                        throw err;
                    }
                    return [];
            }
        };

        try {
            await spfVerify('example.com', {
                ip: '192.0.2.10',
                sender: 'user@example.com',
                resolver: stubResolver
            });
            expect.fail('Should have thrown ETIMEOUT error');
        } catch (err) {
            expect(err.code).to.equal('ETIMEOUT');
            expect(err.spfResult.error).to.equal('temperror');
        }
    });

    it('Should throw ETIMEOUT error when AAAA query times out (with A void)', async () => {
        const stubResolver = async (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 a:timeout.example.com -all']];
                case 'A':
                    if (domain === 'timeout.example.com') return [];
                    return [];
                case 'AAAA':
                    if (domain === 'timeout.example.com') {
                        const err = new Error('DNS timeout');
                        err.code = 'ETIMEOUT';
                        err.spfResult = { error: 'temperror', text: 'DNS timeout' };
                        throw err;
                    }
                    return [];
            }
        };

        try {
            await spfVerify('example.com', {
                ip: '2001:db8::1',
                sender: 'user@example.com',
                resolver: stubResolver
            });
            expect.fail('Should have thrown ETIMEOUT error');
        } catch (err) {
            expect(err.code).to.equal('ETIMEOUT');
            expect(err.spfResult.error).to.equal('temperror');
        }
    });

    it('Should ignore A query EREFUSED error when AAAA has records (IPv6 client)', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 mx -all']];
                case 'MX':
                    return [{ priority: 10, exchange: 'refused.example.com' }];
                case 'A':
                    if (domain === 'refused.example.com') {
                        const err = new Error('DNS request refused');
                        err.code = 'EREFUSED';
                        err.spfResult = { error: 'temperror', text: 'DNS request refused by server' };
                        throw err;
                    }
                    return [];
                case 'AAAA':
                    if (domain === 'refused.example.com') return ['2001:db8::1'];
                    return [];
            }
        };

        const result = await spfVerify('example.com', {
            ip: '2001:db8::1',
            sender: 'user@example.com',
            resolver: stubResolver,
            createSubResolver: () => stubResolver
        });

        // Should pass because IPv6 client matches the AAAA record
        expect(result.qualifier).to.equal('+');
    });

    it('Should ignore AAAA query EREFUSED error when A has records (IPv4 client)', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 mx -all']];
                case 'MX':
                    return [{ priority: 10, exchange: 'refused.example.com' }];
                case 'A':
                    if (domain === 'refused.example.com') return ['192.0.2.10'];
                    return [];
                case 'AAAA':
                    if (domain === 'refused.example.com') {
                        const err = new Error('DNS request refused');
                        err.code = 'EREFUSED';
                        err.spfResult = { error: 'temperror', text: 'DNS request refused by server' };
                        throw err;
                    }
                    return [];
            }
        };

        const result = await spfVerify('example.com', {
            ip: '192.0.2.10',
            sender: 'user@example.com',
            resolver: stubResolver,
            createSubResolver: () => stubResolver
        });

        // Should pass because IPv4 client matches the A record
        expect(result.qualifier).to.equal('+');
    });

    it('Should handle both A and AAAA timing out', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 a:timeout.example.com -all']];
                case 'A':
                    if (domain === 'timeout.example.com') {
                        const err = new Error('DNS timeout');
                        err.code = 'ETIMEOUT';
                        err.spfResult = { error: 'temperror', text: 'DNS timeout' };
                        throw err;
                    }
                    return [];
                case 'AAAA':
                    if (domain === 'timeout.example.com') {
                        const err = new Error('DNS timeout');
                        err.code = 'ETIMEOUT';
                        err.spfResult = { error: 'temperror', text: 'DNS timeout' };
                        throw err;
                    }
                    return [];
            }
        };

        try {
            await spfVerify('example.com', {
                ip: '192.0.2.10',
                sender: 'user@example.com',
                resolver: stubResolver
            });
            expect.fail('Should have thrown ETIMEOUT error');
        } catch (err) {
            expect(err.code).to.equal('ETIMEOUT');
            expect(err.spfResult.error).to.equal('temperror');
        }
    });
});
