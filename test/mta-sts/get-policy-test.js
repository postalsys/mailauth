/* eslint no-unused-expressions:0, no-invalid-this: 0 */
'use strict';

const { expect } = require('chai');
const { getPolicy, validateMx } = require('../../lib/mta-sts');
const { PolicyServer, POLICY, mockResolver, dnsError } = require('./harness');

const TEXT_PLAIN = { 'Content-Type': 'text/plain' };
const HOUR = 3600 * 1000;

const future = () => new Date(Date.now() + 24 * HOUR).toISOString();
const past = () => new Date(Date.now() - 60 * 1000).toISOString();

const cachedPolicy = expires => ({ id: 'v1', version: 'STSv1', mode: 'enforce', mx: ['mail.example.test'], maxAge: 86400, expires });

const A = { 'mta-sts.example.test|A': ['127.0.0.1'] };
const TXT = id => ({ '_mta-sts.example.test|TXT': [[`v=STSv1; id=${id}`]] });

const fail500 = PolicyServer.send(500, TEXT_PLAIN, 'error');

describe('MTA-STS getPolicy caching (RFC 8461 3.3, 5.1)', function () {
    this.timeout(10000);

    const server = new PolicyServer();

    before(async () => {
        await server.start();
    });

    after(async () => {
        await server.stop();
    });

    beforeEach(() => {
        server.reset();
    });

    for (let strict of [false, true]) {
        describe(strict ? 'strict' : 'lax', () => {
            const run = (knownPolicy, table) => getPolicy('example.test', knownPolicy, { strict, resolver: mockResolver(table) });

            it('fetches a new policy when there is no cache', async () => {
                let before = Date.now();
                let { policy, status, warnings } = await run(null, { ...TXT('v1'), ...A });
                expect(status).to.equal('found');
                expect(warnings).to.be.undefined;
                expect(Object.keys(policy)).to.deep.equal(['id', 'mode', 'version', 'mx', 'maxAge', 'expires']);
                expect(policy).to.deep.include({ id: 'v1', mode: 'enforce', version: 'STSv1', mx: ['mail.example.test'], maxAge: 86400 });
                let expires = new Date(policy.expires).getTime();
                expect(expires).to.be.within(before + 86400 * 1000, Date.now() + 86400 * 1000);
                expect(server.requests.length).to.equal(1);
            });

            it('returns not_found without a TXT record and without a valid cache', async () => {
                expect(await run(null, { ...A })).to.deep.equal({ policy: { id: false, mode: 'none' }, status: 'not_found' });
                expect(await run(cachedPolicy(past()), { ...A })).to.deep.equal({ policy: { id: false, mode: 'none' }, status: 'not_found' });
                expect(server.requests.length).to.equal(0);
            });

            it('returns errored without a cache when DNS fails', async () => {
                let { policy, status } = await run(null, { '_mta-sts.example.test|TXT': dnsError('ESERVFAIL') });
                expect(status).to.equal('errored');
                expect(policy).to.deep.include({ id: false, mode: 'none' });
                expect(policy.error.code).to.equal('ESERVFAIL');
            });

            it('reuses a valid cached policy with the same id without fetching', async () => {
                let known = cachedPolicy(future());
                let result = await run(known, { ...TXT('v1'), ...A });
                expect(result).to.deep.equal({ policy: known, status: 'renewed' });
                expect(result.policy).to.not.equal(known);
                expect(server.requests.length).to.equal(0);
            });

            it('refetches an expired cached policy with the same id', async () => {
                let { policy, status } = await run(cachedPolicy(past()), { ...TXT('v1'), ...A });
                expect(status).to.equal('found');
                expect(new Date(policy.expires).getTime()).to.be.above(Date.now());
                expect(server.requests.length).to.equal(1);
            });

            it('refetches a cached policy without expires', async () => {
                let known = cachedPolicy();
                delete known.expires;
                let { status } = await run(known, { ...TXT('v1'), ...A });
                expect(status).to.equal('found');
                expect(server.requests.length).to.equal(1);
            });

            it('fetches a new policy when the id changes', async () => {
                server.handler = PolicyServer.send(200, TEXT_PLAIN, POLICY.replace('enforce', 'testing'));
                let { policy, status } = await run(cachedPolicy(future()), { ...TXT('v2'), ...A });
                expect(status).to.equal('found');
                expect(policy).to.deep.include({ id: 'v2', mode: 'testing' });
            });

            describe('keeps a valid cached policy when no live policy is available', () => {
                const scenarios = [
                    ['TXT record removed', { ...A }, 'sts_record_not_found'],
                    ['TXT lookup SERVFAIL', { '_mta-sts.example.test|TXT': dnsError('ESERVFAIL'), ...A }, 'ESERVFAIL'],
                    ['TXT lookup timeout', { '_mta-sts.example.test|TXT': dnsError('ETIMEOUT'), ...A }, 'ETIMEOUT'],
                    ['multiple TXT records', { '_mta-sts.example.test|TXT': [['v=STSv1; id=a'], ['v=STSv1; id=b']], ...A }, 'multi_sts_records'],
                    ['TXT record without id', { '_mta-sts.example.test|TXT': [['v=STSv1;']], ...A }, 'invalid_sts_record'],
                    ['new id, policy host without address', { ...TXT('v2') }, 'policy_host_not_found'],
                    ['new id, policy host lookup SERVFAIL', { ...TXT('v2'), 'mta-sts.example.test|A': dnsError('ESERVFAIL') }, 'ESERVFAIL'],
                    ['new id, HTTPS 500', { ...TXT('v2'), ...A }, 'http_status_500', fail500],
                    [
                        'new id, policy without mode',
                        { ...TXT('v2'), ...A },
                        'invalid_sts_mode',
                        PolicyServer.send(200, TEXT_PLAIN, POLICY.replace('mode: enforce\r\n', ''))
                    ],
                    [
                        'new id, oversized policy',
                        { ...TXT('v2'), ...A },
                        'policy_too_large',
                        PolicyServer.send(200, TEXT_PLAIN, POLICY + 'x: ' + 'a'.repeat(70000) + '\r\n')
                    ],
                    ['new id, invalid certificate', { ...TXT('v2'), ...A }, 'ERR_TLS_CERT_ALTNAME_INVALID', null, 'wrong']
                ];

                for (let [name, table, code, handler, cert] of scenarios) {
                    it(name, async () => {
                        if (handler) {
                            server.handler = handler;
                        }
                        if (cert) {
                            server.useCert(cert);
                        }
                        let known = cachedPolicy(future());
                        let { policy, status, warnings } = await run(known, table);
                        expect(status).to.equal('errored');
                        expect(warnings).to.be.undefined;
                        expect(policy.error?.code).to.equal(code);
                        let copy = Object.assign({}, policy);
                        delete copy.error;
                        expect(copy).to.deep.equal(known);
                        expect(validateMx('evil.example.test', policy).valid).to.be.false;
                    });
                }
            });

            it('uses the first mode when mode is duplicated', async () => {
                server.handler = PolicyServer.send(200, TEXT_PLAIN, POLICY + 'mode: none\r\n');
                let { policy, status } = await run(cachedPolicy(future()), { ...TXT('v2'), ...A });
                expect(status).to.equal('found');
                expect(policy.mode).to.equal('enforce');
            });

            it('does not disable MTA-STS after a failed first fetch (retry placeholder)', async () => {
                server.handler = fail500;
                let before = Date.now();
                let first = await run(null, { ...TXT('v1'), ...A });
                expect(first.status).to.equal('errored');
                expect(first.policy).to.deep.include({ id: 'v1', mode: 'none' });
                expect(first.policy.error.code).to.equal('http_status_500');
                // retry delay of one hour, at least five minutes per RFC 8461 3.3
                expect(new Date(first.policy.expires).getTime()).to.be.within(before + HOUR, Date.now() + HOUR);

                // within the retry delay the placeholder is reused without a new request
                server.handler = null;
                let second = await run(first.policy, { ...TXT('v1'), ...A });
                expect(second.status).to.equal('renewed');
                expect(second.policy.mode).to.equal('none');
                expect(server.requests.length).to.equal(1);

                // after the retry delay the policy is fetched again
                let third = await run(Object.assign({}, first.policy, { expires: past() }), { ...TXT('v1'), ...A });
                expect(third.status).to.equal('found');
                expect(third.policy).to.deep.include({ id: 'v1', mode: 'enforce', maxAge: 86400 });
                expect(server.requests.length).to.equal(2);

                // a changed id is fetched right away
                server.handler = fail500;
                let fourth = await run(first.policy, { ...TXT('v2'), ...A });
                expect(fourth.status).to.equal('errored');
                expect(fourth.policy).to.deep.include({ id: 'v2', mode: 'none' });
                expect(server.requests.length).to.equal(3);
            });

            it('never throws for a placeholder without maxAge', async () => {
                let placeholder = { id: 'v1', mode: 'none', expires: past() };
                let res = mockResolver({ ...TXT('v1'), ...A });
                let { policy, status } = await getPolicy('example.test', placeholder, { strict, resolver: res });
                expect(status).to.equal('found');
                expect(policy.mode).to.equal('enforce');

                placeholder.expires = future();
                let renewed = await getPolicy('example.test', placeholder, { strict, resolver: res });
                expect(renewed).to.deep.equal({ policy: placeholder, status: 'renewed' });
            });

            it('replaces an expired mode none policy with a retry placeholder on fetch error', async () => {
                server.handler = fail500;
                let known = Object.assign(cachedPolicy(past()), { mode: 'none' });
                let { policy, status, warnings } = await run(known, { ...TXT('v2'), ...A });
                expect(status).to.equal('errored');
                expect(warnings).to.be.undefined;
                expect(policy).to.deep.include({ id: 'v2', mode: 'none' });
                expect(new Date(policy.expires).getTime()).to.be.above(Date.now());
            });

            it('keeps the enforce policy when the README caching recipe is followed', async () => {
                // store whatever getPolicy returns
                let cache = null;
                const step = async (table, handler) => {
                    server.handler = handler || null;
                    let { policy } = await run(cache, table);
                    cache = policy;
                    return policy;
                };

                expect((await step({ ...TXT('v1'), ...A })).mode).to.equal('enforce');
                // an attacker blocks DNS, removes TXT records or breaks HTTPS
                expect((await step({ ...A })).mode).to.equal('enforce');
                expect((await step({ '_mta-sts.example.test|TXT': dnsError('ESERVFAIL') })).mode).to.equal('enforce');
                expect((await step({ ...TXT('v9'), ...A }, fail500)).mode).to.equal('enforce');
                expect((await step({ ...TXT('v9') })).mode).to.equal('enforce');
                expect(cache.id).to.equal('v1');
                // the domain owner publishes a new policy
                expect((await step({ ...TXT('v2'), ...A }, PolicyServer.send(200, TEXT_PLAIN, POLICY.replace('enforce', 'testing')))).mode).to.equal('testing');
                expect(cache.id).to.equal('v2');
            });
        });
    }

    describe('expired cached policy and fetch error', () => {
        it('lax mode keeps applying the expired policy with an expired-cache warning', async () => {
            server.handler = fail500;
            let known = cachedPolicy(past());
            let { policy, status, warnings } = await getPolicy('example.test', known, { resolver: mockResolver({ ...TXT('v2'), ...A }) });
            expect(status).to.equal('errored');
            expect(warnings).to.deep.equal(['expired-cache']);
            expect(policy.error.code).to.equal('http_status_500');
            let copy = Object.assign({}, policy);
            delete copy.error;
            expect(copy).to.deep.equal(known);
        });

        it('strict mode treats the expired policy as no policy', async () => {
            server.handler = fail500;
            let { policy, status, warnings } = await getPolicy('example.test', cachedPolicy(past()), {
                strict: true,
                resolver: mockResolver({ ...TXT('v2'), ...A })
            });
            expect(status).to.equal('errored');
            expect(warnings).to.be.undefined;
            expect(policy).to.deep.include({ id: 'v2', mode: 'none' });
            expect(policy.error.code).to.equal('http_status_500');
            expect(new Date(policy.expires).getTime()).to.be.above(Date.now());
        });
    });

    describe('TXT syntax', () => {
        it('strict mode keeps a valid cached policy when the TXT record is not RFC compliant', async () => {
            let known = cachedPolicy(future());
            let { policy, status } = await getPolicy('example.test', known, {
                strict: true,
                resolver: mockResolver({ '_mta-sts.example.test|TXT': [['v=STSv1; id=v-2']], ...A })
            });
            expect(status).to.equal('errored');
            expect(policy.error.code).to.equal('invalid_sts_record');
            expect(policy.id).to.equal('v1');
            expect(server.requests.length).to.equal(0);
        });

        it('strict mode reports not_found for a non-compliant TXT record without a cache', async () => {
            let result = await getPolicy('example.test', null, {
                strict: true,
                resolver: mockResolver({ '_mta-sts.example.test|TXT': [['v=STSv1; id=v-2']], ...A })
            });
            expect(result).to.deep.equal({ policy: { id: false, mode: 'none' }, status: 'not_found' });
        });

        it('lax mode accepts the non-compliant TXT record with a txt-syntax warning', async () => {
            let { policy, status, warnings } = await getPolicy('example.test', null, {
                resolver: mockResolver({ '_mta-sts.example.test|TXT': [['v=STSv1; id=v-2']], ...A })
            });
            expect(status).to.equal('found');
            expect(policy.id).to.equal('v-2');
            expect(warnings).to.deep.equal(['txt-syntax']);
        });
    });

    it('uses the same domain for discovery and fetching with an email address', async () => {
        let res = mockResolver({ ...TXT('v1'), ...A });
        let { status } = await getPolicy('user@EXAMPLE.test.', null, { resolver: res });
        expect(status).to.equal('found');
        expect(res.queries).to.deep.equal(['_mta-sts.example.test|TXT', 'mta-sts.example.test|A']);
        expect(server.sni).to.deep.equal(['mta-sts.example.test']);
    });
});
