/* eslint @typescript-eslint/no-unused-expressions:0 */
import { describe, it, before, after, beforeEach } from 'node:test';
import { expect } from 'chai';
import { fetchPolicy, getPolicy } from '../../src/mta-sts.js';
import { PolicyServer, POLICY, mockResolver } from './harness.js';

const TEXT_PLAIN = { 'Content-Type': 'text/plain' };
const PARSED = { mode: 'enforce', version: 'STSv1', mx: ['mail.example.test'], maxAge: 86400 };

const resolver = () => mockResolver({ 'mta-sts.example.test|A': ['127.0.0.1'], '_mta-sts.example.test|TXT': [['v=STSv1; id=abc']] });

const fetchResult = async (domain: any, opts?: any) => {
    try {
        return { policy: await fetchPolicy(domain, Object.assign({ resolver: resolver() }, opts)) };
    } catch (err: any) {
        return { error: err };
    }
};

describe('MTA-STS policy fetching (RFC 8461 3.3)', () => {
    const server = new PolicyServer();

    before(
        async () => {
            await server.start();
        },
        { timeout: 10000 }
    );

    after(
        async () => {
            await server.stop();
        },
        { timeout: 10000 }
    );

    beforeEach(
        () => {
            server.reset();
        },
        { timeout: 10000 }
    );

    describe('both modes', () => {
        for (let strict of [false, true]) {
            describe(strict ? 'strict' : 'lax', () => {
                it('fetches a policy with the right URL, Host and SNI', { timeout: 10000 }, async () => {
                    let { policy, error } = await fetchResult('example.test', { strict });
                    expect(error).to.not.exist;
                    expect(policy).to.deep.equal(PARSED);
                    expect(server.requests).to.deep.equal([{ host: 'mta-sts.example.test', url: '/.well-known/mta-sts.txt', method: 'GET' }]);
                    expect(server.sni).to.deep.equal(['mta-sts.example.test']);
                });

                it('uses the domain of an email address and strips a trailing dot', { timeout: 10000 }, async () => {
                    for (let domain of ['user@example.test', 'EXAMPLE.test.']) {
                        server.reset();
                        let { policy, error } = await fetchResult(domain, { strict });
                        expect(error, domain).to.not.exist;
                        expect(policy, domain).to.deep.equal(PARSED);
                        expect(server.sni, domain).to.deep.equal(['mta-sts.example.test']);
                        expect(server.requests[0].host, domain).to.equal('mta-sts.example.test');
                    }
                });

                it('uses A-labels for DNS, SNI and Host with IDN domains', { timeout: 10000 }, async () => {
                    server.useCert('idn');
                    let res = mockResolver({ 'mta-sts.xn--r8jz45g.test|A': ['127.0.0.1'] });
                    let policy = await fetchPolicy('例え.test', { strict, resolver: res });
                    expect(policy).to.deep.equal(PARSED);
                    expect(res.queries).to.deep.equal(['mta-sts.xn--r8jz45g.test|A']);
                    expect(server.sni).to.deep.equal(['mta-sts.xn--r8jz45g.test']);
                    expect(server.requests[0].host).to.equal('mta-sts.xn--r8jz45g.test');
                });

                it('returns false when the policy host has no address', { timeout: 10000 }, async () => {
                    let policy = await fetchPolicy('example.test', { strict, resolver: mockResolver({}) });
                    expect(policy).to.be.false;
                });

                it('does not follow redirects', { timeout: 10000 }, async () => {
                    server.handler = PolicyServer.send(301, { Location: 'https://mta-sts.example.test/other.txt' }, POLICY);
                    let { error } = await fetchResult('example.test', { strict });
                    expect(error?.code).to.equal('http_status_301');
                    expect(server.requests.length).to.equal(1);
                });

                it('rejects non-2xx responses', { timeout: 10000 }, async () => {
                    server.handler = PolicyServer.send(404, TEXT_PLAIN, POLICY);
                    let { error } = await fetchResult('example.test', { strict });
                    expect(error?.code).to.equal('http_status_404');
                });

                it('accepts text/plain with parameters and any case', { timeout: 10000 }, async () => {
                    for (let type of ['text/plain; charset=utf-8', 'TEXT/Plain', 'text/plain;charset=us-ascii']) {
                        server.handler = PolicyServer.send(200, { 'Content-Type': type }, POLICY);
                        let { policy, error } = await fetchResult('example.test', { strict });
                        expect(error, type).to.not.exist;
                        expect(policy, type).to.deep.equal(PARSED);
                    }
                });

                it('rejects a body larger than the default 64 KB limit', { timeout: 10000 }, async () => {
                    server.handler = PolicyServer.send(200, TEXT_PLAIN, POLICY + 'x_pad: ' + 'a'.repeat(65 * 1024) + '\r\n');
                    let { error } = await fetchResult('example.test', { strict });
                    expect(error?.code).to.equal('policy_too_large');
                });

                it('rejects a streamed body without Content-Length once it exceeds the limit', { timeout: 10000 }, async () => {
                    let written = 0;
                    server.handler = (req: any, res: any) => {
                        res.writeHead(200, TEXT_PLAIN);
                        res.write(POLICY);
                        const chunk = Buffer.alloc(16 * 1024, 'a');
                        const pump = () => {
                            while (written < 64 * 1024 * 1024) {
                                if (res.destroyed) {
                                    return;
                                }
                                written += chunk.length;
                                if (!res.write(chunk)) {
                                    return res.once('drain', pump);
                                }
                            }
                            res.end();
                        };
                        res.on('close', () => {});
                        pump();
                    };
                    let { error } = await fetchResult('example.test', { strict, maxPolicySize: 4096 });
                    expect(error?.code).to.equal('policy_too_large');
                    expect(written).to.be.below(64 * 1024 * 1024);
                });

                it('accepts a body up to maxPolicySize', { timeout: 10000 }, async () => {
                    let { policy, error } = await fetchResult('example.test', { strict, maxPolicySize: Buffer.byteLength(POLICY) });
                    expect(error).to.not.exist;
                    expect(policy).to.deep.equal(PARSED);
                    let res = await fetchResult('example.test', { strict, maxPolicySize: Buffer.byteLength(POLICY) - 1 });
                    expect(res.error?.code).to.equal('policy_too_large');
                });

                it('enforces an overall time limit on a slow response', { timeout: 10000 }, async () => {
                    let timer: any;
                    server.handler = (req: any, res: any) => {
                        res.writeHead(200, TEXT_PLAIN);
                        let pos = 0;
                        // one byte every 50ms never hits the idle timeout
                        timer = setInterval(() => {
                            if (pos < POLICY.length) {
                                res.write(POLICY.charAt(pos++));
                            } else {
                                clearInterval(timer);
                                res.end();
                            }
                        }, 50);
                        res.on('close', () => clearInterval(timer));
                    };
                    let start = Date.now();
                    let { error } = await fetchResult('example.test', { strict, timeout: 500 });
                    clearInterval(timer);
                    expect(error?.code).to.equal('HTTP_REQUEST_TIMEOUT');
                    expect(Date.now() - start).to.be.below(3000);
                });

                it('times out when the server does not respond', { timeout: 10000 }, async () => {
                    server.handler = () => {};
                    let start = Date.now();
                    let { error } = await fetchResult('example.test', { strict, timeout: 300 });
                    expect(['HTTP_REQUEST_TIMEOUT', 'HTTP_SOCKET_TIMEOUT']).to.include(error?.code);
                    expect(Date.now() - start).to.be.below(3000);
                });

                it('rejects a truncated response', { timeout: 10000 }, async () => {
                    server.handler = (req: any, res: any) => {
                        res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': 1000 });
                        res.write(POLICY);
                        setTimeout(() => res.destroy(), 50);
                    };
                    let { error } = await fetchResult('example.test', { strict });
                    expect(error).to.exist;
                });

                it('rejects a certificate for another name', { timeout: 10000 }, async () => {
                    server.useCert('wrong');
                    let { error } = await fetchResult('example.test', { strict });
                    expect(error?.code).to.equal('ERR_TLS_CERT_ALTNAME_INVALID');
                    expect(server.requests.length).to.equal(0);
                });

                it('accepts a wildcard certificate that covers the complete left-most label', { timeout: 10000 }, async () => {
                    server.useCert('wild');
                    let { policy, error } = await fetchResult('example.test', { strict });
                    expect(error).to.not.exist;
                    expect(policy).to.deep.equal(PARSED);
                });
            });
        }
    });

    describe('lax mode', () => {
        const warningsFor = async () => {
            let result = await getPolicy('example.test', null, { resolver: resolver() });
            expect(result.status).to.equal('found');
            return result.warnings;
        };

        it('accepts any 2xx status with an http-status warning', { timeout: 10000 }, async () => {
            server.handler = PolicyServer.send(201, TEXT_PLAIN, POLICY);
            expect((await fetchResult('example.test')).policy).to.deep.equal(PARSED);
            expect(await warningsFor()).to.deep.equal(['http-status']);
        });

        it('accepts other media types with a content-type warning', { timeout: 10000 }, async () => {
            for (let headers of [{ 'Content-Type': 'text/html' }, {}]) {
                server.handler = (req: any, res: any) => {
                    res.removeHeader('Content-Type');
                    res.writeHead(200, headers);
                    res.end(POLICY);
                };
                expect((await fetchResult('example.test')).policy).to.deep.equal(PARSED);
                expect(await warningsFor()).to.deep.equal(['content-type']);
            }
        });

        it('accepts CN-only and partial-label wildcard certificates with a cert-identity warning', { timeout: 10000 }, async () => {
            for (let cert of ['cnonly', 'partial']) {
                server.useCert(cert);
                expect((await fetchResult('example.test')).policy, cert).to.deep.equal(PARSED);
                expect(await warningsFor(), cert).to.deep.equal(['cert-identity']);
            }
        });

        it('reports policy-syntax for lax policy syntax', { timeout: 10000 }, async () => {
            server.handler = PolicyServer.send(200, TEXT_PLAIN, POLICY.replace('86400', '8.64e4'));
            expect(await warningsFor()).to.deep.equal(['policy-syntax']);
        });

        it('does not add warnings for a compliant policy', { timeout: 10000 }, async () => {
            expect(await warningsFor()).to.be.undefined;
        });
    });

    describe('strict mode', () => {
        it('accepts only HTTP 200', { timeout: 10000 }, async () => {
            for (let status of [201, 203, 206]) {
                server.handler = PolicyServer.send(status, TEXT_PLAIN, POLICY);
                let { error } = await fetchResult('example.test', { strict: true });
                expect(error?.code, String(status)).to.equal(`http_status_${status}`);
            }
        });

        it('requires Content-Type text/plain', { timeout: 10000 }, async () => {
            for (let headers of [{ 'Content-Type': 'text/html' }, { 'Content-Type': 'image/png' }, {}]) {
                server.handler = (req: any, res: any) => {
                    res.removeHeader('Content-Type');
                    res.writeHead(200, headers);
                    res.end(POLICY);
                };
                let { error } = await fetchResult('example.test', { strict: true });
                expect(error?.code, JSON.stringify(headers)).to.equal('invalid_content_type');
            }
        });

        it('rejects CN-only and partial-label wildcard certificates', { timeout: 10000 }, async () => {
            for (let cert of ['cnonly', 'partial']) {
                server.useCert(cert);
                let { error } = await fetchResult('example.test', { strict: true });
                expect(error?.code, cert).to.equal('ERR_TLS_CERT_ALTNAME_INVALID');
                expect(server.requests.length, cert).to.equal(0);
            }
        });

        it('rejects non-RFC max_age syntax', { timeout: 10000 }, async () => {
            server.handler = PolicyServer.send(200, TEXT_PLAIN, POLICY.replace('86400', '8.64e4'));
            let { error } = await fetchResult('example.test', { strict: true });
            expect(error?.code).to.equal('invalid_sts_max_age');
        });
    });
});
