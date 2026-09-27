/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;
const dgram = require('node:dgram');
const { Resolver } = require('node:dns').promises;

const { spf } = require('../../lib/spf');
const { spfVerify } = require('../../lib/spf/spf-verify');
const macro = require('../../lib/spf/macro');

chai.config.includeStack = true;

// zone: { name: { TXT: ['v=spf1 ...'] | 'ESERVFAIL', A: [...], AAAA: [...], MX: [{ priority, exchange }], PTR: [...] } }
// a string value is thrown as an error with that code, a missing name is NXDOMAIN, a missing type is NODATA
const makeResolver = (zone, log) => {
    const records = {};
    for (const key of Object.keys(zone)) {
        records[key.toLowerCase()] = zone[key];
    }
    return async (name, type) => {
        if (log) {
            log.push(`${type} ${name}`);
        }
        const fail = code => {
            const err = new Error(`${code} ${type} ${name}`);
            err.code = code;
            throw err;
        };
        const entry = records[String(name).toLowerCase()];
        if (!entry) {
            fail('ENOTFOUND');
        }
        const value = entry[type];
        if (value === undefined) {
            fail('ENODATA');
        }
        if (typeof value === 'string') {
            fail(value);
        }
        if (type === 'TXT') {
            return value.map(row => [].concat(row));
        }
        return value;
    };
};

const check = async (opts, zone, log) =>
    await spf(
        Object.assign(
            {
                sender: 'user@example.test',
                ip: '192.0.2.1',
                helo: 'mail.example.test',
                mta: 'mx.receiver.test',
                resolver: makeResolver(zone, log)
            },
            opts
        )
    );

// runs the same check in the default and in the strict mode
const both = async (opts, zone) => ({
    lax: await check(Object.assign({}, opts), zone),
    strict: await check(Object.assign({}, opts, { strict: true }), zone)
});

const record = (txt, extra) => Object.assign({ 'example.test': { TXT: [].concat(txt) } }, extra || {});

describe('SPF RFC 7208 compliance', () => {
    describe('DNS errors inside include and redirect (RFC 7208 5.2, 6.1)', () => {
        it('Should return permerror for an include target that the resolver rejects as a bad name', async () => {
            const { lax, strict } = await both({}, record('v=spf1 -include:_block.provider.test +all', { '_block.provider.test': { TXT: 'EBADNAME' } }));
            expect(lax.status.result).to.equal('permerror');
            expect(strict.status.result).to.equal('permerror');
        });

        it('Should return permerror for an include target with a label over 63 characters', async () => {
            const local = 'a'.repeat(64);
            const { lax, strict } = await both(
                { sender: `${local}@example.test` },
                record('v=spf1 -include:%{l}.block.example.test +all', { [`${local}.block.example.test`]: { TXT: 'EBADNAME' } })
            );
            expect(lax.status.result).to.equal('permerror');
            expect(strict.status.result).to.equal('permerror');
        });

        for (const code of ['ESERVFAIL', 'ECONNREFUSED', 'EBADRESP', 'ENOTIMP', 'ECANCELLED']) {
            it(`Should return temperror for ${code} on an include target`, async () => {
                const { lax, strict } = await both({}, record('v=spf1 include:_spf.provider.test -all', { '_spf.provider.test': { TXT: code } }));
                expect(lax.status.result).to.equal('temperror');
                expect(strict.status.result).to.equal('temperror');
            });

            it(`Should not turn a blocklist include with ${code} into pass`, async () => {
                const { lax, strict } = await both({}, record('v=spf1 -include:_block.provider.test +all', { '_block.provider.test': { TXT: code } }));
                expect(lax.status.result).to.equal('temperror');
                expect(strict.status.result).to.equal('temperror');
            });

            it(`Should return temperror for ${code} on a redirect target`, async () => {
                const { lax, strict } = await both({}, record('v=spf1 redirect=_spf.example.test', { '_spf.example.test': { TXT: code } }));
                expect(lax.status.result).to.equal('temperror');
                expect(strict.status.result).to.equal('temperror');
            });

            it(`Should return temperror for ${code} in a mechanism of an included record`, async () => {
                const { lax, strict } = await both(
                    {},
                    record('v=spf1 -include:inc.example.test +all', {
                        'inc.example.test': { TXT: ['v=spf1 a:host.example.test -all'] },
                        'host.example.test': { A: code, AAAA: code }
                    })
                );
                expect(lax.status.result).to.equal('temperror');
                expect(strict.status.result).to.equal('temperror');
            });
        }

        it('Should keep the existing comment text for a top level DNS error', async () => {
            const res = await check({}, { 'example.test': { TXT: 'ESERVFAIL' } });
            expect(res.status.result).to.equal('temperror');
            expect(res.status.comment).to.equal('mx.receiver.test: error in processing during lookup of user@example.test: ESERVFAIL TXT example.test');
        });

        it('Should propagate DNS errors from include in spfVerify without a limited resolver', async () => {
            const resolver = makeResolver(record('v=spf1 -include:_block.provider.test +all', { '_block.provider.test': { TXT: 'ESERVFAIL' } }));
            let error;
            try {
                await spfVerify('example.test', { ip: '192.0.2.1', sender: 'user@example.test', resolver });
            } catch (err) {
                error = err;
            }
            expect(error).to.exist;
            expect(error.code).to.equal('ESERVFAIL');
        });

        it('Should return temperror for a real SERVFAIL response from node:dns', async () => {
            const txtRdata = str => {
                const buf = Buffer.from(str);
                return Buffer.concat([Buffer.from([buf.length]), buf]);
            };

            const server = dgram.createSocket('udp4');
            server.on('message', (msg, rinfo) => {
                let offset = 12;
                const labels = [];
                while (msg[offset]) {
                    labels.push(msg.slice(offset + 1, offset + 1 + msg[offset]).toString());
                    offset += msg[offset] + 1;
                }
                const question = msg.slice(12, offset + 5);
                const qtype = msg.readUInt16BE(offset + 1);
                const name = labels.join('.').toLowerCase();

                let rcode = 3;
                const answers = [];
                if (name === 'example.test' && qtype === 16) {
                    rcode = 0;
                    answers.push(txtRdata('v=spf1 -include:blocklist.example.test +all'));
                } else if (name === 'blocklist.example.test') {
                    // SERVFAIL
                    rcode = 2;
                }

                const header = Buffer.alloc(12);
                msg.copy(header, 0, 0, 2);
                header.writeUInt16BE(0x8180 | rcode, 2);
                header.writeUInt16BE(1, 4);
                header.writeUInt16BE(answers.length, 6);
                const answerBuffers = answers.map(rdata => {
                    const answer = Buffer.alloc(12);
                    answer.writeUInt16BE(0xc00c, 0);
                    answer.writeUInt16BE(16, 2);
                    answer.writeUInt16BE(1, 4);
                    answer.writeUInt32BE(60, 6);
                    answer.writeUInt16BE(rdata.length, 10);
                    return Buffer.concat([answer, rdata]);
                });
                server.send(Buffer.concat([header, question, ...answerBuffers]), rinfo.port, rinfo.address);
            });

            await new Promise(resolve => server.bind(0, '127.0.0.1', resolve));
            try {
                const dnsResolver = new Resolver({ timeout: 1000, tries: 1 });
                dnsResolver.setServers([`127.0.0.1:${server.address().port}`]);

                const res = await spf({
                    sender: 'user@example.test',
                    ip: '192.0.2.1',
                    helo: 'mail.example.test',
                    mta: 'mx.receiver.test',
                    resolver: (name, type) => dnsResolver.resolve(name, type)
                });
                expect(res.status.result).to.equal('temperror');
            } finally {
                server.close();
            }
        });
    });

    describe('ptr lookup counting (RFC 7208 4.6.4)', () => {
        it('Should count every ptr term toward the lookup limit', async () => {
            const terms = Array.from({ length: 11 }, (_, i) => `ptr:d${i}.example.test`).join(' ');
            const { lax, strict } = await both(
                {},
                record(`v=spf1 ${terms} -all`, {
                    '1.2.0.192.in-addr.arpa': { PTR: ['mail.other.test'] },
                    'mail.other.test': { A: ['192.0.2.1'] }
                })
            );
            expect(lax.status.result).to.equal('permerror');
            expect(lax.status.comment).to.include('Too many DNS requests');
            expect(strict.status.result).to.equal('permerror');
        });

        it('Should count ptr terms together with other DNS terms', async () => {
            const terms = Array.from({ length: 9 }, (_, i) => `ptr:d${i}.example.test`).join(' ');
            const res = await check(
                {},
                record(`v=spf1 ${terms} exists:x.example.test exists:y.example.test -all`, {
                    '1.2.0.192.in-addr.arpa': { PTR: ['mail.other.test'] },
                    'mail.other.test': { A: ['192.0.2.1'] },
                    'x.example.test': { AAAA: ['2001:db8::1'] },
                    'y.example.test': { A: ['127.0.0.2'] }
                })
            );
            expect(res.status.result).to.equal('permerror');
        });

        it('Should bound the DNS queries of a record with many ptr terms', async () => {
            const ptrNames = Array.from({ length: 10 }, (_, i) => `h${i}.attacker.test`);
            const zone = {
                'attacker.test': { TXT: [['v=spf1', ...Array(1000).fill(' ptr'), ' -all']] },
                '1.2.0.192.in-addr.arpa': { PTR: ptrNames }
            };
            for (const name of ptrNames) {
                zone[name] = { A: ['198.51.100.9'] };
            }
            const log = [];
            const res = await check({ sender: 'user@attacker.test' }, zone, log);
            expect(res.status.result).to.equal('permerror');
            expect(res.lookups.count).to.equal(11);
            // 1 TXT query, 10 PTR queries and at most 10 address queries for each PTR query
            expect(log.length).to.be.at.most(111);
        });

        it('Should count the PTR query of a %{p} expansion', async () => {
            const terms = Array.from({ length: 6 }, (_, i) => `exists:%{p}.e${i}.example.test`).join(' ');
            const zone = record(`v=spf1 ${terms} -all`, {
                '1.2.0.192.in-addr.arpa': { PTR: ['mx.example.test'] },
                'mx.example.test': { A: ['192.0.2.1'] }
            });
            for (let i = 0; i < 6; i++) {
                // an empty answer, neither a match nor a void lookup
                zone[`mx.example.test.e${i}.example.test`] = { A: [] };
            }
            // every exists term is one lookup and every %{p} is one more
            const res = await check({}, zone);
            expect(res.status.result).to.equal('permerror');
            expect(res.status.comment).to.include('Too many DNS requests');

            // 5 terms with %{p} stay within the limit
            zone['example.test'].TXT = ['v=spf1 ' + terms.split(' ').slice(0, 5).join(' ') + ' -all'];
            const underLimit = await check({}, zone);
            expect(underLimit.status.result).to.equal('fail');
            expect(underLimit.lookups.count).to.equal(10);
        });
    });

    describe('%{p} macro (RFC 7208 7.3)', () => {
        it('Should expand to "unknown" when there is no validated name', async () => {
            const { lax, strict } = await both(
                { sender: 'user@partner.test' },
                {
                    'partner.test': { TXT: ['v=spf1 include:example.test -all'] },
                    'example.test': { TXT: ['v=spf1 exists:%{p}.trusted.example.test -all'] },
                    'partner.test.trusted.example.test': { A: ['127.0.0.2'] },
                    'unknown.trusted.example.test': { AAAA: ['2001:db8::1'] }
                }
            );
            expect(lax.status.result).to.equal('fail');
            expect(strict.status.result).to.equal('fail');
        });

        it('Should expand to a validated name, preferring a subdomain of <domain>', async () => {
            const log = [];
            const res = await check(
                {},
                record('v=spf1 exists:%{p}.allow.example.test -all', {
                    '1.2.0.192.in-addr.arpa': { PTR: ['mx.other.test', 'mx.example.test'] },
                    'mx.other.test': { A: ['192.0.2.1'] },
                    'mx.example.test': { A: ['192.0.2.1'] },
                    'mx.example.test.allow.example.test': { A: ['127.0.0.2'] }
                }),
                log
            );
            expect(res.status.result).to.equal('pass');
            expect(log).to.include('A mx.example.test.allow.example.test');
        });

        it('Should not use a PTR name that does not validate', async () => {
            const res = await check(
                {},
                record('v=spf1 exists:%{p}.allow.example.test -all', {
                    '1.2.0.192.in-addr.arpa': { PTR: ['mx.example.test'] },
                    'mx.example.test': { A: ['192.0.2.99'] },
                    'mx.example.test.allow.example.test': { A: ['127.0.0.2'] }
                })
            );
            expect(res.status.result).to.equal('fail');
        });

        it('Should render "unknown" in macro() without a validated name', async () => {
            expect(macro('%{p}', { sender: 'user@example.com', ip: '192.0.2.3' })).to.equal('unknown');
            expect(macro('%{p}', { sender: 'user@example.com', ip: '192.0.2.3', p: 'mx.example.org' })).to.equal('mx.example.org');
        });
    });

    describe('Syntax validation (RFC 7208 4.6)', () => {
        const invalidRecords = [
            'v=spf1 -all ip6',
            'v=spf1 -all ip4:999.0.0.1',
            'v=spf1 ip4:192.0.2.1 ip4:192.0.2.300 -all',
            'v=spf1 ip4:192.0.2.1 a:example.test/99 -all',
            'v=spf1 ip4:192.0.2.1 exists:%{z}.example.test -all',
            'v=spf1 ip4:192.0.2.1 include: -all',
            'v=spf1 ip4:192.0.2.1 ptr/24 -all',
            'v=spf1 ip4:192.0.2.1 all:foo',
            'v=spf1 ip4:192.0.2.1 exists:%{d0}.example.test -all',
            'v=spf1 ip4:192.0.2.1 exists:%{d2x}.example.test -all',
            'v=spf1 ip4:192.0.2.1 exists:%{dr2}.example.test -all',
            'v=spf1 ip4:192.0.2.1 exists:%{c}.example.test -all',
            'v=spf1 ip4:192.0.2.1 a:%{t} -all',
            'v=spf1 ip4:192.0.2.1 a:localhost -all',
            'v=spf1 ip4:192.0.2.1 a$b=c -all',
            'v=spf1 ip4:192.0.2.1 exp=a.example.test exp=b.example.test'
        ];

        for (const txt of invalidRecords) {
            it(`Should return permerror in strict mode and keep the lazy result by default for "${txt}"`, async () => {
                const { lax, strict } = await both({}, record(txt));
                expect(strict.status.result).to.equal('permerror');
                expect(strict.warnings).to.not.exist;
                expect(lax.status.result).to.be.oneOf(['pass', 'fail']);
                expect(lax.warnings).to.deep.equal(['syntax-error']);
            });
        }

        it('Should not add warnings for a valid record', async () => {
            const { lax, strict } = await both(
                {},
                record('v=spf1 ip4:192.0.2.0/24 a:%{d} mx/24//64 exists:%{ir}.%{l1r+-}._spf.%{d} ptr:example.test -all exp=exp.%{d}')
            );
            expect(lax.status.result).to.equal('pass');
            expect(lax.warnings).to.not.exist;
            expect(strict.status.result).to.equal('pass');
        });

        it('Should keep a syntax error before the matching term a permerror in both modes', async () => {
            const { lax, strict } = await both({}, record('v=spf1 ip4:192.0.2.300 ip4:192.0.2.1 -all'));
            expect(lax.status.result).to.equal('permerror');
            expect(strict.status.result).to.equal('permerror');
        });
    });

    describe('Modifiers (RFC 7208 6)', () => {
        it('Should accept an unknown modifier with an empty value', async () => {
            const { lax, strict } = await both({}, record('v=spf1 foo= -all'));
            expect(lax.status.result).to.equal('fail');
            expect(lax.warnings).to.not.exist;
            expect(strict.status.result).to.equal('fail');
        });

        it('Should still reject an empty redirect or exp value', async () => {
            for (const txt of ['v=spf1 ?all redirect=', 'v=spf1 exp= -all']) {
                const { lax, strict } = await both({}, record(txt));
                expect(lax.status.result).to.equal('permerror');
                expect(strict.status.result).to.equal('permerror');
            }
        });

        it('Should treat the redirect target case-insensitively', async () => {
            const { lax, strict } = await both({}, record('v=spf1 redirect=_spf.Example.TEST', { '_spf.example.test': { TXT: ['v=spf1 -all'] } }));
            expect(lax.status.result).to.equal('fail');
            expect(strict.status.result).to.equal('fail');
        });

        it('Should accept an uppercase sender domain in a redirect target', async () => {
            const { lax, strict } = await both(
                { sender: 'user@EXAMPLE.TEST' },
                record('v=spf1 redirect=_spf.%{o}', { '_spf.example.test': { TXT: ['v=spf1 ip4:192.0.2.1 -all'] } })
            );
            expect(lax.status.result).to.equal('pass');
            expect(strict.status.result).to.equal('pass');
        });
    });

    describe('Trailing dots (RFC 7208 7.3)', () => {
        const zone = txt =>
            record(txt, {
                'host.example.test': { A: ['192.0.2.1'] },
                'mxd.example.test': { MX: [{ priority: 10, exchange: 'host.example.test.' }] },
                '_spf.example.test': { TXT: ['v=spf1 ip4:192.0.2.1 -all'] },
                '1.2.0.192.in-addr.arpa': { PTR: ['host.example.test'] }
            });

        for (const txt of [
            'v=spf1 a:host.example.test. -all',
            'v=spf1 a:host.example.test./24 -all',
            'v=spf1 mx:mxd.example.test. -all',
            'v=spf1 exists:host.example.test. -all',
            'v=spf1 ptr:example.test. -all',
            'v=spf1 include:_spf.example.test. -all',
            'v=spf1 redirect=_spf.example.test.'
        ]) {
            it(`Should accept "${txt}"`, async () => {
                const { lax, strict } = await both({}, zone(txt));
                expect(lax.status.result).to.equal('pass');
                expect(strict.status.result).to.equal('pass');
            });
        }

        it('Should skip a null MX', async () => {
            const { lax, strict } = await both(
                {},
                record('v=spf1 mx ip4:192.0.2.1 -all', { 'example.test': { TXT: ['v=spf1 mx ip4:192.0.2.1 -all'], MX: [{ priority: 0, exchange: '.' }] } })
            );
            expect(lax.status.result).to.equal('pass');
            expect(strict.status.result).to.equal('pass');
        });
    });

    describe('PTR DNS errors (RFC 7208 5.5)', () => {
        for (const code of ['ESERVFAIL', 'ETIMEOUT', 'EREFUSED']) {
            it(`Should not match the ptr mechanism on ${code} and continue`, async () => {
                const { lax, strict } = await both({}, record('v=spf1 ptr ip4:192.0.2.1 -all', { '1.2.0.192.in-addr.arpa': { PTR: code } }));
                expect(lax.status.result).to.equal('pass');
                expect(strict.status.result).to.equal('pass');
            });
        }

        it('Should skip a PTR name whose address lookup fails', async () => {
            const res = await check(
                {},
                {
                    'example.test': { TXT: ['v=spf1 ptr -all'] },
                    '1.2.0.192.in-addr.arpa': { PTR: ['bad.example.test', 'mail.example.test'] },
                    'bad.example.test': { A: 'ESERVFAIL' },
                    'mail.example.test': { A: ['192.0.2.1'] }
                }
            );
            expect(res.status.result).to.equal('pass');
        });
    });

    describe('Internationalized sender (RFC 8616 4)', () => {
        it('Should convert a U-label MAIL FROM domain to A-labels', async () => {
            const log = [];
            const res = await check({ sender: 'user@bücher.example' }, { 'xn--bcher-kva.example': { TXT: ['v=spf1 ip4:192.0.2.1 -all'] } }, log);
            expect(res.status.result).to.equal('pass');
            expect(res.domain).to.equal('xn--bcher-kva.example');
            expect(log[0]).to.equal('TXT xn--bcher-kva.example');
            // the report keeps the address as it was given
            expect(res.status.smtp.mailfrom).to.equal('user@bücher.example');
        });

        it('Should use the A-label domain in %{o}', async () => {
            const res = await check(
                { sender: 'user@BÜCHER.example' },
                {
                    'xn--bcher-kva.example': { TXT: ['v=spf1 exists:%{o}.allow.example.test -all'] },
                    'xn--bcher-kva.example.allow.example.test': { A: ['127.0.0.2'] }
                }
            );
            expect(res.status.result).to.equal('pass');
        });

        it('Should not match a %{l} term with a non-ASCII local-part in strict mode', async () => {
            const { lax, strict } = await both(
                { sender: 'üser@example.test' },
                record('v=spf1 exists:%{l}.users.example.test -all', { 'xn--ser-goa.users.example.test': { A: ['127.0.0.2'] } })
            );
            expect(lax.status.result).to.equal('pass');
            expect(lax.warnings).to.deep.equal(['non-ascii-local-part']);
            expect(strict.status.result).to.equal('fail');
        });

        it('Should not match an include with %{s} and a non-ASCII local-part in strict mode', async () => {
            const { lax, strict } = await both({ sender: 'üser@example.test' }, record('v=spf1 include:%{s}.users.example.test ip4:192.0.2.1 -all'));
            expect(strict.status.result).to.equal('pass');
            // the default mode keeps the old result, the expanded name is not a valid DNS name
            expect(lax.status.result).to.equal('permerror');
        });
    });

    describe('Long names (RFC 7208 7.3)', () => {
        it('Should truncate names over 253 characters from the left', async () => {
            const local = Array.from({ length: 5 }, (_, i) => String(i).repeat(60)).join('.');
            const log = [];
            const res = await check({ sender: `${local}@example.test` }, record('v=spf1 exists:%{l}._spf.example.test -all'), log);
            expect(res.status.result).to.equal('fail');
            const query = log[1].replace(/^A /, '');
            expect(query.length).to.be.at.most(253);
            expect(query).to.equal(`${'2'.repeat(60)}.${'3'.repeat(60)}.${'4'.repeat(60)}._spf.example.test`);
        });
    });

    describe('Invalid names after macro expansion (RFC 7208 4.8)', () => {
        it('Should not query a name with a label over 63 characters in strict mode', async () => {
            const local = 'a'.repeat(64);
            const log = [];
            const res = await check({ sender: `${local}@example.test`, strict: true }, record('v=spf1 exists:%{l}.users.example.test -all'), log);
            expect(res.status.result).to.equal('fail');
            expect(log).to.deep.equal(['TXT example.test']);
        });

        it('Should give permerror for an EBADNAME resolver error in the default mode', async () => {
            const res = await check({}, record('v=spf1 exists:bad.example.test -all', { 'bad.example.test': { A: 'EBADNAME' } }));
            expect(res.status.result).to.equal('permerror');
            expect(res.status.comment).to.include('Invalid domain bad.example.test');
        });
    });

    describe('Uppercase macros (RFC 7208 7.3)', () => {
        it('Should URL escape uppercase macros', async () => {
            const values = { sender: 'foo+bar@email.example.com', ip: '192.0.2.3', helo: 'mx.example.org', domain: 'email.example.com' };
            expect(macro('%{L}', values)).to.equal('foo%2Bbar');
            expect(macro('%{S}', values)).to.equal('foo%2Bbar%40email.example.com');
            expect(macro('%{l}', values)).to.equal('foo+bar');
            expect(macro('%{L}', { sender: '~jack&jill=up-a_b3.c@e8.example.com' })).to.equal('~jack%26jill%3Dup-a_b3.c');
            expect(macro('%{L}', { sender: 'üser@example.com' })).to.equal('%C3%BCser');
        });

        it('Should read "R" as the reverse transformer', async () => {
            const values = { sender: 'strong-bad@email.example.com', domain: 'email.example.com' };
            expect(macro('%{dR}', values)).to.equal('com.example.email');
            expect(macro('%{d2R}', values)).to.equal('example.email');
        });

        it('Should query the escaped name', async () => {
            const log = [];
            const res = await check(
                { sender: 'foo+bar@example.test' },
                record('v=spf1 exists:%{L}.users.example.test -all', { 'foo%2bbar.users.example.test': { A: ['127.0.0.2'] } }),
                log
            );
            expect(res.status.result).to.equal('pass');
            expect(log).to.include('A foo%2Bbar.users.example.test');
        });

        it('Should keep the lenient transformer handling by default', async () => {
            const values = { sender: 'strong-bad@email.example.com', domain: 'email.example.com' };
            expect(macro('%{d0}', values)).to.equal('email.example.com');
            expect(macro('%{d2x}', values)).to.equal('example.com');
            expect(macro('%{dr2}', values)).to.equal('com.example.email');
        });
    });

    describe('Quoted local-part with "@" (RFC 5321 4.1.2)', () => {
        it('Should split the sender at the last "@"', async () => {
            expect(macro('%{l}|%{o}', { sender: '"a@b"@example.com' })).to.equal('"a@b"|example.com');

            const log = [];
            const res = await check(
                { sender: '"a@b"@example.test' },
                record('v=spf1 exists:%{o}.chk.example.test -all', { 'example.test.chk.example.test': { A: ['127.0.0.2'] } }),
                log
            );
            expect(res.status.result).to.equal('pass');
            expect(res.domain).to.equal('example.test');
        });
    });

    describe('Client IP address (RFC 7208 4.1, 5)', () => {
        for (const ip of ['::ffff:c000:201', '::FFFF:192.0.2.1', '::ffff:192.0.2.1']) {
            it(`Should treat the IPv4-mapped address ${ip} as IPv4`, async () => {
                const { lax, strict } = await both({ ip }, record('v=spf1 ip4:192.0.2.1 -all'));
                expect(lax.status.result).to.equal('pass');
                expect(lax['client-ip']).to.equal('192.0.2.1');
                expect(strict.status.result).to.equal('pass');
            });
        }

        for (const ip of ['fdaa:bbcc::dd:192.0.2.1', '::abcd:192.0.2.1', '::192.0.2.1']) {
            it(`Should not convert the non-mapped address ${ip} to IPv4`, async () => {
                const { lax, strict } = await both({ ip }, record('v=spf1 ip4:192.0.2.1 -all'));
                expect(lax.status.result).to.equal('fail');
                expect(lax['client-ip']).to.equal(ip);
                expect(strict.status.result).to.equal('fail');
            });
        }

        it('Should match an IPv4-compatible network in ip6 exactly', async () => {
            // ::192.0.2.1 is ::c000:201, not ::ffff:c000:201
            const { lax, strict } = await both({ ip: '::c000:201' }, record('v=spf1 ip6:::192.0.2.1 -all'));
            expect(lax.status.result).to.equal('pass');
            expect(strict.status.result).to.equal('pass');
        });

        for (const ip of [undefined, '', 'not-an-ip', '192.0.2', '127.1']) {
            it(`Should return temperror for the client IP ${JSON.stringify(ip)}`, async () => {
                const { lax, strict } = await both({ ip }, record('v=spf1 ip4:192.0.2.1 -all'));
                expect(lax.status.result).to.equal('temperror');
                expect(lax.status.comment).to.equal(
                    'mx.receiver.test: error in processing during lookup of user@example.test: missing or invalid client IP address'
                );
                expect(lax.header).to.not.include('client-ip');
                expect(strict.status.result).to.equal('temperror');
            });
        }
    });

    describe('ip4 and ip6 mechanisms (RFC 7208 5.6)', () => {
        it('Should accept an IPv4-mapped ip6 network with a prefix length', async () => {
            const { lax, strict } = await both({}, record('v=spf1 ip6:::ffff:192.0.2.0/120 -all'));
            expect(lax.status.result).to.equal('fail');
            expect(strict.status.result).to.equal('fail');
        });

        it('Should match IPv6 clients with an embedded IPv4 ip6 network', async () => {
            const { lax, strict } = await both({ ip: '2001:db8::102:304' }, record('v=spf1 ip6:2001:db8::1.2.3.4 -all'));
            expect(lax.status.result).to.equal('pass');
            expect(strict.status.result).to.equal('pass');
        });

        it('Should match every IPv6 client with a /0 ip6 network and never an IPv4 client', async () => {
            let res = await both({ ip: '2001:db8::1' }, record('v=spf1 ip6:::1.1.1.1/0 -all'));
            expect(res.lax.status.result).to.equal('pass');
            expect(res.strict.status.result).to.equal('pass');
            res = await both({ ip: '192.0.2.1' }, record('v=spf1 ip6:::1.1.1.1/0 -all'));
            expect(res.lax.status.result).to.equal('fail');
            expect(res.strict.status.result).to.equal('fail');
        });

        for (const [txt, ip, laxResult] of [
            ['v=spf1 ip4:2001:db8::1 -all', '192.0.2.1', 'fail'],
            ['v=spf1 ip6:192.0.2.1 -all', '192.0.2.1', 'fail'],
            ['v=spf1 ip6:2001:db8::/32//64 -all', '2001:db8::1', 'pass'],
            ['v=spf1 ip4:192.0.2.0/00 +all', '192.0.2.1', 'pass']
        ]) {
            it(`Should return permerror for "${txt}" in strict mode only`, async () => {
                const { lax, strict } = await both({ ip }, record(txt));
                expect(lax.status.result).to.equal(laxResult);
                expect(lax.warnings).to.deep.equal(['syntax-error']);
                expect(strict.status.result).to.equal('permerror');
            });
        }
    });

    describe('Void lookups (RFC 7208 4.6.4)', () => {
        it('Should not count address lookups of MX hosts as void lookups', async () => {
            const { lax, strict } = await both(
                {},
                {
                    'example.test': {
                        TXT: ['v=spf1 mx -all'],
                        MX: [
                            { priority: 1, exchange: 'dead1.example.test' },
                            { priority: 2, exchange: 'dead2.example.test' },
                            { priority: 3, exchange: 'dead3.example.test' },
                            { priority: 4, exchange: 'live.example.test' }
                        ]
                    },
                    'live.example.test': { A: ['192.0.2.1'] }
                }
            );
            expect(lax.status.result).to.equal('pass');
            expect(strict.status.result).to.equal('pass');
            expect(lax.lookups.void).to.equal(0);
            expect(lax.lookups.subqueries['mx:void']).to.equal(3);
        });

        it('Should count a NODATA answer for the client address type as void in strict mode', async () => {
            const { lax, strict } = await both(
                {},
                record('v=spf1 a:v6only1.example.test a:v6only2.example.test a:v6only3.example.test -all', {
                    'v6only1.example.test': { AAAA: ['2001:db8::1'] },
                    'v6only2.example.test': { AAAA: ['2001:db8::2'] },
                    'v6only3.example.test': { AAAA: ['2001:db8::3'] }
                })
            );
            expect(lax.status.result).to.equal('fail');
            expect(lax.warnings).to.deep.equal(['void-lookup-limit']);
            expect(strict.status.result).to.equal('permerror');
            expect(strict.status.comment).to.include('Too many void DNS results');
        });

        it('Should send a repeated query once but count it every time', async () => {
            for (let strict of [false, true]) {
                const log = [];
                const res = await check(
                    { strict },
                    record('v=spf1 a:gone.example.test a:gone.example.test a:gone.example.test -all', {
                        'gone.example.test': { MX: [] }
                    }),
                    log
                );
                expect(res.status.result).to.equal('permerror');
                expect(res.status.comment).to.include('Too many void DNS results');
                expect(res.lookups.count).to.equal(3);
                expect(res.lookups.void).to.equal(3);
                expect(log.filter(entry => entry === 'A gone.example.test')).to.have.lengthOf(1);
            }
        });

        it('Should not warn below the void limit', async () => {
            const lax = await check(
                {},
                record('v=spf1 a:v6only1.example.test a:v6only2.example.test -all', {
                    'v6only1.example.test': { AAAA: ['2001:db8::1'] },
                    'v6only2.example.test': { AAAA: ['2001:db8::2'] }
                })
            );
            expect(lax.status.result).to.equal('fail');
            expect(lax.warnings).to.not.exist;
        });
    });

    describe('Record selection (RFC 7208 4.5)', () => {
        it('Should discard a record with leading whitespace in strict mode', async () => {
            const { lax, strict } = await both({}, record(' v=spf1 -all'));
            expect(lax.status.result).to.equal('fail');
            expect(lax.warnings).to.deep.equal(['syntax-error']);
            expect(strict.status.result).to.equal('none');
        });

        it('Should discard a record whose version is not followed by SP in strict mode', async () => {
            const { lax, strict } = await both({}, record('v=spf1\t-all'));
            expect(lax.status.result).to.equal('permerror');
            expect(strict.status.result).to.equal('none');
        });

        it('Should accept several spaces between terms and trailing spaces', async () => {
            const { lax, strict } = await both({}, record('v=spf1  ip4:192.0.2.9   -all  '));
            expect(lax.status.result).to.equal('fail');
            expect(lax.warnings).to.not.exist;
            expect(strict.status.result).to.equal('fail');
        });
    });

    describe('Received-SPF header (RFC 7208 9.1)', () => {
        const zone = record('v=spf1 ip6:2001:db8::/32 ip4:192.0.2.1 -all');

        it('Should include client-ip, envelope-from and helo', async () => {
            const res = await check({}, zone);
            expect(res.header).to.equal(
                'Received-SPF: pass (mx.receiver.test: domain of user@example.test designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1;\r\n' +
                    ' envelope-from="user@example.test"; helo=mail.example.test;'
            );
        });

        it('Should quote an IPv6 client-ip', async () => {
            const res = await check({ ip: '2001:db8::1' }, zone);
            expect(res.status.result).to.equal('pass');
            expect(res.header.replace(/\r\n/g, '')).to.include(' client-ip="2001:db8::1";');
        });

        it('Should quote a HELO address literal and omit envelope-from for a null sender', async () => {
            const res = await check({ sender: '', helo: '[192.0.2.1]' }, zone);
            expect(res.header.replace(/\r\n/g, '')).to.match(/ client-ip=192\.0\.2\.1; helo="\[192\.0\.2\.1\]";$/);
            expect(res.header).to.not.include('envelope-from');
        });

        it('Should escape quotes and remove line breaks in values', async () => {
            const res = await check({ sender: '"a\\"b"@example.test', helo: 'bad\r\nX-Injected: 1' }, zone);
            const unfolded = res.header.replace(/\r\n /g, ' ');
            expect(unfolded).to.not.match(/\r|\n/);
            expect(unfolded).to.include('envelope-from="\\"a\\\\\\"b\\"@example.test";');
            expect(unfolded).to.include('helo="bad X-Injected: 1";');
        });
    });

    describe('Authentication-Results ptypes (RFC 8601 2.7.2)', () => {
        const zone = record('v=spf1 ip4:192.0.2.1 -all');

        it('Should keep both identities by default', async () => {
            const res = await check({}, zone);
            expect(res.info).to.equal(
                'spf=pass (mx.receiver.test: domain of user@example.test designates 192.0.2.1 as permitted sender) smtp.mailfrom=user@example.test smtp.helo=mail.example.test'
            );
        });

        it('Should report only the MAIL FROM domain in strict mode', async () => {
            const res = await check({ strict: true }, zone);
            expect(res.info).to.equal(
                'spf=pass (mx.receiver.test: domain of user@example.test designates 192.0.2.1 as permitted sender) smtp.mailfrom=example.test'
            );
        });

        it('Should report the local-part in strict mode when the policy uses it', async () => {
            const res = await check(
                { strict: true },
                record('v=spf1 exists:%{l}.users.example.test -all', { 'user.users.example.test': { A: ['127.0.0.2'] } })
            );
            expect(res.status.result).to.equal('pass');
            expect(res.status.smtp).to.deep.equal({ mailfrom: 'user@example.test' });
        });

        it('Should quote only the local-part of smtp.mailfrom in strict mode', async () => {
            // the exists term makes the policy use the local-part, the ip4 term passes it
            const policy = record('v=spf1 exists:%{l}.users.example.test ip4:192.0.2.1 -all');

            const strict = await check({ strict: true, sender: 'a b@example.test' }, policy);
            expect(strict.status.result).to.equal('pass');
            expect(strict.status.smtp).to.deep.equal({ mailfrom: 'a b@example.test' });
            expect(strict.info).to.include(' smtp.mailfrom="a b"@example.test');

            // the lenient output is unchanged, the identity is quoted as a whole
            const lax = await check({ sender: 'a b@example.test' }, policy);
            expect(lax.info).to.include(' smtp.mailfrom="a b@example.test"');
        });

        it('Should report only the HELO identity in strict mode for a null sender', async () => {
            const res = await check({ strict: true, sender: '', helo: 'example.test' }, zone);
            expect(res.status.result).to.equal('pass');
            expect(res.info).to.equal(
                'spf=pass (mx.receiver.test: domain of postmaster@example.test designates 192.0.2.1 as permitted sender) smtp.helo=example.test'
            );
        });
    });

    describe('Time limit (RFC 7208 4.6.4)', () => {
        const slowResolver = delay => async (name, type) => {
            await new Promise(resolve => setTimeout(resolve, delay));
            if (name === 'example.test' && type === 'TXT') {
                return [['v=spf1 ' + Array.from({ length: 10 }, (_, i) => `exists:e${i}.example.test`).join(' ') + ' -all']];
            }
            return [];
        };

        it('Should return temperror when maxElapsedTime is exceeded', async () => {
            const start = Date.now();
            const res = await spf({ sender: 'user@example.test', ip: '192.0.2.1', helo: 'h', mta: 'mx', resolver: slowResolver(40), maxElapsedTime: 100 });
            expect(res.status.result).to.equal('temperror');
            expect(res.status.comment).to.include('SPF evaluation time limit exceeded');
            expect(Date.now() - start).to.be.below(400);
        });

        it('Should return temperror when a DNS query never completes', async () => {
            const res = await spf({
                sender: 'user@example.test',
                ip: '192.0.2.1',
                helo: 'h',
                mta: 'mx',
                resolver: () => new Promise(() => false),
                maxElapsedTime: 50
            });
            expect(res.status.result).to.equal('temperror');
        });

        it('Should not limit the time by default', async () => {
            const res = await spf({ sender: 'user@example.test', ip: '192.0.2.1', helo: 'h', mta: 'mx', resolver: slowResolver(15) });
            expect(res.status.result).to.equal('fail');
        });
    });

    describe('Explanation (RFC 7208 6.2)', () => {
        it('Should compute the explanation for a fail result', async () => {
            const { lax, strict } = await both(
                {},
                record('v=spf1 -all exp=explain._spf.%{d}', { 'explain._spf.example.test': { TXT: ["%{i} is not one of %{d}'s designated mail servers."] } })
            );
            for (const res of [lax, strict]) {
                expect(res.status.result).to.equal('fail');
                expect(res.explanation).to.equal("192.0.2.1 is not one of example.test's designated mail servers.");
            }
            // the explanation is not part of the generated headers
            expect(lax.header).to.not.include('designated mail servers');
            expect(lax.info).to.not.include('designated mail servers');
        });

        it('Should allow c, r and t in the explanation text', async () => {
            const res = await check({}, record('v=spf1 -all exp=explain.example.test', { 'explain.example.test': { TXT: ['%{c} rejected by %{r}'] } }));
            expect(res.explanation).to.equal('192.0.2.1 rejected by mx.receiver.test');
        });

        it('Should not set an explanation for other results', async () => {
            const res = await check({}, record('v=spf1 ~all exp=explain.example.test', { 'explain.example.test': { TXT: ['nope'] } }));
            expect(res.status.result).to.equal('softfail');
            expect(res.explanation).to.not.exist;
        });

        it('Should ignore the explanation of an included record and use the one of a redirect target', async () => {
            let res = await check(
                {},
                record('v=spf1 include:inc.example.test -all exp=outer.example.test', {
                    'inc.example.test': { TXT: ['v=spf1 -all exp=inner.example.test'] },
                    'outer.example.test': { TXT: ['outer'] },
                    'inner.example.test': { TXT: ['inner'] }
                })
            );
            expect(res.explanation).to.equal('outer');

            res = await check(
                {},
                record('v=spf1 exp=outer.example.test redirect=r.example.test', {
                    'r.example.test': { TXT: ['v=spf1 -all exp=inner.example.test'] },
                    'outer.example.test': { TXT: ['outer'] },
                    'inner.example.test': { TXT: ['inner'] }
                })
            );
            expect(res.explanation).to.equal('inner');
        });

        for (const [label, extra] of [
            ['a DNS error', { 'explain.example.test': { TXT: 'ETIMEOUT' } }],
            ['no TXT record', {}],
            ['two TXT records', { 'explain.example.test': { TXT: ['one', 'two'] } }],
            ['a syntax error', { 'explain.example.test': { TXT: ['The %{x}-files.'] } }],
            ['non-ASCII text', { 'explain.example.test': { TXT: ['ï»¿Explanation'] } }]
        ]) {
            it(`Should ignore the explanation on ${label}`, async () => {
                const res = await check({}, record('v=spf1 -all exp=explain.example.test', extra));
                expect(res.status.result).to.equal('fail');
                expect(res.explanation).to.not.exist;
                expect(res.lookups.void).to.equal(0);
            });
        }
    });
});
