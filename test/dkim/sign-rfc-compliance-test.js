/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const fs = require('node:fs');
const chai = require('chai');
const expect = chai.expect;

const { dkimSign, DkimSignStream } = require('../../lib/dkim/sign');
const { dkimVerify } = require('../../lib/dkim/verify');
const { DkimSigner } = require('../../lib/dkim/dkim-signer');
const { relaxedHeaders } = require('../../lib/dkim/header/relaxed');
const { simpleHeaders } = require('../../lib/dkim/header/simple');
const { sealMessage, createSeal } = require('../../lib/mailauth');
const { verify: referenceVerify, parseTagList, resolverFrom, spkiB64 } = require('../helpers/dkim-reference');

chai.config.includeStack = true;

const fixture = file => fs.readFileSync(`${__dirname}/../fixtures/${file}`);

const RSA = fixture('private-rsa.pem');
const RSA_PUBLIC = crypto.createPublicKey(crypto.createPrivateKey(RSA));
const SMALL = fixture('private-small.pem');
const SMALL_PUBLIC = crypto.createPublicKey(crypto.createPrivateKey(SMALL));
const ED = fixture('private-ed25519.pem');
const ED_PUBLIC = crypto.createPublicKey(crypto.createPrivateKey(ED));

const MSG = 'From: Andris <andris@example.com>\r\nTo: x@example.net\r\nSubject: test\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\n\r\nHello world\r\n';

const base = extra => Object.assign({ signingDomain: 'example.com', selector: 's', privateKey: RSA }, extra || {});

const tagsOf = signatures => parseTagList(signatures.slice(signatures.indexOf(':') + 1).replace(/\r\n$/, '')).tags;

const signMessage = async (options, msg = MSG) => {
    const result = await dkimSign(Buffer.from(msg, 'binary'), options);
    return Object.assign(result, { out: result.signatures + msg });
};

const errorCodes = result => result.errors.map(e => e.err.code);

describe('DKIM signing RFC compliance', () => {
    describe('Failed signing output', () => {
        const bad = { signatureData: [base({ algorithm: 'rsa-sha512' })] };

        it('Should return an empty signatures string when no signature was created', async () => {
            const result = await signMessage(bad);
            expect(result.errors).to.have.lengthOf(1);
            expect(result.signatures).to.equal('');

            const noFrom = await signMessage({ signatureData: [base()] }, 'Subject: s\r\n\r\nbody\r\n');
            expect(errorCodes(noFrom)).to.deep.equal(['ENOFROM']);
            expect(noFrom.signatures).to.equal('');
        });

        it('Should report a signature that has no private key', async () => {
            for (let privateKey of [undefined, null, '']) {
                const result = await signMessage({ signatureData: [base({ privateKey })] });
                expect(errorCodes(result)).to.deep.equal(['ENOKEY']);
                expect(result.errors[0]).to.include({ type: 'DKIM', signingDomain: 'example.com', selector: 's' });
                expect(result.signatures).to.equal('');
            }

            // the other signatures are still created
            const result = await signMessage({ signatureData: [base({ privateKey: process.env.MAILAUTH_UNSET_KEY }), base({ selector: 't' })] });
            expect(errorCodes(result)).to.deep.equal(['ENOKEY']);
            expect(tagsOf(result.signatures).s).to.equal('t');
            expect(referenceVerify(result.out, RSA_PUBLIC).ok).to.be.true;
        });

        it('Should report that no signature was configured', async () => {
            for (let options of [
                // the signing values are only read from signatureData
                { signingDomain: 'example.com', selector: 's', privateKey: RSA },
                { signatureData: [] },
                {},
                undefined
            ]) {
                const result = await signMessage(options);
                expect(errorCodes(result)).to.deep.equal(['ENOSIGNATURE']);
                expect(result.signatures).to.equal('');
            }
        });

        it('Should report an ARC signature that has no private key', async () => {
            const result = await signMessage({ signatureData: [base()], arc: { signingDomain: 'example.com', selector: 's' } });
            expect(result.errors).to.have.lengthOf(1);
            expect(result.errors[0]).to.include({ type: 'ARC', signingDomain: 'example.com' });
            expect(result.errors[0].err.code).to.equal('ENOKEY');
            expect(result.arc.messageSignature).to.be.undefined;
            expect(referenceVerify(result.out, RSA_PUBLIC).ok).to.be.true;

            const sealed = await createSeal(false, {
                headers: { parsed: [], original: Buffer.from('From: a@example.com\r\n') },
                seal: { signingDomain: 'example.com', selector: 's', authResults: 'mx.example.com; none', cv: 'none' }
            });
            expect(sealed.headers).to.deep.equal([]);
            expect(sealed.errors.map(e => e.err.code)).to.include('ENOKEY');
        });

        it('Should not prepend an empty line in DkimSignStream when no signature was created', async () => {
            const stream = new DkimSignStream(bad);
            const chunks = [];
            stream.on('data', chunk => chunks.push(chunk));
            await new Promise((resolve, reject) => {
                stream.on('end', resolve);
                stream.on('error', reject);
                stream.end(MSG);
            });

            expect(stream.errors).to.have.lengthOf(1);
            // the message goes out as it came in, a leading CRLF would end the header section
            expect(Buffer.concat(chunks).toString()).to.equal(MSG);
        });

        it('Should still prepend the signature in DkimSignStream', async () => {
            const stream = new DkimSignStream({ signatureData: [base()] });
            const chunks = [];
            stream.on('data', chunk => chunks.push(chunk));
            await new Promise(resolve => {
                stream.on('end', resolve);
                stream.end(MSG);
            });
            const out = Buffer.concat(chunks).toString('binary');
            expect(out).to.match(/^DKIM-Signature: /);
            expect(out.endsWith(MSG)).to.be.true;
            expect(referenceVerify(out, RSA_PUBLIC).ok).to.be.true;
        });
    });

    describe('Weak algorithms and keys (RFC 8301)', () => {
        it('Should sign with rsa-sha1 by default, with a warning', async () => {
            const result = await signMessage({ signatureData: [base({ algorithm: 'rsa-sha1' })] });
            expect(result.errors).to.deep.equal([]);
            expect(result.warnings).to.deep.equal(['rsa-sha1']);
            expect(tagsOf(result.signatures).a).to.equal('rsa-sha1');
        });

        it('Should refuse to sign with rsa-sha1 in strict mode', async () => {
            const result = await signMessage({ strict: true, signatureData: [base({ algorithm: 'rsa-sha1' })] });
            expect(result.signatures).to.equal('');
            expect(errorCodes(result)).to.deep.equal(['EINVALIDALGO']);
        });

        it('Should sign with an RSA key under 1024 bits by default, with a warning', async () => {
            const result = await signMessage({ signatureData: [base({ privateKey: SMALL })] });
            expect(result.errors).to.deep.equal([]);
            expect(result.warnings).to.deep.equal(['weak-key']);
            expect(referenceVerify(result.out, SMALL_PUBLIC).sigOk).to.be.true;
        });

        it('Should refuse to sign with an RSA key under 1024 bits in strict mode', async () => {
            const result = await signMessage({ strict: true, signatureData: [base({ privateKey: SMALL })] });
            expect(result.signatures).to.equal('');
            expect(errorCodes(result)).to.deep.equal(['ESHORTKEY']);
        });

        it('Should not warn for rsa-sha256 with a 2048 bit key', async () => {
            const result = await signMessage({ signatureData: [base()] });
            expect(result.warnings).to.deep.equal([]);
            expect(referenceVerify(result.out, RSA_PUBLIC).ok).to.be.true;
        });

        for (let strict of [false, true]) {
            it(`Should refuse ed25519-sha1, which is not an algorithm (${strict ? 'strict' : 'default'} mode)`, async () => {
                // RFC 8463 defines ed25519-sha256 only
                const result = await signMessage({ strict, signatureData: [base({ privateKey: ED, algorithm: 'ed25519-sha1' })] });
                expect(result.signatures).to.equal('');
                expect(errorCodes(result)).to.deep.equal(['EINVALIDALGO']);
            });
        }

        it('Should sign with ed25519-sha256', async () => {
            const result = await signMessage({ strict: true, signatureData: [base({ privateKey: ED })] });
            expect(tagsOf(result.signatures).a).to.equal('ed25519-sha256');
            expect(referenceVerify(result.out, ED_PUBLIC).ok).to.be.true;
        });
    });

    describe('Signature time and expiration (RFC 6376 section 3.5)', () => {
        const signTime = new Date('2026-01-01T00:00:00Z');

        for (let [title, expires] of [
            ['equal to the signing time', new Date('2026-01-01T00:00:00Z')],
            ['before the signing time', new Date('2025-01-01T00:00:00Z')],
            ['less than a second after the signing time', new Date('2026-01-01T00:00:00.500Z')]
        ]) {
            it(`Should warn about an expiration ${title} by default`, async () => {
                const result = await signMessage({ signTime, expires, signatureData: [base()] });
                expect(result.errors).to.deep.equal([]);
                expect(result.warnings).to.deep.equal(['invalid-expiration']);
            });

            it(`Should refuse an expiration ${title} in strict mode`, async () => {
                const result = await signMessage({ strict: true, signTime, expires, signatureData: [base()] });
                expect(result.signatures).to.equal('');
                expect(errorCodes(result)).to.deep.equal(['EINVALIDTIME']);
            });
        }

        it('Should accept an expiration after the signing time', async () => {
            const result = await signMessage({ strict: true, signTime, expires: new Date('2026-01-02T00:00:00Z'), signatureData: [base()] });
            const tags = tagsOf(result.signatures);
            expect(tags.t).to.equal('1767225600');
            expect(tags.x).to.equal('1767312000');
            expect(referenceVerify(result.out, RSA_PUBLIC).ok).to.be.true;
        });

        for (let [title, time] of [
            ['before 1970', new Date('1960-01-01T00:00:00Z')],
            ['that needs more than 12 digits', new Date(1e15)]
        ]) {
            it(`Should leave out a t= ${title} by default`, async () => {
                // 1*12DIGIT, a negative or longer value is not valid syntax
                const result = await signMessage({ signTime: time, signatureData: [base()] });
                expect(result.warnings).to.deep.equal(['invalid-signtime']);
                expect(tagsOf(result.signatures)).to.not.have.property('t');
                expect(referenceVerify(result.out, RSA_PUBLIC).ok).to.be.true;
            });

            it(`Should refuse a signing time ${title} in strict mode`, async () => {
                const result = await signMessage({ strict: true, signTime: time, signatureData: [base()] });
                expect(errorCodes(result)).to.deep.equal(['EINVALIDTIME']);
            });
        }
    });

    describe('d= and s= values', () => {
        for (let strict of [false, true]) {
            for (let [title, data, code] of [
                ['a d= with a semicolon', { signingDomain: 'example.com; l=0; x=1' }, 'EINVALIDDOMAIN'],
                ['an s= with a semicolon', { selector: 's; i=@evil.example' }, 'EINVALIDSELECTOR'],
                ['a d= with a line break', { signingDomain: 'example.com\r\nBcc: victim@example.net' }, 'EINVALIDDOMAIN'],
                ['a d= with a space', { signingDomain: 'exa mple.com' }, 'EINVALIDDOMAIN'],
                ['a missing d=', { signingDomain: undefined }, 'EINVALIDDOMAIN'],
                ['a missing s=', { selector: undefined }, 'EINVALIDSELECTOR']
            ]) {
                it(`Should refuse ${title} (${strict ? 'strict' : 'default'} mode)`, async () => {
                    // a value that breaks out of its tag or out of the header is never "lenient"
                    const result = await signMessage({ strict, signatureData: [base(data)] });
                    expect(result.signatures).to.equal('');
                    expect(errorCodes(result)).to.deep.equal([code]);
                });
            }
        }

        for (let [title, data, warning] of [
            ['a d= with a trailing dot', { signingDomain: 'example.com.' }, 'd-syntax'],
            ['a single label d=', { signingDomain: 'localhost' }, 'd-syntax'],
            ['an s= with an underscore', { selector: 's_1' }, 's-syntax']
        ]) {
            it(`Should sign ${title} by default, with a warning`, async () => {
                const result = await signMessage({ signatureData: [base(data)] });
                expect(result.errors).to.deep.equal([]);
                expect(result.warnings).to.deep.equal([warning]);
            });

            it(`Should refuse ${title} in strict mode`, async () => {
                const result = await signMessage({ strict: true, signatureData: [base(data)] });
                expect(result.signatures).to.equal('');
                expect(result.errors).to.have.lengthOf(1);
            });
        }

        it('Should convert U-labels to lower case A-labels', async () => {
            for (let [input, expected] of [
                ['õnnelik.ee', 'xn--nnelik-oxa.ee'],
                ['ÕNNELIK.ee', 'xn--nnelik-oxa.ee'],
                ['faß.de', 'xn--fa-hia.de'],
                ['xn--nnelik-oxa.ee', 'xn--nnelik-oxa.ee']
            ]) {
                const result = await signMessage({ strict: true, signatureData: [base({ signingDomain: input, selector: 'sõber' })] });
                const tags = tagsOf(result.signatures);
                expect(tags.d, input).to.equal(expected);
                expect(tags.s, input).to.equal('xn--sber-0qa');
                expect(referenceVerify(result.out, RSA_PUBLIC).ok, input).to.be.true;
            }
        });
    });

    describe('Header list and identity options', () => {
        const CUSTOM = 'From: a@example.com\r\nX-Custom: one\r\nSubject: s\r\nX-Priority: 1\r\n\r\nbody\r\n';

        it('Should accept the header list as a string', async () => {
            const result = await signMessage({ headerList: 'From:X-Custom:Subject', signatureData: [base()] }, CUSTOM);
            expect(tagsOf(result.signatures).h).to.equal('Subject: X-Custom: From');
        });

        it('Should accept the header list as an array', async () => {
            const result = await signMessage({ headerList: ['From', 'X-Custom', 'Subject'], signatureData: [base()] }, CUSTOM);
            expect(tagsOf(result.signatures).h).to.equal('Subject: X-Custom: From');
            expect(referenceVerify(result.out, RSA_PUBLIC).ok).to.be.true;
        });

        it('Should use the header list of a single signature', async () => {
            const result = await signMessage(
                {
                    headerList: 'From:Subject',
                    signatureData: [base({ headerList: 'From:X-Custom' }), base({ selector: 't' })]
                },
                CUSTOM
            );
            const [first, second] = result.signatures.split(/\r\n(?=DKIM-Signature:)/);
            expect(tagsOf(first).h).to.equal('X-Custom: From');
            expect(tagsOf(second).h).to.equal('Subject: From');
        });

        it('Should refuse a header list without From', async () => {
            const result = await signMessage({ headerList: ['Subject', 'X-Custom'], signatureData: [base()] }, CUSTOM);
            expect(errorCodes(result)).to.deep.equal(['ENOFROM']);
        });

        it('Should write the identity into i=', async () => {
            const result = await signMessage({ signatureData: [base({ identity: 'user@mail.example.com' })] });
            expect(tagsOf(result.signatures).i).to.equal('user@mail.example.com');
            expect(referenceVerify(result.out, RSA_PUBLIC).ok).to.be.true;

            const verified = await dkimVerify(Buffer.from(result.out), {
                strict: true,
                resolver: resolverFrom({ 's._domainkey.example.com': [`v=DKIM1; k=rsa; p=${spkiB64(RSA_PUBLIC)}`] })
            });
            expect(verified.results[0].status.result).to.equal('pass');
            expect(verified.results[0].info).to.include('header.i=user@mail.example.com');
        });

        it('Should warn about an identity outside of d= by default and refuse it in strict mode', async () => {
            let result = await signMessage({ signatureData: [base({ identity: 'user@evil.example' })] });
            expect(result.warnings).to.deep.equal(['identity-domain']);
            expect(tagsOf(result.signatures).i).to.equal('user@evil.example');

            result = await signMessage({ strict: true, signatureData: [base({ identity: 'user@evil.example' })] });
            expect(errorCodes(result)).to.deep.equal(['EINVALIDIDENTITY']);
        });

        it('Should refuse an identity that would break out of the tag', async () => {
            for (let strict of [false, true]) {
                const result = await signMessage({ strict, signatureData: [base({ identity: 'user@example.com; l=0' })] });
                expect(errorCodes(result)).to.deep.equal(['EINVALIDIDENTITY']);
            }
        });

        const verifyStrict = out =>
            dkimVerify(Buffer.from(out), {
                strict: true,
                resolver: resolverFrom({ 's._domainkey.example.com': [`v=DKIM1; k=rsa; p=${spkiB64(RSA_PUBLIC)}`] })
            });

        it('Should write the identity as dkim-quoted-printable', async () => {
            const cases = [
                ['jõgi@example.com', 'j=C3=B5gi@example.com'],
                ['日本@example.com', '=E6=97=A5=E6=9C=AC@example.com'],
                ['tag=41b@example.com', 'tag=3D41b@example.com'],
                ['user@mail.example.com', 'user@mail.example.com']
            ];

            for (let canonicalization of ['relaxed/relaxed', 'simple/simple']) {
                for (let [identity, encoded] of cases) {
                    const result = await signMessage({ canonicalization, signatureData: [base({ identity })] });
                    expect(result.errors).to.deep.equal([]);
                    expect(result.warnings).to.deep.equal([]);
                    expect(tagsOf(result.signatures).i).to.equal(encoded);
                    expect(referenceVerify(result.out, RSA_PUBLIC).ok).to.be.true;

                    const verified = await verifyStrict(result.out);
                    expect(verified.results[0].status.result).to.equal('pass');
                    expect(verified.results[0].status.header.i).to.equal(identity);
                }
            }
        });

        it('Should hash a non-ASCII signature header line as the UTF-8 bytes it is written as', async () => {
            const line = 'DKIM-Signature: v=1; a=rsa-sha256; z=jõgi|日本; b=';
            for (let canon of [relaxedHeaders, simpleHeaders]) {
                const { canonicalizedHeader } = canon('DKIM', { headers: [] }, { signatureHeaderLine: line });
                expect(canonicalizedHeader.includes(Buffer.from('z=jõgi|日本;'))).to.be.true;
            }
        });

        it('Should warn about an identity that is not valid syntax by default and refuse it in strict mode', async () => {
            for (let identity of ['x@@example.com', 'a@exa_mple.example.com', 'a@example.com.', 'a..b@example.com']) {
                let result = await signMessage({ signatureData: [base({ identity })] });
                expect(result.errors).to.deep.equal([]);
                expect(result.warnings).to.include('identity-syntax');
                const verified = await dkimVerify(Buffer.from(result.out), {
                    resolver: resolverFrom({ 's._domainkey.example.com': [`v=DKIM1; k=rsa; p=${spkiB64(RSA_PUBLIC)}`] })
                });
                expect(verified.results[0].status.result).to.equal('pass');

                result = await signMessage({ strict: true, signatureData: [base({ identity })] });
                expect(errorCodes(result)).to.deep.equal(['EINVALIDIDENTITY']);
                expect(result.signatures).to.equal('');
            }

            // the Local-part is optional
            const result = await signMessage({ strict: true, signatureData: [base({ identity: '@mail.example.com' })] });
            expect(result.errors).to.deep.equal([]);
            expect(tagsOf(result.signatures).i).to.equal('@mail.example.com');
        });

        it('Should not put the ARC instance into the i= of a DKIM signature', async () => {
            const result = await signMessage({ signatureData: [base()], arc: { instance: 3 } });
            expect(tagsOf(result.signatures)).to.not.have.property('i');
            expect(referenceVerify(result.out, RSA_PUBLIC).ok).to.be.true;
        });
    });

    describe('ARC-Message-Signature header fields (RFC 8617 section 4.1.2)', () => {
        const SIGNED = 'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=x; b=y\r\n' + MSG;

        const amsOf = async (seal, msg = SIGNED) => {
            const sealed = (
                await sealMessage(
                    Buffer.from(msg),
                    Object.assign({ signingDomain: 'example.com', selector: 's', privateKey: RSA, cv: 'none', authResults: 'mx.example.com; none' }, seal)
                )
            ).toString();
            const ams = sealed.split(/\r\n(?=\S)/).find(line => /^ARC-Message-Signature:/i.test(line));
            return tagsOf(ams)
                .h.split(':')
                .map(name => name.trim().toLowerCase());
        };

        it('Should sign DKIM-Signature by default', async () => {
            const h = await amsOf({});
            expect(h).to.include('dkim-signature');
            expect(h).to.include('from');
        });

        it('Should never sign ARC header fields or Authentication-Results', async () => {
            const msg = 'Authentication-Results: mx.example.com; none\r\nARC-Authentication-Results: i=1; mx.example.com; none\r\n' + SIGNED;
            const h = await amsOf({ headerList: 'From:Subject:Authentication-Results:ARC-Authentication-Results:ARC-Seal:ARC-Message-Signature' }, msg);
            expect(h).to.deep.equal(['subject', 'from']);
        });
    });

    describe('ARC instance', () => {
        const headersOf = raw => ({
            parsed: raw.split('\r\n').map(line => ({ key: line.slice(0, line.indexOf(':')).toLowerCase(), line: Buffer.from(line) }))
        });

        it('Should count the next instance from the highest one of a broken chain', async () => {
            const { getARChain } = require('../../lib/arc');
            // i=2 has cv=fail, so the chain does not parse, and there is no i=3 yet
            const raw = [
                'ARC-Seal: i=2; a=rsa-sha256; cv=fail; d=example.com; s=s; t=1; b=AAAA',
                'ARC-Message-Signature: i=2; a=rsa-sha256; d=example.com; s=s; h=from; bh=x; b=y',
                'ARC-Authentication-Results: i=2; mx.example.com; none',
                'ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=s; t=1; b=AAAA',
                'ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=x; b=y',
                'ARC-Authentication-Results: i=1; mx.example.com; none',
                'From: a@example.com'
            ].join('\r\n');

            const signer = new DkimSigner({ arc: {}, getARChain });
            await signer.messageHeaders(headersOf(raw));
            expect(signer.arc.error).to.exist;

            // createSeal owns the instance: the newest seal has cv=fail, so no set is added
            const failed = await createSeal(Buffer.from(raw + '\r\n\r\nbody\r\n'), {
                seal: base({ cv: 'fail', authResults: 'mx.example.com; arc=fail' })
            });
            expect(failed.headers).to.deep.equal([]);
            expect(failed.errors[0].err.code).to.equal('EARCCHAINFAILED');
            expect(failed.errors[0].err.message).to.include('(i=2)');

            // with a cv=pass newest seal, and the chain still broken by the missing i=1
            // ARC-Message-Signature, the next set is i=3, not a second i=1
            const passing = raw
                .replace('cv=fail', 'cv=pass')
                .split('\r\n')
                .filter(line => !line.startsWith('ARC-Message-Signature: i=1;'))
                .join('\r\n');
            expect(() => getARChain(headersOf(passing))).to.throw();
            const sealed = await createSeal(Buffer.from(passing + '\r\n\r\nbody\r\n'), {
                seal: base({ cv: 'fail', authResults: 'mx.example.com; arc=fail' })
            });
            expect(sealed.errors).to.deep.equal([]);
            expect(sealed.headers[0]).to.match(/^ARC-Seal: i=3;/);
            expect(sealed.headers[1]).to.match(/^ARC-Message-Signature: i=3;/);
            expect(sealed.headers[2]).to.match(/^ARC-Authentication-Results: i=3;/);
        });

        it('Should refuse to add a 51st ARC set', async () => {
            const raw = 'From: a@example.com\r\nSubject: s';
            const signer = new DkimSigner({
                headers: headersOf(raw),
                bodyHash: '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
                arc: { instance: 51, signingDomain: 'example.com', selector: 's', privateKey: RSA }
            });
            await signer.finalize();
            expect(signer.arc.messageSignature).to.be.undefined;
            expect(errorCodes(signer)).to.deep.equal(['EINVALIDINSTANCE']);
        });
    });
});
