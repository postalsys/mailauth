/* eslint @typescript-eslint/no-unused-expressions:0 */
// Interoperability with independent DKIM2 implementations: the test vectors of turscar/dkim2tests
// (test/fixtures/dkim2tests), made with turscar/dkim2, messages signed by stalwart mail-auth
// (test/fixtures/dkim2-stalwart), and the draft-09 vectors of croessner/dkim2 (test/fixtures/dkim2-croessner)

import { describe, it } from 'node:test';
import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, config } from 'chai';

import { dkim2Verify } from '../../src/dkim2/verify.js';
import { dkim2Sign } from '../../src/dkim2/sign.js';
import { parseHeaders } from '../../src/tools.js';
import { parseMessageInstance, parseSignature, buildSignatureInput } from '../../src/dkim2/fields.js';
import { Dkim2Verifier } from '../../src/dkim2/dkim2-verifier.js';
import { createKeyLookup } from '../../src/dkim2/key.js';
import { supportsMlDsa, verifySignature } from '../../src/dkim2/algorithms.js';
import { zoneResolver } from '../helpers/dns-zone.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/dkim2tests/vectors.json'), 'utf8'));
const stalwart = JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/dkim2-stalwart/messages.json'), 'utf8'));
const croessner = JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/dkim2-croessner/public-golden.json'), 'utf8'));
const croessnerCrypto = JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/dkim2-croessner/custody-crypto-golden.json'), 'utf8'));

config.includeStack = true;

// Vectors whose expectations do not match their own messages. The test checks that the problem is
// still there, so that it shows up when the vectors are updated
const VECTOR_DEFECTS: Record<string, (signed: any) => unknown> = {
    // ExpectedFlags lists feedback and donotmodify, but the signed message has no f= tag, it has
    // the same signature as simple_rsa2048
    flags_whitespace: (signed: any) => expect(signed.toString()).to.not.match(/;\s*f\s*=/i)
};

// Vectors where the result follows draft-ietf-dkim-dkim2-spec-09 instead of the earlier draft the vector
// was written for, see docs/dkim2.md
const SPEC_09_RESULTS: Record<string, string> = {
    // an algorithm that is not implemented is a PERMERROR (section 14.6 step 4), and a "," group
    // passes only when every signature in it passes
    algorithm_only_future: 'permerror',
    algorithm_with_future: 'permerror',
    // tag names are case-sensitive (section 8): the second, upper case, tag of these vectors is an
    // unknown tag and not a duplicate
    d2_duplicate_d_tag: 'pass',
    d2_duplicate_f_tag: 'pass',
    d2_duplicate_i_tag: 'pass',
    d2_duplicate_m_tag: 'pass',
    d2_duplicate_mf_tag: 'pass',
    d2_duplicate_n_tag: 'pass',
    d2_duplicate_rt_tag: 'pass',
    d2_duplicate_t_tag: 'pass',
    // "S=" is not the s= tag, so its value is not emptied for the signature input (section 12.8)
    d2_duplicate_s_tag: 'fail',
    // "I=", "M=" and the other upper case tags are unknown, so i= and the rest are missing
    tags_mixed_case: 'permerror',
    // a chain of custody error is a FAIL (section 14.4)
    domain_below_mailfrom: 'fail'
};

// Vectors whose canonical form has an upper case "S=" tag emptied, which spec-09 does not do
const CANONICAL_DIFFERENCES = new Set(['d2_duplicate_s_tag', 'tags_mixed_case']);

// answers from the key records of a vector, given as { name: TXT value }
const resolverFor = (dns: any) => zoneResolver(Object.fromEntries(Object.entries(dns || {}).map(([name, txt]) => [name, { TXT: [[txt]] }])));

const headerRows = (message: any): any[] => parseHeaders(message.subarray(0, message.indexOf('\r\n\r\n') + 2)).parsed;

// the vectors were signed in 2026, so they are verified a minute after their t=
const signTime = (signature: any) => (signature && !isNaN(signature.t) ? new Date((signature.t + 60) * 1000) : undefined);

describe('DKIM2 interoperability with the turscar/dkim2tests vectors', () => {
    it('has the vectors', () => {
        expect(vectors.length).to.be.at.least(42);
    });

    for (let vector of vectors) {
        describe(`${vector.Name}${vector.Comments ? ` (${vector.Comments})` : ''}`, () => {
            let signed = Buffer.from(vector.SignedMessage);
            let rows = headerRows(signed);
            let signatures = rows.filter(row => row.key === 'dkim2-signature');
            let signature: any = signatures.length === 1 ? parseSignature(signatures[0].line) : null;
            let options = () => ({ resolver: resolverFor(vector.DNS), mailFrom: vector.MailFrom, rcptTo: vector.RcptTo, curTime: signTime(signature) });

            let expected = SPEC_09_RESULTS[vector.Name] || vector.ExpectedState;
            it(`verifies as ${expected}`, async () => {
                let result = await dkim2Verify(signed, options());
                expect(result.status.result, result.status.comment).to.equal(expected);
                if (VECTOR_DEFECTS[vector.Name]) {
                    // asserts that the known defect of the vector is still there
                    VECTOR_DEFECTS[vector.Name](signed);
                } else if (vector.ExpectedState === 'pass' && expected === 'pass' && vector.ExpectedFlags) {
                    expect(result.signatures[result.signatures.length - 1].flags).to.deep.equal(vector.ExpectedFlags);
                }
            });

            if (vector.CanonicalDkim2Headers && signatures.length === 1 && !CANONICAL_DIFFERENCES.has(vector.Name)) {
                it('canonicalizes the signed header fields the same way (section 12.8)', () => {
                    let instances = rows.filter(row => row.key === 'message-instance').map(row => row.line);
                    expect(buildSignatureInput(instances, [], signatures[0].line).toString()).to.equal(vector.CanonicalDkim2Headers);
                });
            }

            if (vector.ExpectedState === 'pass' && expected === 'pass') {
                it('signs the original with the same Message-Instance hashes, and the signature verifies', async () => {
                    let original = Buffer.from(vector.OriginalMessage);
                    let theirs = parseMessageInstance(rows.find(row => row.key === 'message-instance').line).hashes.find(hash => hash.algorithm === 'sha256');
                    let keys = Object.entries(vector.PrivateKeys);
                    let selectors = signature.signatures.map((entry: any) => entry.selector);
                    let published = (selector: any) => Object.keys(vector.DNS).some(name => name.startsWith(`${selector}._domainkey.`));

                    let ours = await dkim2Sign(original, {
                        signingDomain: signature.signingDomain,
                        // the vectors name a single key differently from its selector
                        signatureData: keys.map(([name, privateKey]) => ({
                            selector: keys.length === 1 ? selectors.find(published) : name,
                            privateKey: privateKey as any
                        })),
                        mailFrom: vector.MailFrom,
                        rcptTo: vector.RcptTo,
                        signTime: signTime(signature)
                    });

                    let hashes = parseMessageInstance(ours.messageInstance!).hashes[0];
                    expect(hashes).to.deep.equal(theirs);

                    let result = await dkim2Verify(Buffer.concat([Buffer.from(ours.signatures), original]), options());
                    expect(result.status.result, result.status.comment).to.equal('pass');
                });
            }
        });
    }
});

describe('DKIM2 interoperability with messages signed by stalwart mail-auth', () => {
    const resolver = resolverFor(stalwart.dns);

    it('has the messages', () => {
        expect(stalwart.messages.length).to.be.at.least(16);
    });

    // Messages whose From domain is not the signing domain test1.dkim2.com. draft-ietf-dkim-dkim2-spec-04,
    // which mail-auth is built for, has no Authentic From rule, spec-09 sections 11 and 14.8 fail them
    const notAuthentic = new Set([
        'emptybody-dual',
        'emptybody-ed',
        'multiheader-dual',
        'multiheader-ed',
        'multirecipient-dual',
        'multirecipient-ed',
        'trailingblank-dual',
        'trailingblank-ed'
    ]);

    for (let entry of stalwart.messages) {
        let expected = notAuthentic.has(entry.name) ? 'fail' : 'pass';
        it(`verifies ${entry.name} as ${expected}`, async () => {
            let message = Buffer.from(entry.message);
            let signatures = headerRows(message).filter(row => row.key === 'dkim2-signature');
            // the highest i=, wherever it is in the header
            let top = signatures.map(row => parseSignature(row.line)).reduce((a, b) => (b.i > a.i ? b : a));
            let result = await dkim2Verify(message, { resolver, mailFrom: entry.mailFrom, rcptTo: entry.rcptTo, curTime: signTime(top) });
            expect(result.status.result, result.status.comment).to.equal(expected);
            if (expected === 'fail') {
                // everything else verifies
                expect(result.errors.map((error: any) => error.message)).to.deep.equal(['DKIM2-Signature i=1 matching From is not authentic']);
            }
            expect(result.status).to.not.have.property('warnings');
        });
    }
});

describe('DKIM2 interoperability with the croessner/dkim2 draft-09 vectors', () => {
    // the keys of the vectors, published under the selectors rsa.test and ed.test
    const rsaKey = crypto
        .createPublicKey({ key: { kty: 'RSA', n: Buffer.from(croessner.rsa_modulus_base64, 'base64').toString('base64url'), e: 'AQAB' }, format: 'jwk' })
        .export({ type: 'spki', format: 'der' })
        .toString('base64');
    const keyRecords: Record<string, string> = {
        'rsa.test': `v=DKIM1; k=rsa; p=${rsaKey}`,
        'ed.test': `v=DKIM1; k=ed25519; p=${croessner.ed25519_public_base64}`
    };

    const dnsError = (code: any) => {
        let err: any = new Error(code);
        err.code = code;
        return err;
    };

    // the key provider modes of the vector test
    const resolvers: Record<string, any> = {
        keys: async (name: any) => {
            if (name === '_domainkey.example.test') {
                // the vector test disables subdomain signing for From domains
                // (WithoutSubdomainFromAuthorization), which is what f=strict does (section 3.8)
                return [['v=DKIM1; f=strict']];
            }
            let record = keyRecords[name.split('._domainkey.')[0]];
            if (!record) {
                throw dnsError('ENOTFOUND');
            }
            return [[record]];
        },
        missing: async () => {
            throw dnsError('ENOTFOUND');
        },
        ambiguous: async () => [[keyRecords['rsa.test']], [keyRecords['rsa.test']]],
        temporary: async () => {
            throw dnsError('ETIMEOUT');
        }
    };

    const corruptSignature = (raw: any) => {
        let str = raw.toString('binary');
        let pos = str.indexOf('s=rsa.test:rsa-sha256:') + 's=rsa.test:rsa-sha256:'.length;
        return Buffer.from(str.slice(0, pos) + (str[pos] === 'A' ? 'B' : 'A') + str.slice(pos + 1), 'binary');
    };
    const duplicateTag = (raw: any) => Buffer.from(raw.toString('binary').replace('DKIM2-Signature: i=1; m=1;', 'DKIM2-Signature: i=1; m=1; m=1;'), 'binary');

    const clock = 1700000000;

    // [name, vector, key provider, expected result, options] from publicGoldenCases in verifier_vector_test.go.
    // `ours` is the result mailauth gives where it differs on purpose, see docs/dkim2.md
    const cases: any[][] = [
        ['rsa_sha256_pass', 'rsa_pass', 'keys', 'pass'],
        ['ed25519_sha256_pass', 'ed25519_pass', 'keys', 'pass'],
        ['rsa_and_ed25519_both_pass', 'both_pass', 'keys', 'pass'],
        ['supported_pass_plus_unknown_signature_in_group_permerror', 'supported_unknown_pass', 'keys', 'permerror'],
        ['sha256_plus_mismatching_sha512_fails', 'sha_unknown_hash_pass', 'keys', 'fail'],
        ['mismatching_sha512_only_fails', 'unknown_hash_only', 'keys', 'fail'],
        ['unknown_signature_only_permerror', 'unknown_signature_only', 'keys', 'permerror'],
        ['supported_pass_plus_supported_bad_signature_fail', 'supported_mixed_fail', 'keys', 'fail'],
        ['body_hash_mismatch_fail', 'body_mismatch', 'keys', 'fail'],
        ['header_hash_mismatch_fail', 'header_mismatch', 'keys', 'fail'],
        ['supported_signature_mismatch_fail', 'rsa_pass', 'keys', 'fail', { mutate: corruptSignature }],
        // a message with no DKIM2 header fields is NONE (section 14.1, draft-gondwana-dkim2-authres-01 section 3.1)
        ['missing_protocol_permerror', 'missing_protocol', 'keys', 'permerror', { ours: 'none' }],
        // bare LF line endings are read as CRLF, and the message has no DKIM2 header fields
        ['malformed_message_permerror', 'malformed_message', 'keys', 'permerror', { ours: 'none' }],
        ['malformed_dkim2_tag_permerror', 'rsa_pass', 'keys', 'permerror', { mutate: duplicateTag }],
        ['inconsistent_protocol_permerror', 'inconsistent_sequence', 'keys', 'permerror'],
        ['missing_key_permerror', 'rsa_pass', 'missing', 'permerror'],
        ['ambiguous_key_permerror', 'rsa_pass', 'ambiguous', 'permerror'],
        ['typed_temporary_provider_temperror', 'rsa_pass', 'temporary', 'temperror'],
        ['timestamp_exact_14_days_pass', 'age_exact', 'keys', 'pass'],
        ['timestamp_14_days_plus_one_fail', 'age_over', 'keys', 'fail'],
        // signed 300 and 301 seconds after the clock, which is moved back one day
        ['timestamp_exact_one_day_future_pass', 'future_exact', 'keys', 'pass', { clock: clock + 300 - 86400 }],
        ['timestamp_one_day_plus_one_fail', 'future_over', 'keys', 'fail', { clock: clock + 300 - 86400 }],
        ['timestamp_large_parseable_fail', 'timestamp_large', 'keys', 'fail'],
        ['mail_from_exact_pass', 'mail_exact', 'keys', 'pass'],
        ['mail_from_ascii_domain_case_pass', 'mail_domain_case', 'keys', 'pass', { reverse: '<Sender@example.test>' }],
        ['mail_from_local_part_case_mismatch', 'mail_exact', 'keys', 'fail', { reverse: '<sender@example.test>' }],
        ['null_reverse_path_matches_null', 'mail_null', 'keys', 'pass'],
        ['null_reverse_path_nonnull_mismatch', 'mail_null', 'keys', 'fail', { reverse: '<sender@example.test>' }],
        ['recipient_subset_order_and_signed_extra_pass', 'recipient_set', 'keys', 'pass', { forward: ['<two@example.test>', '<one@example.test>'] }],
        ['recipient_missing_current_fail', 'recipient_set', 'keys', 'fail', { forward: ['<one@example.test>', '<missing@example.test>'] }],
        ['current_envelope_mismatch_fail', 'mail_exact', 'keys', 'fail', { reverse: '<Sender@other.test>' }],
        ['relaxed_d_alignment_pass', 'alignment_relaxed', 'keys', 'pass'],
        ['d_alignment_mismatch_fail', 'alignment_mismatch', 'keys', 'fail'],
        [
            'intermediate_nd_from_not_authentic',
            'intermediate_nd',
            'keys',
            'fail',
            { comment: 'DKIM2-Signature i=1 From example.test forbids subdomain signing' }
        ],
        ['terminal_current_nd_fail', 'terminal_nd', 'keys', 'fail', { comment: 'DKIM2-Signature i=1 unexpected nd= tag' }]
    ];

    for (let [name, vectorName, provider, expected, options = {}] of cases) {
        let result = options.ours || expected;
        it(`${name} gives ${result}${options.ours ? ` (croessner/dkim2: ${expected})` : ''}`, async () => {
            let vector = croessner.vectors[vectorName];
            let raw = Buffer.from(vector.raw_base64, 'base64');
            if (options.mutate) {
                raw = options.mutate(raw);
            }
            let verified = await dkim2Verify(raw, {
                resolver: resolvers[provider],
                mailFrom: options.reverse || Buffer.from(vector.reverse_path_base64, 'base64').toString(),
                rcptTo: options.forward || vector.forward_paths_base64.map((path: any) => Buffer.from(path, 'base64').toString()),
                curTime: new Date((options.clock || clock) * 1000)
            });
            expect(verified.status.result, verified.status.comment).to.equal(result);
            if (options.comment) {
                expect(verified.status.comment).to.equal(options.comment);
            }
        });
    }

    it('reads the ML-DSA-44 key and checks both signatures of the vector (section 3.4)', { skip: !supportsMlDsa() && 'Node.js has no ML-DSA' }, async () => {
        let vector = croessnerCrypto.mldsa44_vector;
        expect(Buffer.from(vector.public_raw_base64, 'base64')).to.have.length(1312);
        let lookup = createKeyLookup(async () => [[`v=DKIM1; k=mldsa44; p=${vector.public_raw_base64}`]]);
        let key = await lookup('example.test', 'pq', 'mldsa44');
        let input = Buffer.from(vector.input_base64, 'base64');
        for (let signature of [vector.deterministic_signature_base64, vector.openssl_hedged_signature_base64]) {
            expect(verifySignature('mldsa44', input, key.publicKey!, Buffer.from(signature, 'base64'))).to.be.true;
            // the signature covers the input exactly
            expect(verifySignature('mldsa44', Buffer.concat([input, Buffer.from(' ')]), key.publicKey!, Buffer.from(signature, 'base64'))).to.be.false;
        }
        // the context string is part of the signature, without it the same signature does not verify
        let signature = Buffer.from(vector.deterministic_signature_base64, 'base64');
        expect(crypto.verify(null, input, key.publicKey!, signature)).to.be.false;
        // our SubjectPublicKeyInfo of the raw key is the one of the vector
        expect(key.publicKey!.export({ type: 'spki', format: 'der' }).toString('base64')).to.equal(vector.public_spki_base64);
    });

    describe('chain of custody cases', () => {
        for (let entry of croessnerCrypto.custody_cases) {
            it(`${entry.name} ${entry.want_error ? 'does not continue the chain' : `is ${entry.want_status}`}`, () => {
                let signatures = new Map<number, any>(
                    entry.signatures.map((signature: any) => [
                        signature.sequence,
                        {
                            i: signature.sequence,
                            m: signature.instance,
                            signingDomain: signature.domain,
                            nextDomain: signature.next_domain,
                            mailFrom: signature.mail_from,
                            rcptTo: signature.recipients
                        }
                    ])
                );
                let errors: string[] = [];
                new Dkim2Verifier().checkCustody(signatures, signatures.size, (result, message) => errors.push(`${result}: ${message}`));
                if (entry.want_error) {
                    expect(errors).to.have.length(1);
                    expect(errors[0]).to.match(/^fail: DKIM2-Signature i=\d+ (?:mf=|d=|nd=) does not match/);
                } else if (entry.want_status === 'terminal_next_domain') {
                    expect(errors).to.deep.equal([`fail: DKIM2-Signature i=${signatures.size} unexpected nd= tag`]);
                } else {
                    expect(errors).to.deep.equal([]);
                }
            });
        }
    });
});
