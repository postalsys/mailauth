/* eslint no-unused-expressions:0 */
'use strict';

// Interoperability with independent DKIM2 implementations: the test vectors of turscar/dkim2tests
// (test/fixtures/dkim2tests), made with turscar/dkim2, messages signed by stalwart mail-auth
// (test/fixtures/dkim2-stalwart), and the draft-06 vectors of croessner/dkim2 (test/fixtures/dkim2-croessner)

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const chai = require('chai');
const expect = chai.expect;

const { dkim2Verify } = require('../../lib/dkim2/verify');
const { dkim2Sign } = require('../../lib/dkim2/sign');
const { parseHeaders } = require('../../lib/tools');
const { parseMessageInstance, parseSignature, buildSignatureInput } = require('../../lib/dkim2/fields');
const { zoneResolver } = require('../helpers/dns-zone');
const vectors = require('../fixtures/dkim2tests/vectors.json');
const stalwart = require('../fixtures/dkim2-stalwart/messages.json');
const croessner = require('../fixtures/dkim2-croessner/public-golden.json');

chai.config.includeStack = true;

// Vectors whose expectations do not match their own messages. The test checks that the problem is
// still there, so that it shows up when the vectors are updated
const VECTOR_DEFECTS = {
    // ExpectedFlags lists feedback and donotmodify, but the signed message has no f= tag, it has
    // the same signature as simple_rsa2048
    flags_whitespace: signed => expect(signed.toString()).to.not.match(/;\s*f\s*=/i)
};

// Vectors where the result follows draft-ietf-dkim-dkim2-spec-06 instead of the earlier draft the vector
// was written for, see docs/dkim2.md
const SPEC_06_RESULTS = {
    // only unknown signature algorithms: FAIL in the spec-02 based vector, PERMERROR by spec-06
    // section 11.1, as croessner/dkim2 (built for spec-06) reports it as well
    algorithm_only_future: 'permerror'
};

// answers from the key records of a vector, given as { name: TXT value }
const resolverFor = dns => zoneResolver(Object.fromEntries(Object.entries(dns || {}).map(([name, txt]) => [name, { TXT: [[txt]] }])));

const headerRows = message => parseHeaders(message.subarray(0, message.indexOf('\r\n\r\n') + 2)).parsed;

// the vectors were signed in 2026, so they are verified a minute after their t=
const signTime = signature => (signature && !isNaN(signature.t) ? new Date((signature.t + 60) * 1000) : undefined);

describe('DKIM2 interoperability with the turscar/dkim2tests vectors', () => {
    it('has the vectors', () => {
        expect(vectors.length).to.be.at.least(42);
    });

    for (let vector of vectors) {
        describe(`${vector.Name}${vector.Comments ? ` (${vector.Comments})` : ''}`, () => {
            let signed = Buffer.from(vector.SignedMessage);
            let rows = headerRows(signed);
            let signatures = rows.filter(row => row.key === 'dkim2-signature');
            let signature = signatures.length === 1 ? parseSignature(signatures[0].line) : null;
            let options = () => ({ resolver: resolverFor(vector.DNS), mailFrom: vector.MailFrom, rcptTo: vector.RcptTo, curTime: signTime(signature) });

            let expected = SPEC_06_RESULTS[vector.Name] || vector.ExpectedState;
            it(`verifies as ${expected}`, async () => {
                let result = await dkim2Verify(signed, options());
                expect(result.status.result, result.status.comment).to.equal(expected);
                if (VECTOR_DEFECTS[vector.Name]) {
                    // asserts that the known defect of the vector is still there
                    VECTOR_DEFECTS[vector.Name](signed);
                } else if (vector.ExpectedState === 'pass' && vector.ExpectedFlags) {
                    expect(result.signatures[result.signatures.length - 1].flags).to.deep.equal(vector.ExpectedFlags);
                }
            });

            if (vector.CanonicalDkim2Headers && signatures.length === 1) {
                it('canonicalizes the signed header fields the same way (section 9.6)', () => {
                    let instances = rows.filter(row => row.key === 'message-instance').map(row => row.line);
                    expect(buildSignatureInput(instances, [], signatures[0].line).toString()).to.equal(vector.CanonicalDkim2Headers);
                });
            }

            if (vector.ExpectedState === 'pass') {
                it('signs the original with the same Message-Instance hashes, and the signature verifies', async () => {
                    let original = Buffer.from(vector.OriginalMessage);
                    let theirs = parseMessageInstance(rows.find(row => row.key === 'message-instance').line).hashes.find(hash => hash.algorithm === 'sha256');
                    let keys = Object.entries(vector.PrivateKeys);
                    let selectors = signature.signatures.map(entry => entry.selector);
                    let published = selector => Object.keys(vector.DNS).some(name => name.startsWith(`${selector}._domainkey.`));

                    let ours = await dkim2Sign(original, {
                        signingDomain: signature.signingDomain,
                        // the vectors name a single key differently from its selector
                        signatureData: keys.map(([name, privateKey]) => ({ selector: keys.length === 1 ? selectors.find(published) : name, privateKey })),
                        mailFrom: vector.MailFrom,
                        rcptTo: vector.RcptTo,
                        signTime: signTime(signature)
                    });

                    let hashes = parseMessageInstance(ours.messageInstance).hashes[0];
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

    for (let entry of stalwart.messages) {
        it(`verifies ${entry.name}`, async () => {
            let message = Buffer.from(entry.message);
            let signatures = headerRows(message).filter(row => row.key === 'dkim2-signature');
            // the highest i=, wherever it is in the header
            let top = signatures.map(row => parseSignature(row.line)).reduce((a, b) => (b.i > a.i ? b : a));
            let result = await dkim2Verify(message, { resolver, mailFrom: entry.mailFrom, rcptTo: entry.rcptTo, curTime: signTime(top) });
            expect(result.status.result, result.status.comment).to.equal('pass');
            expect(result.status).to.not.have.property('warnings');
        });
    }
});

describe('DKIM2 interoperability with the croessner/dkim2 draft-06 vectors', () => {
    // the keys of the vectors, published under the selectors rsa.test and ed.test
    const rsaKey = crypto
        .createPublicKey({ key: { kty: 'RSA', n: Buffer.from(croessner.rsa_modulus_base64, 'base64').toString('base64url'), e: 'AQAB' }, format: 'jwk' })
        .export({ type: 'spki', format: 'der' })
        .toString('base64');
    const keyRecords = { 'rsa.test': `v=DKIM1; k=rsa; p=${rsaKey}`, 'ed.test': `v=DKIM1; k=ed25519; p=${croessner.ed25519_public_base64}` };

    const dnsError = code => {
        let err = new Error(code);
        err.code = code;
        return err;
    };

    // the key provider modes of the vector test
    const resolvers = {
        keys: async name => {
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

    const corruptSignature = raw => {
        let str = raw.toString('binary');
        let pos = str.indexOf('s=rsa.test:rsa-sha256:') + 's=rsa.test:rsa-sha256:'.length;
        return Buffer.from(str.slice(0, pos) + (str[pos] === 'A' ? 'B' : 'A') + str.slice(pos + 1), 'binary');
    };
    const duplicateTag = raw => Buffer.from(raw.toString('binary').replace('DKIM2-Signature: i=1; m=1;', 'DKIM2-Signature: i=1; m=1; m=1;'), 'binary');

    // [name, vector, key provider, expected result, options] from publicGoldenCases in lib/verifier_vector_test.go.
    // `ours` is the result mailauth gives where it differs on purpose, see docs/dkim2.md
    const cases = [
        ['rsa_sha256_pass', 'rsa_pass', 'keys', 'pass'],
        ['ed25519_sha256_pass', 'ed25519_pass', 'keys', 'pass'],
        ['rsa_and_ed25519_both_pass', 'both_pass', 'keys', 'pass'],
        ['supported_pass_plus_unknown_signature_pass', 'supported_unknown_pass', 'keys', 'pass'],
        ['sha256_plus_mismatching_sha512_fails', 'sha_unknown_hash_pass', 'keys', 'fail'],
        ['mismatching_sha512_only_fails', 'unknown_hash_only', 'keys', 'fail'],
        ['unknown_signature_only_permerror', 'unknown_signature_only', 'keys', 'permerror'],
        ['supported_pass_plus_supported_bad_signature_fail', 'supported_mixed_fail', 'keys', 'fail'],
        ['body_hash_mismatch_fail', 'body_mismatch', 'keys', 'fail'],
        ['header_hash_mismatch_fail', 'header_mismatch', 'keys', 'fail'],
        ['supported_signature_mismatch_fail', 'rsa_pass', 'keys', 'fail', { mutate: corruptSignature }],
        // a message with no DKIM2 header fields is dkim2=none (draft-gondwana-dkim2-authres-00 section 3.1)
        ['missing_protocol_permerror', 'missing_protocol', 'keys', 'permerror', { ours: 'none' }],
        // bare LF line endings are read as CRLF, and the message has no DKIM2 header fields
        ['malformed_message_permerror', 'malformed_message', 'keys', 'permerror', { ours: 'none' }],
        ['malformed_dkim2_tag_permerror', 'rsa_pass', 'keys', 'permerror', { mutate: duplicateTag }],
        ['inconsistent_protocol_permerror', 'inconsistent_sequence', 'keys', 'permerror'],
        ['missing_key_permerror', 'rsa_pass', 'missing', 'permerror'],
        ['ambiguous_key_permerror', 'rsa_pass', 'ambiguous', 'permerror'],
        ['typed_temporary_provider_temperror', 'rsa_pass', 'temporary', 'temperror'],
        ['timestamp_exact_14_days_pass', 'age_exact', 'keys', 'pass'],
        ['timestamp_14_days_plus_one_permerror', 'age_over', 'keys', 'permerror'],
        ['timestamp_exact_five_minutes_future_pass', 'future_exact', 'keys', 'pass'],
        ['timestamp_five_minutes_plus_one_permerror', 'future_over', 'keys', 'permerror'],
        ['timestamp_large_parseable_permerror', 'timestamp_large', 'keys', 'permerror'],
        ['mail_from_exact_pass', 'mail_exact', 'keys', 'pass'],
        ['mail_from_ascii_domain_case_pass', 'mail_domain_case', 'keys', 'pass', { reverse: '<Sender@example.test>' }],
        ['mail_from_local_part_case_mismatch', 'mail_exact', 'keys', 'permerror', { reverse: '<sender@example.test>' }],
        ['null_reverse_path_matches_null', 'mail_null', 'keys', 'pass'],
        ['null_reverse_path_nonnull_mismatch', 'mail_null', 'keys', 'permerror', { reverse: '<sender@example.test>' }],
        ['recipient_subset_order_and_signed_extra_pass', 'recipient_set', 'keys', 'pass', { forward: ['<two@example.test>', '<one@example.test>'] }],
        ['recipient_missing_current_permerror', 'recipient_set', 'keys', 'permerror', { forward: ['<one@example.test>', '<missing@example.test>'] }],
        ['current_envelope_mismatch_permerror', 'mail_exact', 'keys', 'permerror', { reverse: '<Sender@other.test>' }],
        ['relaxed_d_alignment_pass', 'alignment_relaxed', 'keys', 'pass'],
        ['d_alignment_mismatch_permerror', 'alignment_mismatch', 'keys', 'permerror'],
        ['intermediate_nd_successor_pass', 'intermediate_nd', 'keys', 'pass'],
        ['terminal_current_nd_permerror', 'terminal_nd', 'keys', 'permerror']
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
                rcptTo: options.forward || vector.forward_paths_base64.map(path => Buffer.from(path, 'base64').toString()),
                curTime: new Date(1700000000 * 1000)
            });
            expect(verified.status.result, verified.status.comment).to.equal(result);
        });
    }
});
