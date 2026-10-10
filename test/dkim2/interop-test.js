/* eslint no-unused-expressions:0 */
'use strict';

// Interoperability with an independent DKIM2 implementation: the test vectors of
// turscar/dkim2tests (test/fixtures/dkim2tests), made with turscar/dkim2

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

const { dkim2Verify } = require('../../lib/dkim2/verify');
const { dkim2Sign } = require('../../lib/dkim2/sign');
const { parseHeaders } = require('../../lib/tools');
const { parseMessageInstance, parseSignature, buildSignatureInput } = require('../../lib/dkim2/fields');
const { zoneResolver } = require('../helpers/dns-zone');
const vectors = require('../fixtures/dkim2tests/vectors.json');

chai.config.includeStack = true;

// Vectors whose expectations do not match their own messages. The test checks that the problem is
// still there, so that it shows up when the vectors are updated
const VECTOR_DEFECTS = {
    // ExpectedFlags lists feedback and donotmodify, but the signed message has no f= tag, it has
    // the same signature as simple_rsa2048
    flags_whitespace: signed => expect(signed.toString()).to.not.match(/;\s*f\s*=/i)
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

            it(`verifies as ${vector.ExpectedState}`, async () => {
                let result = await dkim2Verify(signed, options());
                expect(result.status.result, result.status.comment).to.equal(vector.ExpectedState);
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
