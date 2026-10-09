'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const { expect } = require('chai');

const { dkimBody } = require('../../lib/dkim/body');
const { canonBodyRelaxed } = require('../helpers/dkim-reference');
const { fc, check, timeout, bytesFrom, chunkBuffer } = require('./helper');

// Body bytes that exercise every branch of the canonicalization: line endings (CRLF, bare LF,
// bare CR), the whitespace that relaxed collapses, ordinary text and 8-bit bytes
const bodyBytes = fc.oneof(bytesFrom('ab \t\r\n\x00\xa0\xff', { maxLength: 200 }), bytesFrom('a \t\r\n', { maxLength: 40 }));

const cuts = fc.array(fc.nat(), { maxLength: 12 });
const maxBodyLength = fc.option(fc.nat({ max: 220 }), { nil: false });

const hashBody = (canon, chunks, l) => {
    let hasher = dkimBody(canon, 'sha256', l);
    for (let chunk of chunks) {
        hasher.update(chunk);
    }
    let bodyHash = hasher.digest('base64');
    return { bodyHash, canonicalizedLength: hasher.canonicalizedLength, bodyHashedBytes: hasher.bodyHashedBytes };
};

// Reference body canonicalization, from RFC 6376 sections 3.4.3 and 3.4.4. mailauth reads a
// bare <LF> as a line ending in both modes, the message parser has already turned it into a
// CRLF for any message that is read off the wire, so the reference does the same first. A
// <CR> that no <LF> follows is content
const referenceCanonical = (canon, body) => {
    if (canon === 'relaxed') {
        return canonBodyRelaxed(body.replace(/\r?\n/g, '\r\n'));
    }
    return body.replace(/(?:\r?\n)*$/, '') + '\r\n';
};

const sha256 = str => crypto.createHash('sha256').update(Buffer.from(str, 'latin1')).digest('base64');

describe('Property: DKIM body canonicalization', function () {
    this.timeout(timeout(300));

    for (let canon of ['simple', 'relaxed']) {
        it(`${canon}: the body hash does not depend on how the body is split into chunks`, () =>
            check(
                fc.property(bodyBytes, cuts, maxBodyLength, (body, cutPoints, l) => {
                    let buf = Buffer.from(body, 'latin1');
                    let whole = hashBody(canon, [buf], l);
                    let chunked = hashBody(canon, chunkBuffer(buf, cutPoints), l);
                    let byteByByte = hashBody(
                        canon,
                        Array.from(buf).map(byte => Buffer.from([byte])),
                        l
                    );
                    expect(chunked).to.deep.equal(whole);
                    expect(byteByByte).to.deep.equal(whole);
                }),
                300
            ));

        it(`${canon}: matches the reference canonicalization, with and without l=`, () =>
            check(
                fc.property(bodyBytes, cuts, maxBodyLength, (body, cutPoints, l) => {
                    let canonical = referenceCanonical(canon, body);
                    let hashed = l === false ? canonical : canonical.slice(0, l);

                    let result = hashBody(canon, chunkBuffer(Buffer.from(body, 'latin1'), cutPoints), l);

                    expect(result.bodyHash).to.equal(sha256(hashed));
                    expect(result.canonicalizedLength).to.equal(canonical.length);
                    expect(result.bodyHashedBytes).to.equal(hashed.length);
                }),
                300
            ));
    }
});
