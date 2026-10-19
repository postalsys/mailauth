import { describe, it } from 'node:test';
import { Buffer } from 'node:buffer';
import { expect } from 'chai';

import { dkimBody } from '../../src/dkim/body/index.js';
import { PrefixBodyHash } from '../../src/dkim/body/prefix-hashes.js';
import { getSigningHeaderLines } from '../../src/tools.js';
import type { ParsedHeaderRow } from '../../src/tools.js';
import { fc, check, timeout, bytesFrom, chunkBuffer } from './helper.js';

// The verifier reads the body hash of every l= value from one hasher of the whole body (a
// copy of the running hash at each limit), and getSigningHeaderLines() picks the signed header
// fields through an index of the header rows. Both must give exactly what the direct
// computation gives

// The header fields of an h= list as RFC 6376 section 5.4.2 describes it: for each name, the
// last header field of that name not taken yet, scanning from the bottom
const scanSignedFields = (rows: ParsedHeaderRow[], names: string[]) => {
    let remaining = rows.slice();
    let taken: ParsedHeaderRow[] = [];
    for (let name of names) {
        for (let i = remaining.length - 1; i >= 0; i--) {
            if (remaining[i].key === name) {
                taken.push(remaining[i]);
                remaining.splice(i, 1);
                break;
            }
        }
    }
    return taken;
};

const bodyBytes = fc.oneof(bytesFrom('ab \t\r\n\x00\xa0\xff', { maxLength: 200 }), bytesFrom('a \t\r\n', { maxLength: 40 }));
const cuts = fc.array(fc.nat(), { maxLength: 12 });
const limits = fc.array(fc.nat({ max: 220 }), { minLength: 1, maxLength: 8 });

const summary = (hasher: {
    digest(encoding: 'base64'): string;
    canonicalizedLength: number;
    bodyHashedBytes: number;
    byteLength: number;
    getMimeStructureStart(): number;
}) => ({
    bodyHash: hasher.digest('base64'),
    canonicalizedLength: hasher.canonicalizedLength,
    bodyHashedBytes: hasher.bodyHashedBytes,
    byteLength: hasher.byteLength,
    mimeStructureStart: hasher.getMimeStructureStart()
});

describe('Property: shared body hashing for l= values and the header field index', { timeout: timeout(300) }, () => {
    for (let canon of ['simple', 'relaxed']) {
        for (let algo of ['sha256', 'sha1']) {
            it(`${canon}/${algo}: the hash at each l= equals a hasher created with that limit`, () =>
                check(
                    fc.property(bodyBytes, cuts, limits, (body, cutPoints, ls) => {
                        let chunks = chunkBuffer(Buffer.from(body, 'latin1'), cutPoints);

                        let source = dkimBody(canon, algo, '');
                        let views = ls.map(l => new PrefixBodyHash(source, l));
                        let plain = dkimBody(canon, algo, '');
                        let direct = ls.map(l => dkimBody(canon, algo, l));
                        for (let hasher of [source, plain, ...direct]) {
                            for (let chunk of chunks) {
                                hasher.update(chunk);
                            }
                        }

                        // views read in any order, before or after the hasher they share
                        views.reverse().forEach((view, i) => {
                            expect(summary(view)).to.deep.equal(summary(direct[ls.length - 1 - i]));
                        });
                        expect(summary(source)).to.deep.equal(summary(plain));
                        // a second read gives the same value
                        expect(source.digest('base64')).to.equal(plain.digest('base64'));
                    }),
                    300
                ));
        }
    }

    it('picks the same header rows as scanning the header from the bottom', () =>
        check(
            fc.property(
                fc.array(fc.constantFrom('from', 'to', 'subject', 'x-a', null), { maxLength: 30 }),
                fc.array(fc.constantFrom('from', 'to', 'subject', 'x-a', 'x-missing', 'FROM', ' from'), { maxLength: 12 }),
                (keys, names) => {
                    let rows = keys.map(
                        (key, i) => ({ key, casedKey: key ? key.toUpperCase() : undefined, line: Buffer.from(`${key}: ${i}`) }) as ParsedHeaderRow
                    );
                    let signed = getSigningHeaderLines(rows, names.join(':'), true);
                    // h= names are compared lowercased and trimmed
                    let expected = scanSignedFields(
                        rows,
                        names.map(name => name.trim().toLowerCase())
                    );
                    expect(signed.headers.length).to.equal(expected.length);
                    signed.headers.forEach((row, i) => expect(row).to.equal(expected[i]));
                    expect(signed.keys).to.equal(expected.map(row => row.casedKey).join(': '));
                    // the second call reads the cached index of the same rows
                    expect(getSigningHeaderLines(rows, names.join(':'), true).headers).to.deep.equal(signed.headers);
                }
            ),
            500
        ));
});
