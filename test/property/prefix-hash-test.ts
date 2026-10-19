import { describe, it } from 'node:test';
import { Buffer } from 'node:buffer';
import { expect } from 'chai';

import { dkimBody } from '../../src/dkim/body/index.js';
import { PrefixBodyHash } from '../../src/dkim/body/prefix-hashes.js';
import { getSigningHeaderLines, indexHeaderKeys } from '../../src/tools.js';
import type { ParsedHeaderRow } from '../../src/tools.js';
import { fc, check, timeout, bytesFrom, chunkBuffer } from './helper.js';

// The verifier reads the body hash of every l= value from one hasher of the whole body (a
// copy of the running hash at each limit), and picks the signed header fields through an index
// of the header rows. Both must give exactly what the direct computation gives

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

    it('picks the same header rows through the index as by scanning', () =>
        check(
            fc.property(
                fc.array(fc.constantFrom('from', 'to', 'subject', 'x-a', null), { maxLength: 30 }),
                fc.array(fc.constantFrom('from', 'to', 'subject', 'x-a', 'x-missing', 'FROM', ' from'), { maxLength: 12 }),
                (keys, names) => {
                    let rows = keys.map(
                        (key, i) => ({ key, casedKey: key ? key.toUpperCase() : undefined, line: Buffer.from(`${key}: ${i}`) }) as ParsedHeaderRow
                    );
                    let h = names.join(':');
                    let scanned = getSigningHeaderLines(rows, h, true);
                    let indexed = getSigningHeaderLines(rows, h, true, indexHeaderKeys(rows));
                    expect(indexed.keys).to.equal(scanned.keys);
                    expect(indexed.headers.length).to.equal(scanned.headers.length);
                    indexed.headers.forEach((row, i) => expect(row).to.equal(scanned.headers[i]));
                }
            ),
            500
        ));
});
