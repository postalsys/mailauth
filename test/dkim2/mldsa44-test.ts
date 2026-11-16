/* eslint @typescript-eslint/no-unused-expressions:0 */
// ML-DSA-44 verification without node:crypto ML-DSA (src/dkim2/mldsa44.ts), which Node.js 20 and 22
// use, as draft-ietf-dkim-dkim2-spec-09 section 3 has verifiers implement every algorithm

import { describe, it } from 'node:test';
import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, config } from 'chai';

import { mlDsa44Verify, internals as M } from '../../src/dkim2/mldsa44.js';
import { supportsMlDsa, verifySignature } from '../../src/dkim2/algorithms.js';
import { createKeyLookup } from '../../src/dkim2/key.js';
import { dkim2Verify } from '../../src/dkim2/verify.js';
import { resolver } from '../helpers/dkim2.js';

config.includeStack = true;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vector = JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/dkim2-croessner/custody-crypto-golden.json'), 'utf8')).mldsa44_vector;
const signed = JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/dkim2-mldsa44.json'), 'utf8'));

const CONTEXT = Buffer.from('DKIM2');
const publicKey = Buffer.from(vector.public_raw_base64, 'base64');
const input = Buffer.from(vector.input_base64, 'base64');
const signatures = [Buffer.from(vector.deterministic_signature_base64, 'base64'), Buffer.from(vector.openssl_hedged_signature_base64, 'base64')];

// a copy of a buffer with one byte changed
const withByte = (buffer: Buffer, pos: number, value: number) => {
    let copy = Buffer.from(buffer);
    copy[pos] = value;
    return copy;
};

// the offsets of the signature parts: c~ (32 bytes), z (4 x 576 bytes), hints (80 + 4 bytes)
const Z_START = 32;
const HINT_START = 32 + 4 * 576;
const HINT_COUNTS = HINT_START + 80;

describe('ML-DSA-44 verification in JavaScript (FIPS 204)', () => {
    it('accepts the deterministic and the hedged signature of the croessner/dkim2 vector', () => {
        for (let signature of signatures) {
            expect(mlDsa44Verify(publicKey, input, signature, CONTEXT)).to.be.true;
        }
    });

    it('rejects another message, another context, or no context', () => {
        for (let signature of signatures) {
            expect(mlDsa44Verify(publicKey, Buffer.concat([input, Buffer.from(' ')]), signature, CONTEXT)).to.be.false;
            expect(mlDsa44Verify(publicKey, input.subarray(1), signature, CONTEXT)).to.be.false;
            expect(mlDsa44Verify(publicKey, input, signature, Buffer.from('DKIM3'))).to.be.false;
            expect(mlDsa44Verify(publicKey, input, signature, Buffer.alloc(0))).to.be.false;
        }
    });

    it('rejects keys, signatures and contexts of the wrong length', () => {
        let [signature] = signatures;
        expect(mlDsa44Verify(publicKey.subarray(1), input, signature, CONTEXT)).to.be.false;
        expect(mlDsa44Verify(Buffer.concat([publicKey, Buffer.alloc(1)]), input, signature, CONTEXT)).to.be.false;
        expect(mlDsa44Verify(publicKey, input, signature.subarray(1), CONTEXT)).to.be.false;
        expect(mlDsa44Verify(publicKey, input, Buffer.concat([signature, Buffer.alloc(1)]), CONTEXT)).to.be.false;
        expect(mlDsa44Verify(publicKey, input, Buffer.alloc(0), CONTEXT)).to.be.false;
        expect(mlDsa44Verify(publicKey, input, signature, Buffer.alloc(256))).to.be.false;
    });

    it('rejects a change in any part of the signature or the key', () => {
        let [signature] = signatures;
        // c~, every z polynomial, the hint positions and the hint counts
        for (let pos of [0, 31, Z_START, Z_START + 575, Z_START + 576 * 3 + 100, HINT_START, HINT_COUNTS - 1, HINT_COUNTS, HINT_COUNTS + 3]) {
            expect(mlDsa44Verify(publicKey, input, withByte(signature, pos, signature[pos] ^ 1), CONTEXT), `byte ${pos}`).to.be.false;
        }
        // rho and every t1 polynomial
        for (let pos of [0, 31, 32, 32 + 320, 32 + 320 * 3 + 319]) {
            expect(mlDsa44Verify(withByte(publicKey, pos, publicKey[pos] ^ 1), input, signature, CONTEXT), `key byte ${pos}`).to.be.false;
        }
    });

    it('rejects hints that are not encoded as FIPS 204 Algorithm 21 requires', () => {
        let [signature] = signatures;
        let counts = signature.subarray(HINT_COUNTS, HINT_COUNTS + 4);
        let used = counts[3];
        // a count above omega
        expect(mlDsa44Verify(publicKey, input, withByte(signature, HINT_COUNTS + 3, 81), CONTEXT)).to.be.false;
        // counts that go down
        expect(mlDsa44Verify(publicKey, input, withByte(signature, HINT_COUNTS + 1, counts[0] > 0 ? counts[0] - 1 : 81), CONTEXT)).to.be.false;
        // a non-zero byte after the last hint
        if (used < 80) {
            expect(mlDsa44Verify(publicKey, input, withByte(signature, HINT_START + used, 1), CONTEXT)).to.be.false;
        }
        // hint positions of one polynomial that are not in ascending order
        if (counts[0] >= 2) {
            let swapped = Buffer.from(signature);
            [swapped[HINT_START], swapped[HINT_START + 1]] = [signature[HINT_START + 1], signature[HINT_START]];
            expect(mlDsa44Verify(publicKey, input, swapped, CONTEXT)).to.be.false;
        }
    });

    it('rejects a z coefficient at or above gamma1 - beta', () => {
        let [signature] = signatures;
        // the first 18 bit z value is gamma1 - stored value, a stored 0 gives z = gamma1
        let large = Buffer.from(signature);
        large[Z_START] = 0;
        large[Z_START + 1] = 0;
        large[Z_START + 2] &= 0xfc;
        expect(mlDsa44Verify(publicKey, input, large, CONTEXT)).to.be.false;
    });

    describe('signatures built for a key with t1 = 0', () => {
        // With t1 = 0 the verifier computes w' = A z, which does not depend on c~, so any z and hints
        // give a signature that verifies once c~ = H(mu || w1Encode(UseHint(h, A z))). Changing only
        // z, or only the hint encoding, then shows that its own check rejects
        const Q = 8380417;
        const GAMMA1 = 1 << 17;
        const LIMIT = GAMMA1 - 78;
        const HALF_ALPHA = (Q - 1) / 88;
        const rho = crypto.createHash('sha256').update('mailauth').digest();
        const key = Buffer.concat([rho, Buffer.alloc(1280)]);
        const message = Buffer.from('message');

        // the 2420 byte signature of c~, z and hint positions per polynomial
        const encode = (cTilde: Buffer, z: number[][], hints: Buffer) =>
            Buffer.concat([
                cTilde,
                ...z.map(poly =>
                    M.packBits(
                        poly.map(value => GAMMA1 - value),
                        18
                    )
                ),
                hints
            ]);
        const hintBytes = (positions: number[][]) => {
            let y = Buffer.alloc(84);
            let index = 0;
            positions.forEach((list, i) => {
                for (let position of list) {
                    y[index++] = position;
                }
                y[80 + i] = index;
            });
            return y;
        };
        // the w' coefficients of z, and the c~ that makes z and the hints h verify
        const azOf = (z: number[][]) => {
            let zHat = z.map(poly => M.ntt(poly.map(M.mod)));
            return [0, 1, 2, 3].map(i => {
                let acc: number[] = new Array(256).fill(0);
                for (let j = 0; j < 4; j++) {
                    let a = M.rejNttPoly(Buffer.concat([rho, Buffer.from([j, i])]));
                    for (let n = 0; n < 256; n++) {
                        acc[n] = M.mod(acc[n] + M.mul(a[n], zHat[j][n]));
                    }
                }
                return M.inverseNtt(acc);
            });
        };
        const cTildeOf = (az: number[][], h: number[][], context: Buffer) => {
            let tr = M.shake('shake256', [key], 64);
            let mu = M.shake('shake256', [tr, Buffer.from([0, context.length]), context, message], 64);
            let w1 = az.flatMap((poly, i) => poly.map((value, n) => M.useHint(h[i][n], value)));
            return M.shake('shake256', [mu, M.packBits(w1, 6)], 32);
        };
        const hintsOf = (positions: number[][]) => positions.map(list => Array.from({ length: 256 }, (v, n) => (list.includes(n) ? 1 : 0)));
        const zOf = (value: (i: number, n: number) => number) => [0, 1, 2, 3].map(i => Array.from({ length: 256 }, (v, n) => value(i, n)));
        const nodeVerify = (signature: Buffer, context: Buffer) =>
            crypto.verify(
                null,
                message,
                {
                    key: crypto.createPublicKey({
                        key: Buffer.concat([Buffer.from('30820532300b06096086480165030403110382052100', 'hex'), key]),
                        format: 'der',
                        type: 'spki'
                    }),
                    context
                } as any,
                signature
            );
        // our result, and the node:crypto result where Node.js has ML-DSA
        const verifyBoth = (signature: Buffer, context = CONTEXT) => {
            let ours = mlDsa44Verify(key, message, signature, context);
            if (supportsMlDsa()) {
                expect(nodeVerify(signature, context), 'node:crypto').to.equal(ours);
            }
            return ours;
        };

        const zMax = zOf((i, n) => ((i + n) % 2 ? LIMIT - 1 : -(LIMIT - 1)));
        const azMax = azOf(zMax);
        const positions = [[1, 7, 200], [], [0, 255], [42]];

        it('accepts z at the largest allowed value and hints in every polynomial', () => {
            let h = hintsOf(positions);
            expect(verifyBoth(encode(cTildeOf(azMax, h, CONTEXT), zMax, hintBytes(positions)))).to.be.true;
            // the same with no hints at all, and with a context of 255 bytes
            let none = hintsOf([[], [], [], []]);
            expect(verifyBoth(encode(cTildeOf(azMax, none, CONTEXT), zMax, hintBytes([[], [], [], []])))).to.be.true;
            let long = Buffer.alloc(255, 9);
            expect(verifyBoth(encode(cTildeOf(azMax, h, long), zMax, hintBytes(positions)), long)).to.be.true;
        });

        it('rejects a z coefficient of gamma1 - beta or more, in either direction', () => {
            for (let bad of [LIMIT, -LIMIT, GAMMA1, -(GAMMA1 - 1), LIMIT + 1]) {
                let z = zMax.map(poly => poly.slice());
                z[2][100] = bad;
                let h = hintsOf(positions);
                expect(verifyBoth(encode(cTildeOf(azOf(z), h, CONTEXT), z, hintBytes(positions))), `z = ${bad}`).to.be.false;
            }
        });

        it('rejects hint encodings that FIPS 204 Algorithm 21 does not allow, whatever c~ says', () => {
            let h = hintsOf(positions);
            let cTilde = cTildeOf(azMax, h, CONTEXT);
            let good = hintBytes(positions);
            let variants: [string, Buffer][] = [];
            const variant = (label: string, change: (y: Buffer) => void) => {
                let y = Buffer.from(good);
                change(y);
                variants.push([label, y]);
            };
            variant('non-zero padding', y => (y[10] = 1));
            variant('a count above omega', y => (y[83] = 81));
            variant('a count that goes down', y => (y[81] = 2));
            variant('positions out of order', y => ([y[0], y[1]] = [y[1], y[0]]));
            variant('a repeated position', y => (y[1] = y[0]));
            // the same hints decode the same with the strict and a lenient reading only when valid
            expect(verifyBoth(encode(cTilde, zMax, good))).to.be.true;
            for (let [label, y] of variants) {
                expect(verifyBoth(encode(cTilde, zMax, y)), label).to.be.false;
            }
        });

        it('applies a hint on a coefficient where r+ - r0 = q - 1 (FIPS 204 Algorithm 36)', () => {
            // find coefficients of A z whose decomposition takes the q - 1 branch, by searching z
            let found: [number, number][] = [];
            let z = zMax;
            let az = azMax;
            for (let attempt = 0; attempt < 400 && !found.length; attempt++) {
                z = zOf((i, n) => ((((i * 7 + n * 13 + attempt * 31) % 509) * 517) % (2 * LIMIT - 1)) - (LIMIT - 1));
                az = azOf(z);
                az.forEach((poly, i) =>
                    poly.forEach((value, n) => {
                        let r0 = value % (2 * HALF_ALPHA);
                        if (r0 > HALF_ALPHA) {
                            r0 -= 2 * HALF_ALPHA;
                        }
                        if (value - r0 === Q - 1) {
                            found.push([i, n]);
                        }
                    })
                );
            }
            expect(found.length, 'a coefficient on the q - 1 branch').to.be.greaterThan(0);
            let [i, n] = found[0];
            expect(M.decompose(az[i][n])[0]).to.equal(0);
            let hinted = [[], [], [], []] as number[][];
            hinted[i] = [n];
            let h = hintsOf(hinted);
            expect(verifyBoth(encode(cTildeOf(az, h, CONTEXT), z, hintBytes(hinted)))).to.be.true;
            // a c~ made without the hint does not verify with it
            expect(verifyBoth(encode(cTildeOf(az, hintsOf([[], [], [], []]), CONTEXT), z, hintBytes(hinted)))).to.be.false;
        });
    });

    it('is used for a bare ML-DSA-44 key by verifySignature()', () => {
        for (let signature of signatures) {
            expect(verifySignature('mldsa44', input, publicKey, signature)).to.be.true;
            expect(verifySignature('ed25519-sha256', input, publicKey, signature)).to.be.false;
        }
    });

    it('reads a k=mldsa44 key record on every Node.js version', async () => {
        let lookup = createKeyLookup(async () => [[`v=DKIM1; k=mldsa44; p=${vector.public_raw_base64}`]]);
        let key = await lookup('example.com', 'pq', 'mldsa44');
        expect(verifySignature('mldsa44', input, key.publicKey!, signatures[1])).to.be.true;
        // a KeyObject where Node.js has ML-DSA, the bare key where it does not
        expect(Buffer.isBuffer(key.publicKey)).to.equal(!supportsMlDsa());

        let short = createKeyLookup(async () => [[`v=DKIM1; k=mldsa44; p=${publicKey.subarray(1).toString('base64')}`]]);
        let err = await short('example.com', 'pq', 'mldsa44').catch(err => err);
        expect(err.message).to.equal('is malformed');
    });

    it('agrees with node:crypto on random keys, messages and contexts', { skip: !supportsMlDsa() && 'Node.js has no ML-DSA' }, () => {
        for (let n = 0; n < 24; n++) {
            let { privateKey, publicKey: keyObject } = crypto.generateKeyPairSync('ml-dsa-44' as any);
            let raw = keyObject.export({ type: 'spki', format: 'der' }).subarray(-1312);
            let message = crypto.randomBytes(n * 53);
            let context = n % 3 ? CONTEXT : crypto.randomBytes(n % 2 ? 255 : 0);
            let signature = crypto.sign(null, message, { key: privateKey, context } as any);
            let changed = withByte(signature, (n * 101) % signature.length, signature[(n * 101) % signature.length] ^ (1 << (n % 8)));
            for (let [m, s] of [
                [message, signature],
                [message, changed],
                [Buffer.concat([message, Buffer.from([n])]), signature]
            ]) {
                let node = crypto.verify(null, m, { key: keyObject, context } as any, s);
                expect(mlDsa44Verify(raw, m, s, context), `case ${n}`).to.equal(node);
            }
        }
    });

    describe('messages signed with ML-DSA-44 on Node.js 24 (test/fixtures/dkim2-mldsa44.json)', () => {
        const zone = () => resolver({ 'pq._domainkey.example.com': { TXT: [[signed.keyRecord]] } });
        const options = () => ({ resolver: zone(), mailFrom: 'sender@example.com', rcptTo: 'rcpt@example.net', curTime: new Date('2026-11-01T00:01:00Z') });

        for (let name of ['alone', 'alternative', 'hybrid']) {
            it(`verifies the ${name} signature`, async () => {
                let result = await dkim2Verify(Buffer.from(signed[name], 'binary'), options());
                expect(result.status.result, result.status.comment).to.equal('pass');
                let pq = result.signatures[0].values.find(entry => entry.selector === 'pq')!;
                expect(pq).to.deep.include({ algorithm: 'mldsa44', result: 'pass' });
            });
        }

        it('fails a changed message', async () => {
            let changed = Buffer.from(signed.alone.replace('Hello world!', 'Hello World!'), 'binary');
            let result = await dkim2Verify(changed, options());
            expect(result.status.result).to.equal('fail');

            // a changed ML-DSA-44 signature value
            let value = Buffer.from(
                signed.alone.replace(/(s=pq:mldsa44:\s*)(.)/, (m: string, lead: string, c: string) => lead + (c === 'A' ? 'B' : 'A')),
                'binary'
            );
            let tampered = await dkim2Verify(value, options());
            expect(tampered.status.comment).to.equal('DKIM2-Signature i=1 selector pq incorrect signature');
        });

        it('needs both signatures of the hybrid "," group', async () => {
            let result = await dkim2Verify(
                Buffer.from(signed.hybrid, 'binary'),
                Object.assign(options(), { resolver: resolver({ 'pq._domainkey.example.com': { TXT: [] } }) })
            );
            expect(result.status.result).to.equal('permerror');
            expect(result.status.comment).to.equal('DKIM2-Signature i=1 public key pq does not exist');
        });
    });
});
