// ML-DSA-44 signature verification (FIPS 204, Algorithms 3 and 8), for Node.js versions that do not
// have ML-DSA in node:crypto. draft-ietf-dkim-dkim2-spec-09 section 3 has verifiers implement every
// algorithm. Only verification is here: signers choose their algorithms, and sign with node:crypto.
// Everything is computed on public data, so nothing has to run in constant time.

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';

// FIPS 204 section 4, Table 1, the ML-DSA-44 parameters
const Q = 8380417;
const N = 256;
const D = 13;
const TAU = 39;
const LAMBDA = 128;
const GAMMA1 = 1 << 17;
const GAMMA2 = (Q - 1) / 88;
const K = 4;
const L = 4;
const ETA = 2;
const BETA = TAU * ETA;
const OMEGA = 80;

const PUBLIC_KEY_LENGTH = 32 + 32 * K * 10;
const C_TILDE_LENGTH = LAMBDA / 4;
const Z_POLY_LENGTH = 32 * 18;
const SIGNATURE_LENGTH = C_TILDE_LENGTH + L * Z_POLY_LENGTH + OMEGA + K;

// Appendix B: the powers of the root of unity 1753 in bit-reversed order
const ZETAS: number[] = (() => {
    let zetas: number[] = [];
    for (let k = 0; k < N; k++) {
        let exponent = parseInt(k.toString(2).padStart(8, '0').split('').reverse().join(''), 2);
        let value = 1n;
        for (let i = 0; i < exponent; i++) {
            value = (value * 1753n) % BigInt(Q);
        }
        zetas.push(Number(value));
    }
    return zetas;
})();

// 256^-1 mod q, the scaling of the inverse NTT
const N_INVERSE = 8347681;

// a mod q in [0, q), for products of two values below q, which stay exact as doubles
const mod = (a: number): number => {
    let r = a % Q;
    return r < 0 ? r + Q : r;
};

const mul = (a: number, b: number): number => mod(a * b);

// Algorithm 41
const ntt = (input: number[]): number[] => {
    let w = input.slice();
    let m = 0;
    for (let len = 128; len >= 1; len >>= 1) {
        for (let start = 0; start < N; start += 2 * len) {
            let zeta = ZETAS[++m];
            for (let j = start; j < start + len; j++) {
                let t = mul(zeta, w[j + len]);
                w[j + len] = mod(w[j] - t);
                w[j] = mod(w[j] + t);
            }
        }
    }
    return w;
};

// Algorithm 42
const inverseNtt = (input: number[]): number[] => {
    let w = input.slice();
    let m = N;
    for (let len = 1; len < N; len <<= 1) {
        for (let start = 0; start < N; start += 2 * len) {
            let zeta = Q - ZETAS[--m];
            for (let j = start; j < start + len; j++) {
                let t = w[j];
                w[j] = mod(t + w[j + len]);
                w[j + len] = mul(zeta, mod(t - w[j + len]));
            }
        }
    }
    return w.map(value => mul(value, N_INVERSE));
};

// SHAKE output of at least `length` bytes. An XOF gives the same prefix for any length, so a
// longer output can be asked for when rejection sampling needs more bytes
const shake = (algorithm: 'shake128' | 'shake256', data: Buffer[], length: number): Buffer => {
    let hash = crypto.createHash(algorithm, { outputLength: length });
    for (let part of data) {
        hash.update(part);
    }
    return hash.digest();
};

// Reads `count` values of `bits` bits each, least significant bit first (Algorithms 18 and 19)
const unpackBits = (bytes: Buffer, bits: number, count: number): number[] => {
    let values: number[] = [];
    let buffer = 0;
    let available = 0;
    let pos = 0;
    for (let i = 0; i < count; i++) {
        while (available < bits) {
            buffer += bytes[pos++] * 2 ** available;
            available += 8;
        }
        let value = buffer % 2 ** bits;
        values.push(value);
        buffer = Math.floor(buffer / 2 ** bits);
        available -= bits;
    }
    return values;
};

// Writes values of `bits` bits each, least significant bit first (Algorithm 16)
const packBits = (values: number[], bits: number): Buffer => {
    let bytes: number[] = [];
    let buffer = 0;
    let available = 0;
    for (let value of values) {
        buffer += value * 2 ** available;
        available += bits;
        while (available >= 8) {
            bytes.push(buffer % 256);
            buffer = Math.floor(buffer / 256);
            available -= 8;
        }
    }
    return Buffer.from(bytes);
};

// Algorithm 30, one polynomial of ExpandA (Algorithm 32) in the NTT domain. It starts with the
// three bytes per coefficient that are enough when nothing is rejected, and reads more otherwise
const rejNttPoly = (seed: Buffer): number[] => {
    for (let length = 3 * N; ; length *= 2) {
        let stream = shake('shake128', [seed], length);
        let a: number[] = [];
        for (let pos = 0; a.length < N && pos + 3 <= stream.length; pos += 3) {
            // Algorithm 14: the top bit of the third byte is not used
            let z = (stream[pos + 2] & 0x7f) * 65536 + stream[pos + 1] * 256 + stream[pos];
            if (z < Q) {
                a.push(z);
            }
        }
        if (a.length === N) {
            return a;
        }
    }
};

// Algorithm 29. It starts with the 8 sign bytes and one byte per coefficient, and reads more
// when a byte is rejected
const sampleInBall = (cTilde: Buffer): number[] => {
    for (let length = 8 + TAU; ; length *= 2) {
        let stream = shake('shake256', [cTilde], length);
        let c: number[] = new Array(N).fill(0);
        let pos = 8;
        let complete = true;
        for (let i = N - TAU; i < N; i++) {
            let j: number;
            do {
                if (pos >= stream.length) {
                    complete = false;
                    break;
                }
                j = stream[pos++];
            } while (j > i);
            if (!complete) {
                break;
            }
            let bit = i + TAU - N;
            let sign = (stream[bit >> 3] >> (bit & 7)) & 1;
            c[i] = c[j!];
            c[j!] = sign ? Q - 1 : 1;
        }
        if (complete) {
            return c;
        }
    }
};

// Algorithm 21, null for a malformed hint
const hintBitUnpack = (y: Buffer): number[][] | null => {
    let h: number[][] = Array.from({ length: K }, () => new Array(N).fill(0));
    let index = 0;
    for (let i = 0; i < K; i++) {
        let end = y[OMEGA + i];
        if (end < index || end > OMEGA) {
            return null;
        }
        let first = index;
        while (index < end) {
            if (index > first && y[index - 1] >= y[index]) {
                return null;
            }
            h[i][y[index]] = 1;
            index++;
        }
    }
    for (let i = index; i < OMEGA; i++) {
        if (y[i] !== 0) {
            return null;
        }
    }
    return h;
};

// Algorithm 36 for 2 * gamma2, returns [r1, r0]
const decompose = (r: number): [number, number] => {
    let rPlus = mod(r);
    let r0 = rPlus % (2 * GAMMA2);
    if (r0 > GAMMA2) {
        r0 -= 2 * GAMMA2;
    }
    if (rPlus - r0 === Q - 1) {
        return [0, r0 - 1];
    }
    return [(rPlus - r0) / (2 * GAMMA2), r0];
};

// Algorithm 40
const useHint = (h: number, r: number): number => {
    let m = (Q - 1) / (2 * GAMMA2);
    let [r1, r0] = decompose(r);
    if (h === 1) {
        return r0 > 0 ? (r1 + 1) % m : (r1 - 1 + m) % m;
    }
    return r1;
};

/**
 * ML-DSA.Verify of FIPS 204 (Algorithm 3) for ML-DSA-44, pure ML-DSA with a context string
 *
 * @param {Buffer} publicKey The 1312 byte public key
 * @param {Buffer} message The signed data
 * @param {Buffer} signature The 2420 byte signature
 * @param {Buffer} context The context string, at most 255 bytes
 * @returns {Boolean}
 */
const mlDsa44Verify = (publicKey: Buffer, message: Buffer, signature: Buffer, context: Buffer): boolean => {
    if (publicKey.length !== PUBLIC_KEY_LENGTH || signature.length !== SIGNATURE_LENGTH || context.length > 255) {
        return false;
    }

    // Algorithm 23 (pkDecode)
    let rho = publicKey.subarray(0, 32);
    let t1 = Array.from({ length: K }, (v, i) => unpackBits(publicKey.subarray(32 + i * 320, 32 + (i + 1) * 320), 10, N));

    // Algorithm 27 (sigDecode)
    let cTilde = signature.subarray(0, C_TILDE_LENGTH);
    let z = Array.from({ length: L }, (v, i) =>
        unpackBits(signature.subarray(C_TILDE_LENGTH + i * Z_POLY_LENGTH, C_TILDE_LENGTH + (i + 1) * Z_POLY_LENGTH), 18, N).map(value => GAMMA1 - value)
    );
    let h = hintBitUnpack(signature.subarray(C_TILDE_LENGTH + L * Z_POLY_LENGTH));
    if (!h) {
        return false;
    }

    // ||z||inf < gamma1 - beta
    if (z.some(poly => poly.some(value => Math.abs(value) >= GAMMA1 - BETA))) {
        return false;
    }

    // Algorithm 3: M' = 0 || |ctx| || ctx || M, then Algorithm 8
    let tr = shake('shake256', [publicKey], 64);
    let mu = shake('shake256', [tr, Buffer.from([0, context.length]), context, message], 64);
    let cHat = ntt(sampleInBall(cTilde));
    let zHat = z.map(poly => ntt(poly.map(mod)));

    let w1: number[] = [];
    for (let i = 0; i < K; i++) {
        let acc: number[] = new Array(N).fill(0);
        for (let j = 0; j < L; j++) {
            let a = rejNttPoly(Buffer.concat([rho, Buffer.from([j, i])]));
            for (let n = 0; n < N; n++) {
                acc[n] = mod(acc[n] + mul(a[n], zHat[j][n]));
            }
        }
        let t1Hat = ntt(t1[i].map(value => value * 2 ** D));
        for (let n = 0; n < N; n++) {
            acc[n] = mod(acc[n] - mul(cHat[n], t1Hat[n]));
        }
        let wApprox = inverseNtt(acc);
        // Algorithm 28 (w1Encode), six bits for every coefficient of w1
        w1.push(...wApprox.map((value, n) => useHint(h[i][n], value)));
    }

    let expected = shake('shake256', [mu, packBits(w1, 6)], C_TILDE_LENGTH);
    return expected.equals(cTilde);
};

// the building blocks, for tests that construct signatures
const internals = { ntt, inverseNtt, mod, mul, rejNttPoly, useHint, decompose, shake, packBits };

export { mlDsa44Verify, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, internals };
