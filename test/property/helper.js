'use strict';

// Shared settings for the property-based tests in this directory.
//
// The runs are deterministic: every property starts from the same seed, so a failure in CI can
// be reproduced locally. fast-check puts the seed, the shrunk counterexample and the replay path
// into the error message of a failing property.
//
// Environment variables:
//   FC_NUM_RUNS  number of generated cases per property (default: the per-property value,
//                kept small so that `npm test` stays fast). Raise it to search harder:
//                FC_NUM_RUNS=5000 npx mocha "test/property/*-test.js"
//   FC_SEED      seed to use, or "random" for a new seed on every run

const fc = require('fast-check');

const DEFAULT_SEED = 0x6d61696c; // "mail"

// "medium" lets strings and arrays grow past the 10 elements of the default "small" size, so
// long lines, long bodies and long tag-lists are generated too. It is a global setting of
// fast-check, which only these tests use
fc.configureGlobal({ ...fc.readConfigureGlobal(), baseSize: 'medium' });

const getSeed = () => {
    let value = process.env.FC_SEED;
    if (!value) {
        return DEFAULT_SEED;
    }
    if (value === 'random') {
        return undefined;
    }
    let seed = Number(value);
    if (!Number.isInteger(seed)) {
        throw new Error(`FC_SEED must be an integer or "random", got ${JSON.stringify(value)}`);
    }
    return seed;
};

const getNumRuns = defaultRuns => {
    let value = Number(process.env.FC_NUM_RUNS);
    return Number.isInteger(value) && value > 0 ? value : defaultRuns;
};

// Runs a property with the shared settings. `numRuns` is the default for this property, the
// FC_NUM_RUNS environment variable overrides it
const check = (property, numRuns) => {
    let params = { numRuns: getNumRuns(numRuns || 100) };
    let seed = getSeed();
    if (typeof seed === 'number') {
        params.seed = seed;
    }
    return fc.assert(property, params);
};

// Mocha timeout for a property test, scaled with the number of runs
const timeout = (numRuns, msPerRun) => Math.max(10000, getNumRuns(numRuns) * (msPerRun || 20));

// Byte strings as latin1 ("binary") strings, which keep one character per byte
const bytesFrom = (alphabet, constraints) => fc.string({ unit: fc.constantFrom(...alphabet.split('')), ...(constraints || {}) });

// Splits a buffer into chunks at the given cut points
const chunkBuffer = (buf, cuts) => {
    let points = Array.from(new Set(cuts.map(cut => cut % (buf.length + 1)))).sort((a, b) => a - b);
    let chunks = [];
    let last = 0;
    for (let point of points) {
        chunks.push(buf.subarray(last, point));
        last = point;
    }
    chunks.push(buf.subarray(last));
    return chunks;
};

module.exports = { fc, check, timeout, bytesFrom, chunkBuffer };
