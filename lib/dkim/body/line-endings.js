'use strict';

const { Buffer } = require('node:buffer');

const CHAR_CR = 0x0d;
const CHAR_LF = 0x0a;

// A run of line endings at the end of the body is held back until it is known whether any
// content follows it, because RFC 6376 drops it if none does. Both canonicalizations count
// the CRLF pairs in that run instead of keeping the buffers they arrived in: the message
// parser hands over one small buffer per line, and each of those pins the whole pool it
// was allocated from, so a body of nothing but line breaks was retained about two hundred
// times over. The pairs are written back out from this one shared buffer, which is built
// with Buffer.alloc because Buffer.from would pool it and pin a slab for the same reason
const EMPTY_LINE_BATCH = 512;
const CRLF_RUN = Buffer.alloc(EMPTY_LINE_BATCH * 2);
for (let i = 0; i < CRLF_RUN.length; i += 2) {
    CRLF_RUN[i] = CHAR_CR;
    CRLF_RUN[i + 1] = CHAR_LF;
}

const CRLF = CRLF_RUN.subarray(0, 2);

// Calls back with every held back CRLF pair, in batches. The caller owns the counter and
// has to clear it
const eachHeldLineBreak = (count, fn) => {
    while (count > 0) {
        let batch = Math.min(count, EMPTY_LINE_BATCH);
        fn(CRLF_RUN.subarray(0, batch * 2));
        count -= batch;
    }
};

module.exports = { CHAR_CR, CHAR_LF, CRLF, eachHeldLineBreak };
