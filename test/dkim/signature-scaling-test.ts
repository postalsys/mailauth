import { describe, it } from 'node:test';
import { Buffer } from 'node:buffer';
import { expect } from 'chai';

import { dkimVerify } from '../../src/dkim/verify.js';
import assertLinear, { time } from '../helpers/assert-linear.js';
import { zoneResolver } from '../helpers/dns-zone.js';

// Resource budgets for messages that carry many DKIM signatures. The signatures are only
// limited by the size of the header, so each one may only add a constant amount of work:
// looking up the signed header fields, the Content-Type and the l= body hashes used to cost
// work proportional to the number of signatures (or to the body size) for every signature

// every name is NXDOMAIN
const resolver = zoneResolver({});

const signatures = (count: number, l: (i: number) => number, h = 'from') => {
    let lines = [];
    for (let i = 0; i < count; i++) {
        lines.push(`DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s${i}; l=${l(i)}; h=${h}; bh=AAAA; b=BBBB\r\n`);
    }
    return lines.join('');
};

describe('DKIM verification of messages with many signatures', { timeout: 120 * 1000 }, () => {
    it('takes linear time in the number of signatures', async () => {
        // the Content-Type sits above the signatures, the h= names are missing from the header
        await assertLinear(
            count =>
                dkimVerify(
                    Buffer.from(
                        'Content-Type: multipart/mixed; boundary="b"\r\n' +
                            signatures(count, i => 100 + i, 'x-missing:x-missing:from') +
                            'From: a@example.com\r\n\r\n--b\r\n\r\nhi\r\n--b--\r\n'
                    ),
                    { resolver }
                ),
            1000
        );
    });

    it('hashes the body once however many l= values the signatures use', async () => {
        let body = ('x'.repeat(998) + '\r\n').repeat(1024);
        let verify = (count: number) => {
            let message = Buffer.from(signatures(count, i => body.length - i) + 'From: a@example.com\r\n\r\n' + body);
            return async () => {
                let res = await dkimVerify(message, { resolver });
                expect(res.results).to.have.length(count);
            };
        };
        await verify(1)(); // warm up
        let one = await time(verify(1));
        // hashing the 1 MB body for each of 300 signatures would take hundreds of times longer
        let many = await time(verify(300));
        expect(many, `${one.toFixed(1)} ms for one signature, ${many.toFixed(1)} ms for 300`).to.be.below(one * 10 + 100);
    });
});
