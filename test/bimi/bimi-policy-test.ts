/* eslint @typescript-eslint/no-unused-expressions:0 */
import { describe, it } from 'node:test';
import { expect, config } from 'chai';

import { bimi } from '../../src/bimi/index.js';
import { zoneResolver } from '../helpers/dns-zone.js';

config.includeStack = true;

const dmarcResult = (extra: any) => ({
    status: { result: 'pass', header: { from: 'example.com', d: 'example.com' } },
    domain: 'example.com',
    policy: 'reject',
    testMode: false,
    alignment: { spf: { strict: false }, dkim: { result: 'example.com', strict: false } },
    ...extra
});

describe('BIMI DMARC policy requirements', () => {
    it('Should skip a domain that tests its DMARC policy (t=y)', async () => {
        const resolver = zoneResolver({});
        const result: any = await bimi({ dmarc: dmarcResult({ policy: 'quarantine', testMode: true }), resolver } as any);

        expect(result.status.result).to.equal('skipped');
        expect(result.status.comment).to.equal('too lax DMARC policy');
        expect(resolver.calls).to.have.lengthOf(0);
    });

    it('Should skip a domain with policy none', async () => {
        const result: any = await bimi({ dmarc: dmarcResult({ policy: 'none' }), resolver: zoneResolver({}) } as any);

        expect(result.status.comment).to.equal('too lax DMARC policy');
    });

    it('Should look up the BIMI record for an enforcing quarantine policy', async () => {
        const resolver = zoneResolver({});
        const result: any = await bimi({ dmarc: dmarcResult({ policy: 'quarantine' }), resolver } as any);

        expect(result.status.comment).to.not.equal('too lax DMARC policy');
        expect(resolver.calls.map(call => call.name)).to.include('default._bimi.example.com');
    });
});
