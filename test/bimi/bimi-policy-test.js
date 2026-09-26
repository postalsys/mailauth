/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const { bimi } = require('../../lib/bimi');
const { zoneResolver } = require('../helpers/dns-zone');

chai.config.includeStack = true;

const dmarcResult = extra => ({
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
        const result = await bimi({ dmarc: dmarcResult({ policy: 'quarantine', testMode: true }), resolver });

        expect(result.status.result).to.equal('skipped');
        expect(result.status.comment).to.equal('too lax DMARC policy');
        expect(resolver.calls).to.have.lengthOf(0);
    });

    it('Should skip a domain with policy none', async () => {
        const result = await bimi({ dmarc: dmarcResult({ policy: 'none' }), resolver: zoneResolver({}) });

        expect(result.status.comment).to.equal('too lax DMARC policy');
    });

    it('Should look up the BIMI record for an enforcing quarantine policy', async () => {
        const resolver = zoneResolver({});
        const result = await bimi({ dmarc: dmarcResult({ policy: 'quarantine' }), resolver });

        expect(result.status.comment).to.not.equal('too lax DMARC policy');
        expect(resolver.calls.map(call => call.name)).to.include('default._bimi.example.com');
    });
});
