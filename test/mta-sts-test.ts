/* eslint @typescript-eslint/no-unused-expressions:0 */
import { describe, it } from 'node:test';
import { expect, config } from 'chai';

import { getPolicy, validateMx } from '../src/mta-sts.js';

config.includeStack = true;

// NB! these tests perform live DNS and HTTPS queries

describe('MTA-STS Tests', () => {
    it('Should pass valid MX', { timeout: 15000 }, async () => {
        const { policy } = await getPolicy('gmail.com');
        const policyMatch = validateMx('alt4.gmail-smtp-in.l.google.com', policy);
        expect(policyMatch.valid).to.be.true;
        expect(policy.mode).to.equal('enforce');
    });

    it('Should discard invalid MX', { timeout: 15000 }, async () => {
        const { policy } = await getPolicy('gmail.com');
        const policyMatch = validateMx('alt4.gmail-smtp-in.l.zoogle.com', policy);
        expect(policyMatch.valid).to.be.false;
        expect(policy.mode).to.equal('enforce');
    });

    it('Should pass any MX', { timeout: 15000 }, async () => {
        const { policy } = await getPolicy('unknown.kreata.ee');
        const policyMatch = validateMx('alt4.gmail-smtp-in.l.zoogle.com', policy);
        expect(policyMatch.valid).to.be.true;
        expect(policy.mode).to.equal('none');
    });
});
