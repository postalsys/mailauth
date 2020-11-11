/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

let { getPolicy, validateMx } = require('../lib/mta-sts');

chai.config.includeStack = true;

// NB! these tests perform live DNS and HTTPS queries

describe('MTA-STS Tests', () => {
    it('Should pass valid MX', async () => {
        const policy = await getPolicy('gmail.com');
        const policyMatch = validateMx('alt4.gmail-smtp-in.l.google.com', policy);
        expect(policyMatch).to.be.true;
        expect(policy.mode).to.equal('enforce');
    });

    it('Should discard invalid MX', async () => {
        const policy = await getPolicy('gmail.com');
        const policyMatch = validateMx('alt4.gmail-smtp-in.l.zoogle.com', policy);
        expect(policyMatch).to.be.false;
        expect(policy.mode).to.equal('enforce');
    });

    it('Should pass any MX', async () => {
        const policy = await getPolicy('unknown.kreata.ee');
        const policyMatch = validateMx('alt4.gmail-smtp-in.l.zoogle.com', policy);
        expect(policyMatch).to.be.true;
        expect(policy).to.be.false;
    });
});
