'use strict';

const chai = require('chai');
const expect = chai.expect;

chai.config.includeStack = true;

// example test
describe('mailauth', () => {
    it('should work', async () => {
        let a = 1;
        await new Promise(r => setTimeout(r, 100));
        expect(a).to.equal(1);
    }).timeout(2000);
});
