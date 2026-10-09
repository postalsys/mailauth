/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const { stripRootDot } = require('../../lib/spf/syntax');

chai.config.includeStack = true;

describe('SPF syntax helpers', () => {
    describe('stripRootDot', () => {
        it('Should remove a single trailing dot only', () => {
            expect(stripRootDot('example.com.')).to.equal('example.com');
            expect(stripRootDot('example.com')).to.equal('example.com');
            expect(stripRootDot('example.com..')).to.equal('example.com..');
            expect(stripRootDot('.')).to.equal('.');
            expect(stripRootDot('')).to.equal('');
        });
    });
});
