/* eslint no-unused-expressions:0 */
import { describe, it } from 'node:test';
import { expect, config } from 'chai';

import { stripRootDot } from '../../src/spf/syntax.js';

config.includeStack = true;

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
