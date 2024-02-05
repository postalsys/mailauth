/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

let parseDkimHeaders = require('../../lib/parse-dkim-headers');

chai.config.includeStack = true;

describe('parseDkimHeaders Tests', () => {
    it('Should parse ARC header', () => {
        let parsed = parseDkimHeaders(
            'i=1; mx.microsoft.com 1; spf=fail (sender ip is 52.138.216.130) smtp.rcpttodomain=recipient.com smtp.mailfrom=sender.com; dmarc=fail (p=reject sp=reject pct=100) action=oreject header.from=sender.com; dkim=none (message not signed); arc=none (0)'
        );

        expect(parsed.parsed.arc.value).to.equal('none');
    });
});
