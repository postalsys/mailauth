/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

let { parseReceived } = require('../lib/parse-received');

chai.config.includeStack = true;

describe('parseRecived Tests', () => {
    it('Should parse header from Haraka', async () => {
        const res = parseReceived(`Received: from mail-oi1-f179.google.com (mail-oi1-f179.google.com [209.85.167.179])
	by zonemx.eu (Haraka/2.8.25) with ESMTPS id B3C0198B-A390-42E9-9DDC-C57D8D207298.1
	envelope-from <andris.reinman@gmail.com>
	(cipher=TLS_AES_256_GCM_SHA384);
	Fri, 06 Nov 2020 12:20:14 +0000`);

        expect(res).to.deep.equal({
            from: {
                value: 'mail-oi1-f179.google.com',
                comment: 'mail-oi1-f179.google.com [209.85.167.179]'
            },
            by: { value: 'zonemx.eu', comment: 'Haraka/2.8.25' },
            with: { value: 'ESMTPS' },
            id: { value: 'B3C0198B-A390-42E9-9DDC-C57D8D207298.1' },
            tls: { value: '', comment: 'cipher=TLS_AES_256_GCM_SHA384' },
            'envelope-from': { value: '<andris.reinman@gmail.com>' },
            timestamp: 'Fri, 06 Nov 2020 12:20:14 +0000',
            full: 'Received: from mail-oi1-f179.google.com (mail-oi1-f179.google.com [209.85.167.179]) by zonemx.eu (Haraka/2.8.25) with ESMTPS id B3C0198B-A390-42E9-9DDC-C57D8D207298.1 envelope-from <andris.reinman@gmail.com> (cipher=TLS_AES_256_GCM_SHA384); Fri, 06 Nov 2020 12:20:14 +0000'
        });
    });

    it('Should keep the transport security of a hop with an unusable key', async () => {
        const res = parseReceived('Received: __proto__ (version=TLS1_3 cipher=X) by mx.example.com; Mon, 1 Jan 2024 00:00:00 +0000');

        expect(res.tls).to.deep.equal({ value: '', comment: 'version=TLS1_3 cipher=X' });
        // the key itself is not assigned, it would replace the prototype of the parsed hop
        expect(Object.getPrototypeOf(res)).to.equal(Object.prototype);
        expect(Object.keys(res)).to.not.contain('__proto__');
    });
});
