/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

let { spfVerify } = require('../../lib/spf');

chai.config.includeStack = true;

describe('SPF Verifier Tests', () => {
    it('Should pass all IPs', async () => {
        const stubResolver = () => [['v=spf1 +all']];

        let result = await spfVerify('example.com', { ip: '1.2.3.4', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');
    });

    it('Should fail all IPs', async () => {
        const stubResolver = () => [['v=spf1 -all']];

        let result = await spfVerify('example.com', { ip: '1.2.3.4', resolver: stubResolver });
        expect(result.qualifier).to.equal('-');
    });

    it('Should pass A records', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 a -all']];
                case 'A':
                    return ['192.0.2.10', '192.0.2.11'];
            }
        };

        let result;

        result = await spfVerify('example.com', { ip: '1.2.3.4', resolver: stubResolver });
        expect(result.qualifier).to.equal('-');

        result = await spfVerify('example.com', { ip: '192.0.2.10', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');

        result = await spfVerify('example.com', { ip: '192.0.2.11', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');
    });

    it('Should pass MX records', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 mx -all']];
                case 'A':
                    return ['192.0.2.10', '192.0.2.11'];
                case 'MX':
                    return [{ priority: 1, exchange: 'example.com' }];
            }
        };

        let result;

        result = await spfVerify('example.com', { ip: '1.2.3.4', resolver: stubResolver });
        expect(result.qualifier).to.equal('-');

        result = await spfVerify('example.com', { ip: '192.0.2.10', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');

        result = await spfVerify('example.com', { ip: '192.0.2.11', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');
    });

    it('Should pass MX/CIDR records', async () => {
        const stubResolver = (domain, type) => {
            switch (type) {
                case 'TXT':
                    return [['v=spf1 mx/24 -all']];
                case 'A':
                    return ['192.0.2.10', '192.0.2.11'];
                case 'MX':
                    return [{ priority: 1, exchange: 'example.com' }];
            }
        };

        let result;

        result = await spfVerify('example.com', { ip: '1.2.3.4', resolver: stubResolver });
        expect(result.qualifier).to.equal('-');

        result = await spfVerify('example.com', { ip: '192.0.2.10', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');

        result = await spfVerify('example.com', { ip: '192.0.2.11', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');

        result = await spfVerify('example.com', { ip: '192.0.2.56', resolver: stubResolver });
        expect(result.qualifier).to.equal('+');
    });
});
