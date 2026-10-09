/* eslint no-unused-expressions:0 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const chai = require('chai');
const expect = chai.expect;

const { dmarc } = require('../../lib/dmarc');
const { zoneResolver } = require('../helpers/dns-zone');

chai.config.includeStack = true;

// Top level properties of an interface in index.d.ts, mapped to whether they are optional
const interfaceProperties = name => {
    const source = fs.readFileSync(path.join(__dirname, '..', '..', 'index.d.ts'), 'utf8').replace(/\r\n/g, '\n');
    const start = source.indexOf(`export interface ${name} {`);
    expect(start, name).to.be.at.least(0);
    const body = source.slice(start, source.indexOf('\n}\n', start));
    const properties = new Map();
    for (const match of body.matchAll(/^ {4}([A-Za-z]+)(\??):/gm)) {
        properties.set(match[1], match[2] === '?');
    }
    return properties;
};

const fail = code => async () => {
    const err = new Error(code);
    err.code = code;
    throw err;
};

describe('DMARCResult type definition', () => {
    it('Should not mark properties required that a none or temperror result does not have', async () => {
        const properties = interfaceProperties('DMARCResult');
        const required = Array.from(properties)
            .filter(([, optional]) => !optional)
            .map(([key]) => key);

        const results = [
            await dmarc({ headerFrom: 'ceo@bank.example', spfDomains: [], dkimDomains: [], resolver: fail('ENOTFOUND') }),
            await dmarc({ headerFrom: 'ceo@bank.example', spfDomains: [], dkimDomains: [], resolver: fail('ETIMEOUT') }),
            // a record without a valid policy and without rua gets no DMARC processing
            await dmarc({
                headerFrom: 'ceo@bank.example',
                spfDomains: [],
                dkimDomains: [],
                resolver: zoneResolver({ '_dmarc.bank.example': { TXT: [['v=DMARC1; p=invalid']] } })
            })
        ];

        expect(results.map(r => r.status.result)).to.deep.equal(['none', 'temperror', 'none']);
        for (const result of results) {
            for (const key of required) {
                expect(result, `${result.status.result} result, required property ${key}`).to.have.property(key);
            }
            for (const key of Object.keys(result)) {
                expect(properties.has(key), `${key} is declared`).to.be.true;
            }
        }
    });

    it('Should cite RFC 9989 for the dmarc ptype properties', () => {
        const source = fs.readFileSync(path.join(__dirname, '..', '..', 'index.d.ts'), 'utf8').replace(/\r\n/g, '\n');
        const start = source.indexOf('export interface DMARCResult {');
        const body = source.slice(start, source.indexOf('\n}\n', start));
        expect(body).to.not.include('RFC 8601 section 2.7.2');
        expect(body).to.include('RFC 9989 section 9.1');
    });
});
