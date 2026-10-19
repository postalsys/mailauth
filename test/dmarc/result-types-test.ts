/* eslint @typescript-eslint/no-unused-expressions:0 */
import { describe, it } from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, config } from 'chai';

import { dmarc } from '../../src/dmarc/index.js';
import { zoneResolver } from '../helpers/dns-zone.js';

config.includeStack = true;

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Top level properties of an interface in src/types.ts, mapped to whether they are optional
const interfaceProperties = (name: string) => {
    const source = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'types.ts'), 'utf8').replace(/\r\n/g, '\n');
    const start = source.indexOf(`export interface ${name} {`);
    expect(start, name).to.be.at.least(0);
    const body = source.slice(start, source.indexOf('\n}\n', start));
    const properties = new Map<string, boolean>();
    for (const match of body.matchAll(/^ {4}([A-Za-z]+)(\??):/gm)) {
        properties.set(match[1], match[2] === '?');
    }
    return properties;
};

const fail = (code: string) => async () => {
    const err: any = new Error(code);
    err.code = code;
    throw err;
};

describe('DMARCResult type definition', () => {
    it('Should not mark properties required that a none or temperror result does not have', async () => {
        const properties = interfaceProperties('DMARCResult');
        const required = Array.from(properties)
            .filter(([, optional]) => !optional)
            .map(([key]) => key);

        const results: any[] = [
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
        const source = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'types.ts'), 'utf8').replace(/\r\n/g, '\n');
        const start = source.indexOf('export interface DMARCResult {');
        const body = source.slice(start, source.indexOf('\n}\n', start));
        expect(body).to.not.include('RFC 8601 section 2.7.2');
        expect(body).to.include('RFC 9989 section 9.1');
    });
});
