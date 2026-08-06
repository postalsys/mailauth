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

    describe('Crafted property keys', () => {
        // A leaked property would otherwise cascade into every later test in the run
        afterEach(() => {
            delete Object.prototype.polluted;
        });

        it('Should not pollute Object.prototype', () => {
            const vectors = [
                'ARC-Authentication-Results: i=1; mx.example.com; dkim=pass __proto__.polluted=owned@evil.example',
                'ARC-Authentication-Results: i=1; mx.example.com; dkim=pass constructor.prototype.polluted=owned@evil.example',
                'Authentication-Results: mx.example.com; dkim=pass prototype.polluted=owned@evil.example',
                'Authentication-Results: mx.example.com; dkim=pass header.__proto__.polluted=owned@evil.example',
                'Authentication-Results: mx.example.com; polluted=1; __proto__=owned@evil.example'
            ];

            for (let vector of vectors) {
                parseDkimHeaders(vector);
                expect(Object.prototype.polluted, vector).to.be.undefined;
                expect({}.polluted, vector).to.be.undefined;
            }
        });

        it('Should not shadow inherited members of a parsed entry', () => {
            // Shadowing toString or valueOf with an object makes string coercion of that
            // entry throw, which used to crash the ARC result formatting
            for (let name of ['toString', 'valueOf', 'hasOwnProperty', 'constructor']) {
                let parsed = parseDkimHeaders(`Authentication-Results: mx.example.com; dmarc=pass header.from.${name}.z=1`);
                expect(parsed.parsed.dmarc.header, name).to.be.undefined;
                expect(() => `${parsed.parsed.dmarc}`, name).to.not.throw();
            }
        });

        it('Should not let a crafted key overwrite the method result', () => {
            for (let key of ['value=owned', 'value.x=1']) {
                let parsed = parseDkimHeaders(`Authentication-Results: mx.example.com; dkim=pass ${key}`);
                expect(parsed.parsed.dkim, key).to.deep.equal([{ value: 'pass' }]);
            }
        });

        it('Should not let a crafted part overwrite the authserv-id value', () => {
            // "value" at the part level holds the authserv-id picked from the first
            // key-only part; a "value=" part used to replace that string with an object
            let parsed = parseDkimHeaders('ARC-Authentication-Results: i=1; mx.example.com; value=evil; dkim=pass');
            expect(parsed.parsed.value).to.equal('mx.example.com');
        });

        it('Should not let a crafted part overwrite the header name', () => {
            // "header" is the other key the result shape pre-seeds
            let parsed = parseDkimHeaders('Authentication-Results: mx.example.com; header=evil; dkim=pass');
            expect(parsed.parsed.header).to.equal('authentication-results');
        });

        it('Should drop propspecs deeper than ptype.property', () => {
            // RFC 8601 2.2: a propspec is exactly "ptype.property", so a third segment would
            // only ever nest an object where the readers of this shape expect a string
            let parsed = parseDkimHeaders('Authentication-Results: mx.example.com; dkim=pass header.i.x=1');
            expect(parsed.parsed.dkim).to.deep.equal([{ value: 'pass' }]);
        });

        it('Should keep the other properties of an entry with a rejected key', () => {
            // the control case: sibling propspecs of a rejected one still parse
            for (let rejected of ['header.toString.z=1', 'value.x=1']) {
                let parsed = parseDkimHeaders(`Authentication-Results: mx.example.com; dkim=pass header.d=example.com ${rejected} header.s=sel1`);
                expect(parsed.parsed.dkim, rejected).to.deep.equal([{ value: 'pass', header: { d: 'example.com', s: 'sel1' } }]);
            }
        });
    });

    it('Should still parse nested property keys', () => {
        let parsed = parseDkimHeaders('Authentication-Results: mx.example.com; dkim=pass header.d=example.com header.s=sel1');
        expect(parsed.parsed.dkim).to.deep.equal([{ value: 'pass', header: { d: 'example.com', s: 'sel1' } }]);
    });
});
