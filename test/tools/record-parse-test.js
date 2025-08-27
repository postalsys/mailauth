/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const { parseTagValueRecord, validateTagValueRecord } = require('../../lib/tools');
const expect = chai.expect;

chai.config.includeStack = true;

describe('parseTagValueRecord Tests', () => {
    describe('Basic parsing functionality', () => {
        it('Should parse valid BIMI tag-value pairs', () => {
            const record = 'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.errors).to.have.length(0);
            expect(result.tags.v).to.equal('BIMI1');
            expect(result.tags.l).to.equal('https://example.com/logo.svg');
            expect(result.tags.a).to.equal('https://example.com/cert.pem');
        });

        it('Should parse DKIM-Signature header', () => {
            const record = 'v=1; a=rsa-sha256; d=example.com; s=selector; c=relaxed/relaxed; h=from:to:subject; bh=abcd1234; b=signature123';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.v).to.equal('1');
            expect(result.tags.a).to.equal('rsa-sha256');
            expect(result.tags.d).to.equal('example.com');
            expect(result.tags.s).to.equal('selector');
            expect(result.tags.c).to.equal('relaxed/relaxed');
            expect(result.tags.h).to.equal('from:to:subject');
            expect(result.tags.bh).to.equal('abcd1234');
            expect(result.tags.b).to.equal('signature123');
        });

        it('Should parse Authentication-Results header', () => {
            const record = 'spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.spf).to.equal('pass smtp.mailfrom=example.com');
            expect(result.tags.dkim).to.equal('pass header.d=example.com');
            expect(result.tags.dmarc).to.equal('pass header.from=example.com');
        });

        it('Should parse ARC-Message-Signature header', () => {
            const record = 'i=1; a=rsa-sha256; d=example.com; s=arc-selector; c=relaxed/relaxed; h=from:to:subject; bh=xyz789; b=arcsignature456';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.i).to.equal('1');
            expect(result.tags.a).to.equal('rsa-sha256');
            expect(result.tags.d).to.equal('example.com');
            expect(result.tags.s).to.equal('arc-selector');
            expect(result.tags.c).to.equal('relaxed/relaxed');
            expect(result.tags.h).to.equal('from:to:subject');
            expect(result.tags.bh).to.equal('xyz789');
            expect(result.tags.b).to.equal('arcsignature456');
        });

        it('Should parse simple From header content', () => {
            const record = 'name=John Doe; email=john@example.com; display=John Doe <john@example.com>';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.name).to.equal('John Doe');
            expect(result.tags.email).to.equal('john@example.com');
            expect(result.tags.display).to.equal('John Doe <john@example.com>');
        });

        it('Should parse simple To header content', () => {
            const record = 'primary=user@example.com; cc=admin@example.com; bcc=backup@example.com';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.primary).to.equal('user@example.com');
            expect(result.tags.cc).to.equal('admin@example.com');
            expect(result.tags.bcc).to.equal('backup@example.com');
        });

        it('Should parse Received header components', () => {
            const record = 'from=smtp.example.com; by=mail.receiver.com; with=ESMTP; id=ABC123; for=user@receiver.com';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.from).to.equal('smtp.example.com');
            expect(result.tags.by).to.equal('mail.receiver.com');
            expect(result.tags.with).to.equal('ESMTP');
            expect(result.tags.id).to.equal('ABC123');
            expect(result.tags.for).to.equal('user@receiver.com');
        });

        it('Should handle whitespace and normalize input', () => {
            const record = '  v = BIMI1 ;  l = https://example.com/logo.svg  ;  a = https://example.com/cert.pem  ';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.v).to.equal('BIMI1');
            expect(result.tags.l).to.equal('https://example.com/logo.svg');
            expect(result.tags.a).to.equal('https://example.com/cert.pem');
        });

        it('Should handle literal newlines and carriage returns', () => {
            const record = 'v=BIMI1;\\n\\r\\n l=https://example.com/logo.svg; a=https://example.com/cert.pem';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.v).to.equal('BIMI1');
            expect(result.tags.l).to.equal('https://example.com/logo.svg');
        });

        it('Should parse ARC-Seal header', () => {
            const record = 'i=1; a=rsa-sha256; d=example.com; s=arc-seal; t=1234567890; cv=none; b=sealsignature789';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.i).to.equal('1');
            expect(result.tags.a).to.equal('rsa-sha256');
            expect(result.tags.d).to.equal('example.com');
            expect(result.tags.s).to.equal('arc-seal');
            expect(result.tags.t).to.equal('1234567890');
            expect(result.tags.cv).to.equal('none');
            expect(result.tags.b).to.equal('sealsignature789');
        });

        it('Should parse SPF record format', () => {
            const record = 'v=spf1; include=_spf.google.com; include=mailgun.org; mx=example.com; a=192.168.1.1; all=-all';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.v).to.equal('spf1');
            expect(result.tags.include).to.deep.equal(['_spf.google.com', 'mailgun.org']);
            expect(result.tags.mx).to.equal('example.com');
            expect(result.tags.a).to.equal('192.168.1.1');
            expect(result.tags.all).to.equal('-all');
        });

        it('Should parse DMARC record format', () => {
            const record = 'v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; sp=reject';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.tags.v).to.equal('DMARC1');
            expect(result.tags.p).to.equal('quarantine');
            expect(result.tags.pct).to.equal('50');
            expect(result.tags.rua).to.equal('mailto:dmarc@example.com');
            expect(result.tags.ruf).to.equal('mailto:forensic@example.com');
            expect(result.tags.sp).to.equal('reject');
        });

        it('Should handle empty input', () => {
            const result = parseTagValueRecord('');

            expect(result.isValid).to.be.true;
            expect(result.tags).to.deep.equal({});
            expect(result.errors).to.have.length(0);
        });

        it('Should handle null/undefined input', () => {
            const resultNull = parseTagValueRecord(null);
            const resultUndefined = parseTagValueRecord(undefined);

            expect(resultNull.isValid).to.be.true;
            expect(resultUndefined.isValid).to.be.true;
            expect(resultNull.tags).to.deep.equal({});
            expect(resultUndefined.tags).to.deep.equal({});
        });
    });

    describe('Error handling', () => {
        it('Should detect malformed parts without equals sign', () => {
            const record = 'v=BIMI1; invalidpart; l=https://example.com/logo.svg';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.false;
            expect(result.errors).to.have.length(1);
            expect(result.errors[0]).to.include('Malformed part (no equals sign): "invalidpart"');
            expect(result.tags.v).to.equal('BIMI1');
            expect(result.tags.l).to.equal('https://example.com/logo.svg');
        });

        it('Should validate tag name format', () => {
            const record = 'v=BIMI1; invalid@tag=value; l=https://example.com/logo.svg';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.false;
            expect(result.errors).to.have.length(1);
            expect(result.errors[0]).to.include('Invalid tag name: "invalid@tag"');
        });

        it('Should stop parsing on first error in strict mode', () => {
            const record = 'v=BIMI1; invalid@tag=value; another-error; l=https://example.com/logo.svg';
            const result = parseTagValueRecord(record, { strictMode: true });

            expect(result.isValid).to.be.false;
            expect(result.errors).to.have.length(1);
            expect(result.errors[0]).to.include('Invalid tag name: "invalid@tag"');
        });

        it('Should continue parsing errors in non-strict mode', () => {
            const record = 'v=BIMI1; invalid@tag=value; another-error; l=https://example.com/logo.svg';
            const result = parseTagValueRecord(record, { strictMode: false });

            expect(result.isValid).to.be.false;
            expect(result.errors).to.have.length(2);
        });
    });

    describe('Options handling', () => {
        it('Should enforce required tags', () => {
            const record = 'l=https://example.com/logo.svg; a=https://example.com/cert.pem';
            const result = parseTagValueRecord(record, { requiredTags: ['v', 'l'] });

            expect(result.isValid).to.be.false;
            expect(result.errors).to.have.length(1);
            expect(result.errors[0]).to.include('Missing required tag: "v"');
        });

        it('Should restrict to allowed tags', () => {
            const record = 'v=BIMI1; l=https://example.com/logo.svg; unknown=value';
            const result = parseTagValueRecord(record, { allowedTags: ['v', 'l', 'a'] });

            expect(result.isValid).to.be.true;
            expect(result.warnings).to.have.length(1);
            expect(result.warnings[0]).to.include('Unknown/disallowed tag ignored: "unknown"');
            expect(result.tags).to.not.have.property('unknown');
        });

        it('Should handle case sensitivity', () => {
            const record = 'V=BIMI1; L=https://example.com/logo.svg';
            const resultSensitive = parseTagValueRecord(record, { caseSensitive: true });
            const resultInsensitive = parseTagValueRecord(record, { caseSensitive: false });

            expect(resultSensitive.tags).to.have.property('V');
            expect(resultSensitive.tags).to.have.property('L');
            expect(resultInsensitive.tags).to.have.property('v');
            expect(resultInsensitive.tags).to.have.property('l');
        });

        it('Should warn about duplicate tags', () => {
            const record = 'v=BIMI1; v=BIMI2; l=https://example.com/logo.svg';
            const result = parseTagValueRecord(record);

            expect(result.isValid).to.be.true;
            expect(result.warnings).to.have.length(1);
            expect(result.warnings[0]).to.include('Duplicate tag "v" found');
            expect(result.tags.v).to.deep.equal(['BIMI1', 'BIMI2']);
        });
    });
});

describe('validateTagValueRecord BIMI Tests', () => {
    describe('Valid BIMI records', () => {
        it('Should validate complete BIMI record', () => {
            const record = 'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.true;
            expect(result.errors).to.have.length(0);
            expect(result.tags.v).to.equal('BIMI1');
            expect(result.tags.l).to.equal('https://example.com/logo.svg');
            expect(result.tags.a).to.equal('https://example.com/cert.pem');
        });

        it('Should accept valid version formats', () => {
            const records = ['v=BIMI1', 'v=bimi1', 'v=BiMi1'];

            records.forEach(versionTag => {
                const record = `${versionTag}; l=https://example.com/logo.svg; a=https://example.com/cert.pem`;
                const result = validateTagValueRecord(record, 'BIMI');

                expect(result.isValid).to.be.true;
            });
        });
    });

    describe('Version validation', () => {
        it('Should reject invalid version format', () => {
            const record = 'v=BIMI; l=https://example.com/logo.svg; a=https://example.com/cert.pem';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.false;
            expect(result.errors.some(e => e.includes('Version must match BIMI<digit>'))).to.be.true;
        });

        it('Should reject missing version', () => {
            const record = 'l=https://example.com/logo.svg; a=https://example.com/cert.pem';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.false;
            expect(result.errors.some(e => e.includes('Missing required tag: "v"'))).to.be.true;
        });
    });

    describe('Location (l) validation', () => {
        it('Should reject empty location', () => {
            const record = 'v=BIMI1; l=; a=https://example.com/cert.pem';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.false;
            expect(result.errors.some(e => e.includes('Location cannot be empty'))).to.be.true;
        });

        it('Should reject non-HTTPS location', () => {
            const record = 'v=BIMI1; l=http://example.com/logo.svg; a=https://example.com/cert.pem';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.false;
            expect(result.errors.some(e => e.includes('Location must use HTTPS protocol'))).to.be.true;
        });

        it('Should reject invalid location URL', () => {
            const record = 'v=BIMI1; l=not-a-valid-url; a=https://example.com/cert.pem';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.false;
            expect(result.errors.some(e => e.includes('Invalid location URL'))).to.be.true;
        });

        it('Should reject missing location', () => {
            const record = 'v=BIMI1; a=https://example.com/cert.pem';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.false;
            expect(result.errors.some(e => e.includes('Missing required tag: "l"'))).to.be.true;
        });
    });

    describe('Authority (a) validation', () => {
        it('Should reject empty authority', () => {
            const record = 'v=BIMI1; l=https://example.com/logo.svg; a=';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.false;
            expect(result.errors.some(e => e.includes('Authority cannot be empty'))).to.be.true;
        });

        it('Should reject non-HTTPS authority', () => {
            const record = 'v=BIMI1; l=https://example.com/logo.svg; a=http://example.com/cert.pem';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.false;
            expect(result.errors.some(e => e.includes('Authority must use HTTPS protocol'))).to.be.true;
        });

        it('Should reject invalid authority URL', () => {
            const record = 'v=BIMI1; l=https://example.com/logo.svg; a=invalid-url';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.false;
            expect(result.errors.some(e => e.includes('Invalid authority URL'))).to.be.true;
        });

        it('Should reject missing authority', () => {
            const record = 'v=BIMI1; l=https://example.com/logo.svg';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.false;
            expect(result.errors.some(e => e.includes('Missing required tag: "a"'))).to.be.true;
        });
    });

    describe('Error handling and edge cases', () => {
        it('Should reject unknown record type', () => {
            const record = 'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem';

            expect(() => validateTagValueRecord(record, 'UNKNOWN')).to.throw('Unknown record type: UNKNOWN');
        });

        it('Should handle whitespace in URLs', () => {
            const record = 'v=BIMI1; l= https://example.com/logo.svg ; a= https://example.com/cert.pem ';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.true;
        });

        it('Should reject disallowed tags in BIMI', () => {
            const record = 'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem; unknown=value';
            const result = validateTagValueRecord(record, 'BIMI');

            expect(result.isValid).to.be.true;
            expect(result.warnings.some(w => w.includes('Unknown/disallowed tag ignored: "unknown"'))).to.be.true;
        });
    });
});
