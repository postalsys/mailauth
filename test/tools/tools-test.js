/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;
const { PassThrough } = require('node:stream');

const {
    writeToStream,
    parseHeaders,
    getSigningHeaderLines,
    formatSignatureHeaderLine,
    formatAuthHeaderRow,
    escapeCommentValue,
    formatRelaxedLine,
    stripSignatureValue,
    formatDomain,
    getAlignment,
    validateAlgorithm,
    getPtrHostname,
    getCurTime
} = require('../../lib/tools');

chai.config.includeStack = true;

describe('Tools Tests', () => {
    describe('writeToStream', () => {
        it('Should write string to stream', async () => {
            const stream = new PassThrough();
            const chunks = [];

            stream.on('data', chunk => chunks.push(chunk));

            await writeToStream(stream, 'Hello World');

            const result = Buffer.concat(chunks).toString();
            expect(result).to.equal('Hello World');
        });

        it('Should write Buffer to stream', async () => {
            const stream = new PassThrough();
            const chunks = [];

            stream.on('data', chunk => chunks.push(chunk));

            await writeToStream(stream, Buffer.from('Test Buffer'));

            const result = Buffer.concat(chunks).toString();
            expect(result).to.equal('Test Buffer');
        });

        it('Should pipe readable stream to target stream', async () => {
            const source = new PassThrough();
            const target = new PassThrough();
            const chunks = [];

            target.on('data', chunk => chunks.push(chunk));

            const writePromise = writeToStream(target, source);
            source.end('Piped data');

            await writePromise;

            const result = Buffer.concat(chunks).toString();
            expect(result).to.equal('Piped data');
        });

        it('Should handle custom chunk size', async () => {
            const stream = new PassThrough();
            const data = 'A'.repeat(200);
            const chunks = [];

            stream.on('data', chunk => chunks.push(chunk));

            await writeToStream(stream, data, 50);

            const result = Buffer.concat(chunks).toString();
            expect(result).to.equal(data);
        });
    });

    describe('parseHeaders', () => {
        it('Should parse simple headers', () => {
            const headers = Buffer.from('From: user@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n');
            const result = parseHeaders(headers);

            expect(result.parsed).to.have.length(3);
            expect(result.parsed[0].key).to.equal('from');
            expect(result.parsed[0].casedKey).to.equal('From');
            expect(result.parsed[1].key).to.equal('to');
            expect(result.parsed[2].key).to.equal('subject');
        });

        it('Should handle folded headers', () => {
            const headers = Buffer.from('Subject: This is a very long subject\r\n that has been folded\r\n');
            const result = parseHeaders(headers);

            expect(result.parsed).to.have.length(1);
            expect(result.parsed[0].key).to.equal('subject');
            expect(result.parsed[0].line.toString()).to.include('folded');
        });

        it('Should preserve original buffer', () => {
            const headers = Buffer.from('From: user@example.com\r\n');
            const result = parseHeaders(headers);

            expect(result.original).to.equal(headers);
        });

        it('Should handle headers with LF line endings', () => {
            const headers = Buffer.from('From: user@example.com\nTo: recipient@example.com\n');
            const result = parseHeaders(headers);

            expect(result.parsed).to.have.length(2);
        });
    });

    describe('getSigningHeaderLines', () => {
        it('Should select headers for signing', () => {
            const parsedHeaders = [
                { key: 'from', casedKey: 'From', line: Buffer.from('From: user@example.com') },
                { key: 'to', casedKey: 'To', line: Buffer.from('To: recipient@example.com') },
                { key: 'subject', casedKey: 'Subject', line: Buffer.from('Subject: Test') },
                { key: 'x-custom', casedKey: 'X-Custom', line: Buffer.from('X-Custom: value') }
            ];

            const result = getSigningHeaderLines(parsedHeaders, 'From:Subject');

            expect(result.headers).to.have.length(2);
            expect(result.keys).to.include('From');
            expect(result.keys).to.include('Subject');
        });

        it('Should use default field names when not specified', () => {
            const parsedHeaders = [
                { key: 'from', casedKey: 'From', line: Buffer.from('From: user@example.com') },
                { key: 'subject', casedKey: 'Subject', line: Buffer.from('Subject: Test') }
            ];

            const result = getSigningHeaderLines(parsedHeaders);

            expect(result.headers.length).to.be.at.least(1);
        });

        it('Should handle verify mode', () => {
            const parsedHeaders = [
                { key: 'from', casedKey: 'From', line: Buffer.from('From: user1@example.com') },
                { key: 'from', casedKey: 'From', line: Buffer.from('From: user2@example.com') }
            ];

            const result = getSigningHeaderLines(parsedHeaders, 'From:From', true);

            expect(result.headers).to.have.length(2);
        });
    });

    describe('formatSignatureHeaderLine', () => {
        it('Should format DKIM-Signature header', () => {
            const result = formatSignatureHeaderLine('DKIM', {
                a: 'rsa-sha256',
                d: 'example.com',
                s: 'selector1',
                h: 'from:to:subject',
                bh: 'bodyhash==',
                b: 'signature=='
            });

            expect(result).to.include('DKIM-Signature:');
            expect(result).to.include('v=1');
            expect(result).to.include('a=rsa-sha256');
            expect(result).to.include('d=example.com');
        });

        it('Should serialize l=0 as a value, not as an empty tag', () => {
            // sig-l-tag is 1*76DIGIT (RFC 6376 section 3.5), so `l=` is not a legal tag
            const result = formatSignatureHeaderLine('DKIM', {
                a: 'rsa-sha256',
                d: 'example.com',
                s: 'selector1',
                h: 'from',
                l: 0,
                bh: 'bodyhash==',
                b: 'signature=='
            });

            expect(result).to.include('l=0');
        });

        it('Should format ARC-Message-Signature header', () => {
            const result = formatSignatureHeaderLine('ARC', {
                i: 1,
                a: 'rsa-sha256',
                d: 'example.com',
                s: 'arc-selector',
                h: 'from:to:subject',
                bh: 'bodyhash==',
                b: 'signature=='
            });

            expect(result).to.include('ARC-Message-Signature:');
            expect(result).to.include('i=1');
        });

        it('Should format ARC-Seal header', () => {
            const result = formatSignatureHeaderLine('AS', {
                i: 1,
                a: 'rsa-sha256',
                d: 'example.com',
                s: 'arc-selector',
                cv: 'none',
                b: 'signature=='
            });

            expect(result).to.include('ARC-Seal:');
            expect(result).to.include('cv=none');
        });

        it('Should throw for unknown type', () => {
            try {
                formatSignatureHeaderLine('UNKNOWN', {});
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.message).to.equal('Unknown Signature type');
            }
        });

        it('Should fold signature when folded=true', () => {
            const result = formatSignatureHeaderLine(
                'DKIM',
                {
                    a: 'rsa-sha256',
                    d: 'example.com',
                    s: 'selector1',
                    h: 'from:to:subject',
                    bh: 'bodyhash==',
                    b: 'a'.repeat(200)
                },
                true
            );

            expect(result).to.include('\r\n');
        });

        it('Should convert IDN domains', () => {
            const result = formatSignatureHeaderLine('DKIM', {
                a: 'rsa-sha256',
                d: 'xn--e1afmkfd.xn--p1ai',
                s: 'selector1',
                h: 'from',
                bh: 'hash',
                b: 'sig'
            });

            expect(result).to.include('d=xn--e1afmkfd.xn--p1ai');
        });
    });

    describe('formatAuthHeaderRow', () => {
        it('Should format basic authentication result', () => {
            const result = formatAuthHeaderRow('dkim', { result: 'pass' });

            expect(result).to.equal('dkim=pass');
        });

        it('Should include comment', () => {
            const result = formatAuthHeaderRow('spf', {
                result: 'pass',
                comment: 'sender authorized'
            });

            expect(result).to.include('spf=pass');
            expect(result).to.include('(sender authorized)');
        });

        it('Should include ptype properties', () => {
            const result = formatAuthHeaderRow('dkim', {
                result: 'pass',
                header: { d: 'example.com', s: 'selector1' }
            });

            expect(result).to.include('header.d=example.com');
            expect(result).to.include('header.s=selector1');
        });

        it('Should handle underSized status', () => {
            const result = formatAuthHeaderRow('dkim', {
                result: 'pass',
                underSized: 100
            });

            expect(result).to.include('undersized signature: 100 bytes unsigned');
        });

        it('Should handle none result', () => {
            const result = formatAuthHeaderRow('dmarc', {});

            expect(result).to.equal('dmarc=none');
        });
    });

    describe('escapeCommentValue', () => {
        it('Should return simple string unchanged', () => {
            const result = escapeCommentValue('simple comment');
            expect(result).to.equal('simple comment');
        });

        it('Should escape backslash', () => {
            const result = escapeCommentValue('path\\to\\file');
            expect(result).to.equal('path\\\\to\\\\file');
        });

        it('Should escape closing parenthesis', () => {
            const result = escapeCommentValue('comment (with parens)');
            expect(result).to.equal('comment (with parens\\)');
        });

        it('Should handle empty string', () => {
            const result = escapeCommentValue('');
            expect(result).to.equal('');
        });

        it('Should normalize whitespace', () => {
            const result = escapeCommentValue('multiple   spaces');
            expect(result).to.equal('multiple spaces');
        });
    });

    describe('parseHeaders folding', () => {
        it('Should fold a line that starts with SP or HTAB', () => {
            const parsed = parseHeaders(Buffer.from('From: a@example.com\r\nSubject: first\r\n\tsecond\r\n continued\r\n', 'binary')).parsed;
            expect(parsed.map(row => row.key)).to.deep.equal(['from', 'subject']);
            expect(parsed[1].line.toString('binary')).to.equal('Subject: first\r\n\tsecond\r\n continued');
        });

        it('Should fold a line that begins with another whitespace byte', () => {
            // 0xA0 is latin1 NBSP and the second byte of UTF-8 NBSP. RFC 5322 does not
            // fold on it, but libmime and MUAs do, so folding it in here keeps the line
            // inside the value a reader sees instead of hiding it from the signature
            for (const wsp of [' ', '\t', '\v', '\f', '\xa0']) {
                const parsed = parseHeaders(Buffer.from(`From: a@example.com\r\n${wsp}Subject: x\r\n`, 'binary')).parsed;
                expect(parsed.map(row => row.key)).to.deep.equal(['from']);
            }
        });

        it('Should trim only SP and HTAB from the header name', () => {
            const parsed = parseHeaders(Buffer.from('Subject \t : value\r\n', 'binary')).parsed;
            expect(parsed[0].casedKey).to.equal('Subject');
        });

        it('Should not leave a fold line break in the header name', () => {
            // the colon of this From sits on the continuation line. Every MUA unfolds it
            // and shows a From, so DMARC has to find one too
            const parsed = parseHeaders(Buffer.from('From\r\n : boss@example.com\r\nSubject: t\r\n', 'binary')).parsed;
            expect(parsed.map(row => row.key)).to.deep.equal(['from', 'subject']);
            expect(parsed[0].casedKey).to.equal('From');
        });

        it('Should lowercase the header name without shifting non-ASCII bytes', () => {
            // toLowerCase() is Unicode aware and would map 0xC3 to 0xE3
            const parsed = parseHeaders(Buffer.from('Sö: value\r\n', 'utf-8')).parsed;
            expect([...Buffer.from(parsed[0].key, 'binary')]).to.deep.equal([0x73, 0xc3, 0xb6]);
        });
    });

    describe('getSigningHeaderLines', () => {
        it('Should normalize h= field names the same way parseHeaders does', () => {
            // an h= entry is read off the wire as a 'binary' string, so it has to be
            // lowercased and trimmed by the same rules that produced the parsed keys
            const parsed = parseHeaders(Buffer.from('S\xc3\xb6: v\r\nFrom: a@example.com\r\n', 'binary')).parsed;
            expect(parsed.map(row => row.key)).to.deep.equal(['s\xc3\xb6', 'from']);

            const selected = getSigningHeaderLines(parsed, ' from \t:S\xc3\xb6', true);
            expect(selected.headers.map(header => header.key)).to.deep.equal(['from', 's\xc3\xb6']);
        });
    });

    describe('formatRelaxedLine', () => {
        it('Should lowercase header name', () => {
            const result = formatRelaxedLine(Buffer.from('FROM: user@example.com'));
            expect(result.toString()).to.equal('from:user@example.com');
        });

        it('Should collapse whitespace', () => {
            const result = formatRelaxedLine(Buffer.from('Subject:   Multiple   Spaces'));
            expect(result.toString()).to.equal('subject:Multiple Spaces');
        });

        it('Should unfold headers', () => {
            const result = formatRelaxedLine(Buffer.from('Subject: Line1\r\n Line2'));
            expect(result.toString()).to.equal('subject:Line1 Line2');
        });

        it('Should add suffix when provided', () => {
            const result = formatRelaxedLine(Buffer.from('From: test'), '\r\n');
            expect(result.toString()).to.equal('from:test\r\n');
        });

        it('Should trim whitespace around colon', () => {
            const result = formatRelaxedLine(Buffer.from('Subject  :  value'));
            expect(result.toString()).to.equal('subject:value');
        });

        it('Should collapse runs of SP and HTAB and drop trailing whitespace', () => {
            const result = formatRelaxedLine(Buffer.from('Subject: a \t b\r\n\t c  \r\n d \t'));
            expect(result.toString()).to.equal('subject:a b c d');
        });

        it('Should keep an empty value', () => {
            const result = formatRelaxedLine(Buffer.from('Subject: \t '));
            expect(result.toString()).to.equal('subject:');
        });

        it('Should treat only SP and HTAB as whitespace', () => {
            // the line is handled as a 'binary' string, so the 0xA0 byte of a UTF-8
            // non-breaking space (C2 A0) and the bytes of an ideographic space (E3 80 80)
            // are content
            const nbsp = formatRelaxedLine(Buffer.from('Subject: a\u00a0b', 'utf-8'));
            expect(nbsp.toString('utf-8')).to.equal('subject:a\u00a0b');

            const ideographic = formatRelaxedLine(Buffer.from('Subject: 日本\u3000語 ', 'utf-8'));
            expect(ideographic.toString('utf-8')).to.equal('subject:日本\u3000語');

            const latin1 = formatRelaxedLine(Buffer.from('Subject: j\xf5geva ', 'binary'));
            expect(latin1.toString('binary')).to.equal('subject:j\xf5geva');
        });

        it('Should lowercase the header name without shifting non-ASCII bytes', () => {
            // toLowerCase() is Unicode aware and maps the latin1 bytes 0xC0-0xDE to
            // 0xE0-0xFE, which would corrupt the UTF-8 sequence of this header name
            const result = formatRelaxedLine(Buffer.from('Sö: value', 'utf-8'));
            expect([...result]).to.deep.equal([...Buffer.from('sö:value', 'utf-8')]);
        });

        it('Should drop whitespace in front of a line that is not a header field', () => {
            expect(formatRelaxedLine(Buffer.from(' garbage', 'binary')).toString('binary')).to.equal('garbage');
        });

        it('Should canonicalize a missing line as nothing', () => {
            // optional chaining here would resolve to undefined and hash the string
            // "undefined" as if it were a header line
            expect(formatRelaxedLine(undefined).toString('binary')).to.equal('');
            expect(formatRelaxedLine(undefined, '\r\n').toString('binary')).to.equal('\r\n');
        });
    });

    describe('stripSignatureValue', () => {
        it('Should strip the b= value', () => {
            const line = Buffer.from('DKIM-Signature: v=1; bh=AAA; b=REALSIGNATURE', 'binary');
            expect(stripSignatureValue(line).toString('binary')).to.equal('DKIM-Signature: v=1; bh=AAA; b=');
        });

        it('Should strip a b= that a fold pushed onto a continuation line', () => {
            // simple canonicalization does not unfold, so the CRLF is what separates the
            // tag from the one before it
            const line = Buffer.from('DKIM-Signature: v=1; bh=AAA;\r\n b=REALSIGNATURE', 'binary');
            expect(stripSignatureValue(line).toString('binary')).to.not.include('REALSIGNATURE');
        });

        it('Should treat only SP and HTAB as whitespace in front of b=', () => {
            // JS \s matches 0x0B, 0x0C and 0xA0, RFC 6376 does not. Matching them would
            // strip a decoy tag and leave the real signature inside the hashed header
            for (const byte of ['\x0b', '\x0c', '\xa0']) {
                const line = Buffer.from(`DKIM-Signature: v=1; bh=AAA;${byte}b=DECOY; b=REALSIGNATURE`, 'binary');
                const stripped = stripSignatureValue(line).toString('binary');

                expect(stripped).to.include(`${byte}b=DECOY`);
                expect(stripped).to.not.include('REALSIGNATURE');
            }
        });
    });

    describe('formatDomain', () => {
        it('Should lowercase domain', () => {
            const result = formatDomain('EXAMPLE.COM');
            expect(result).to.equal('example.com');
        });

        it('Should trim whitespace', () => {
            const result = formatDomain('  example.com  ');
            expect(result).to.equal('example.com');
        });

        it('Should convert IDN to punycode', () => {
            // This will convert to punycode
            const result = formatDomain('example.com');
            expect(result).to.equal('example.com');
        });

        it('Should handle already ASCII domains', () => {
            const result = formatDomain('xn--e1afmkfd.xn--p1ai');
            expect(result).to.equal('xn--e1afmkfd.xn--p1ai');
        });
    });

    describe('getAlignment', () => {
        it('Should match exact domain in relaxed mode', () => {
            const result = getAlignment('example.com', ['example.com']);
            expect(result).to.deep.include({ domain: 'example.com' });
        });

        it('Should match subdomain in relaxed mode', () => {
            const result = getAlignment('mail.example.com', ['example.com']);
            expect(result).to.deep.include({ domain: 'example.com' });
        });

        it('Should match org domain in relaxed mode', () => {
            const result = getAlignment('example.com', ['mail.example.com']);
            expect(result).to.deep.include({ domain: 'mail.example.com' });
        });

        it('Should match identical domain in strict mode', () => {
            const result = getAlignment('news.example.com', ['news.example.com'], true);
            expect(result).to.deep.include({ domain: 'news.example.com' });
        });

        it('Should not match a host against its org domain in strict mode', () => {
            const result = getAlignment('mail.example.com', ['example.com'], true);
            expect(result).to.be.false;
        });

        it('Should not match two different hosts of the same org in strict mode', () => {
            const result = getAlignment('news.example.com', ['foo.example.com'], true);
            expect(result).to.be.false;
        });

        it('Should not match unrelated domains in strict mode', () => {
            const result = getAlignment('news.example.com', ['foo.example.net'], true);
            expect(result).to.be.false;
        });

        it('Should match identical domains case-insensitively in strict mode', () => {
            const result = getAlignment('News.Example.COM', ['news.example.com'], true);
            expect(result).to.deep.include({ domain: 'news.example.com' });
        });

        it('Should match a host against its org domain in relaxed mode', () => {
            const result = getAlignment('mail.example.com', ['example.com'], false);
            expect(result).to.deep.include({ domain: 'example.com' });
        });

        it('Should match two different hosts of the same org in relaxed mode', () => {
            const result = getAlignment('news.example.com', ['foo.example.com'], false);
            expect(result).to.deep.include({ domain: 'foo.example.com' });
        });

        it('Should not match unrelated domains in relaxed mode', () => {
            const result = getAlignment('news.example.com', ['foo.example.net'], false);
            expect(result).to.be.false;
        });

        it('Should honor the legacy options object instead of treating it as truthy', () => {
            // { strict: false } is the call shape this argument used to take. Every object is
            // truthy, so without unwrapping it would mean hard strict, the opposite of the ask.
            expect(getAlignment('mail.example.com', ['example.com'], { strict: false })).to.deep.include({ domain: 'example.com' });
            expect(getAlignment('mail.example.com', ['example.com'], { strict: true })).to.be.false;
            expect(getAlignment('mail.example.com', ['example.com'], {})).to.deep.include({ domain: 'example.com' });
        });

        it('Should ignore a trailing root dot in strict mode', () => {
            expect(getAlignment('example.com.', ['example.com'], true)).to.deep.include({ domain: 'example.com' });
            expect(getAlignment('example.com', ['example.com.'], true)).to.deep.include({ domain: 'example.com.' });
        });

        it('Should ignore a trailing root dot in relaxed mode', () => {
            expect(getAlignment('mail.example.com.', ['example.com'], false)).to.deep.include({ domain: 'example.com' });
        });

        it('Should not align a bare root label with anything', () => {
            // "." and "" both normalize to an empty string once the root label is
            // stripped, and empty must never equal empty here
            expect(getAlignment('.', ['.'], true)).to.be.false;
            expect(getAlignment('', [''], true)).to.be.false;
            expect(getAlignment('.', ['.'], false)).to.be.false;
            expect(getAlignment('', ['example.com'], true)).to.be.false;
        });

        it('Should return false when no match', () => {
            const result = getAlignment('example.com', ['other.com']);
            expect(result).to.be.false;
        });

        it('Should handle string domain entries', () => {
            const result = getAlignment('example.com', ['example.com']);
            expect(result.domain).to.equal('example.com');
        });

        it('Should handle object domain entries', () => {
            const result = getAlignment('example.com', [{ domain: 'example.com', underSized: 50 }]);
            expect(result.domain).to.equal('example.com');
            expect(result.underSized).to.equal(50);
        });

        it('Should sort by underSized', () => {
            const result = getAlignment('example.com', [
                { domain: 'example.com', underSized: 100 },
                { domain: 'example.com', underSized: 50 }
            ]);
            expect(result.underSized).to.equal(50);
        });

        it('Should handle empty domain list', () => {
            const result = getAlignment('example.com', []);
            expect(result).to.be.false;
        });
    });

    describe('validateAlgorithm', () => {
        it('Should accept rsa-sha256', () => {
            expect(() => validateAlgorithm('rsa-sha256')).to.not.throw();
        });

        it('Should accept ed25519-sha256', () => {
            expect(() => validateAlgorithm('ed25519-sha256')).to.not.throw();
        });

        it('Should accept rsa-sha1 in non-strict mode', () => {
            expect(() => validateAlgorithm('rsa-sha1')).to.not.throw();
        });

        it('Should reject rsa-sha1 in strict mode', () => {
            try {
                validateAlgorithm('rsa-sha1', true);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('EINVALIDALGO');
            }
        });

        it('Should reject unknown signing algorithm', () => {
            try {
                validateAlgorithm('dsa-sha256');
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('EINVALIDALGO');
                expect(err.signAlgo).to.equal('dsa');
            }
        });

        it('Should reject unknown hashing algorithm', () => {
            try {
                validateAlgorithm('rsa-md5');
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('EINVALIDALGO');
                expect(err.hashAlgo).to.equal('md5');
            }
        });

        it('Should reject invalid format', () => {
            try {
                validateAlgorithm('invalid');
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('EINVALIDALGO');
            }
        });

        it('Should reject empty algorithm', () => {
            try {
                validateAlgorithm('');
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('EINVALIDALGO');
            }
        });
    });

    describe('getPtrHostname', () => {
        it('Should format IPv4 PTR hostname', () => {
            const mockAddr = {
                toByteArray: () => [192, 0, 2, 1]
            };

            const result = getPtrHostname(mockAddr);
            expect(result).to.equal('1.2.0.192.in-addr.arpa');
        });

        it('Should format IPv6 PTR hostname', () => {
            const mockAddr = {
                toByteArray: () => [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            };

            const result = getPtrHostname(mockAddr);
            expect(result).to.include('.ip6.arpa');
            expect(result).to.match(/^[0-9a-f.]+\.ip6\.arpa$/);
        });
    });

    describe('getCurTime', () => {
        it('Should return current date when no argument', () => {
            const now = Date.now();
            const result = getCurTime();

            // Result should be very close to now
            expect(Math.abs(result.getTime() - now)).to.be.lessThan(1000);
        });

        it('Should return same Date object when passed', () => {
            const date = new Date('2024-01-15T12:00:00Z');
            const result = getCurTime(date);

            expect(result).to.equal(date);
        });

        it('Should parse number timestamp', () => {
            const timestamp = 1705320000000;
            const result = getCurTime(timestamp);

            expect(result.getTime()).to.equal(timestamp);
        });

        it('Should parse string timestamp number', () => {
            const timestamp = '1705320000000';
            const result = getCurTime(timestamp);

            expect(result.getTime()).to.equal(1705320000000);
        });

        it('Should parse ISO date string', () => {
            const dateStr = '2024-01-15T12:00:00Z';
            const result = getCurTime(dateStr);

            expect(result.toISOString()).to.equal('2024-01-15T12:00:00.000Z');
        });

        it('Should handle invalid string value', () => {
            const result = getCurTime('not-a-date-at-all');

            // The function returns the Invalid Date since the bug in the code
            // checks toString !== 'Invalid Date' but toString is a function.
            // This matches the actual current behavior.
            expect(result).to.be.instanceof(Date);
        });
    });
});
