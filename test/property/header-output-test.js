'use strict';

const { Buffer } = require('node:buffer');
const { expect } = require('chai');

const { authenticate } = require('../../lib/mailauth');
const { spf } = require('../../lib/spf');
const { unfold, parseAuthResults, parseReceivedSpf } = require('../helpers/auth-results-reference');
const { fc, check, timeout, bytesFrom } = require('./helper');

// Every DNS query fails with NXDOMAIN, which keeps the runs fast and still produces every header
const resolver = async name => {
    let err = new Error(`NXDOMAIN ${name}`);
    err.code = 'ENOTFOUND';
    throw err;
};

// Text that tries to break out of a comment, a quoted-string or a resinfo, with control
// characters, folding characters, 8-bit text and Unicode line separators
const hostile = fc
    .array(
        fc.oneof(
            bytesFrom('az09.-_@"\\()<>[];:=, \t'),
            fc.constantFrom(
                '\r\n',
                '\r',
                '\n',
                '\r\n ',
                '\x00',
                '\x07',
                '\x1b',
                '\x7f',
                '\u0085',
                ' ',
                'é',
                '日本',
                '; dkim=pass header.d=bank.example',
                ') spf=pass (',
                '" smtp.mailfrom=ceo@bank.example "',
                '\\',
                'example.com',
                'x'.repeat(500)
            )
        ),
        { maxLength: 8 }
    )
    .map(parts => parts.join(''));

const ip = fc.oneof(fc.ipV4(), fc.ipV6(), fc.constant('::ffff:192.0.2.1'), hostile);
const sender = fc.oneof(
    hostile,
    fc.tuple(hostile, hostile).map(([local, domain]) => `${local}@${domain}`),
    fc.emailAddress()
);
const helo = fc.oneof(hostile, fc.domain());

// d=, s= and i= of a DKIM-Signature are copied into header.d, header.s and header.i. A ";"
// would only end the tag and a line break the header field, so they are left out
const tagValue = hostile.map(value => value.replace(/[;\r\n]/g, ''));

const inputs = fc.record({
    ip,
    sender,
    helo,
    mta: fc.domain(),
    d: tagValue,
    s: tagValue,
    i: tagValue,
    fromDomain: fc.oneof(
        fc.domain(),
        hostile.map(value => value.replace(/[\r\n]/g, ''))
    )
});

const buildMessage = ({ d, s, i, fromDomain }) =>
    Buffer.from(
        `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=${d}; s=${s}; i=${i};\r\n h=from:subject; bh=AAAA; b=BBBB\r\n` +
            `From: user@${fromDomain}\r\nSubject: test\r\n\r\nbody\r\n`
    );

// The text mailauth writes for an input value, as escapePropValue and formatDotAtomOrQuoted
// clean it: control characters are not allowed anywhere in a structured field, not even escaped
const cleaned = value =>
    String(value)
        .replace(/[\x00-\x1F\x7F]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

// Splits generated header lines into fields. Each field must start at the beginning of a line
const splitFields = headers => {
    expect(headers.endsWith('\r\n')).to.equal(true);
    let fields = [];
    for (let line of headers.slice(0, -2).split('\r\n')) {
        // lines of RFC 5322 section 2.1.1 are at most 998 octets
        expect(Buffer.byteLength(line), line.slice(0, 80)).to.be.at.most(998);
        if (/^[ \t]/.test(line)) {
            expect(fields.length).to.be.above(0);
            fields[fields.length - 1] += '\r\n' + line;
        } else {
            fields.push(line);
        }
    }
    return fields.map(field => {
        let match = field.match(/^([A-Za-z-]+): ?([\s\S]*)$/);
        expect(match, field.slice(0, 80)).to.not.equal(null);
        return { name: match[1], value: match[2] };
    });
};

const assertNoControls = value => {
    // after unfolding, only HTAB is allowed of the control characters
    expect(unfold(value)).to.not.match(/[\x00-\x08\x0a-\x1f\x7f]/);
};

describe('Property: generated Authentication-Results and Received-SPF header fields', function () {
    this.timeout(timeout(200, 40));

    for (let strict of [false, true]) {
        it(`stay well-formed and keep every value in place for any input${strict ? ' (strict)' : ''}`, () =>
            check(
                fc.asyncProperty(inputs, async input => {
                    let res = await authenticate(buildMessage(input), {
                        ip: input.ip,
                        sender: input.sender,
                        helo: input.helo,
                        mta: input.mta,
                        resolver,
                        strict
                    });

                    let fields = splitFields(res.headers);
                    expect(fields.map(field => field.name).sort()).to.deep.equal(['Authentication-Results', 'Received-SPF']);

                    for (let field of fields) {
                        assertNoControls(field.value);
                    }

                    let ar = parseAuthResults(fields.find(field => field.name === 'Authentication-Results').value);
                    expect(ar.authservId).to.equal(input.mta);
                    // one resinfo per method: an injected "; dkim=pass" never becomes its own result
                    expect(ar.results.map(entry => entry.method)).to.deep.equal([
                        'dkim',
                        'spf',
                        ...(res.arc?.info ? ['arc'] : []),
                        ...(res.dmarc?.info ? ['dmarc'] : []),
                        ...(res.bimi?.info ? ['bimi'] : [])
                    ]);

                    let dkim = ar.results[0];
                    expect(dkim.result).to.not.equal('pass');
                    if ('header.s' in dkim.props && !strict) {
                        // the selector can only be the one from the signature
                        expect(dkim.props['header.s']).to.equal(cleaned(input.s));
                    }

                    let spfResult = ar.results[1];
                    expect(Object.keys(spfResult.props).every(prop => ['smtp.mailfrom', 'smtp.helo'].includes(prop))).to.equal(true);
                    if (!strict && 'smtp.helo' in spfResult.props) {
                        expect(spfResult.props['smtp.helo']).to.equal(cleaned(res.spf.status.smtp.helo));
                    }
                    if (!strict && 'smtp.mailfrom' in spfResult.props) {
                        expect(spfResult.props['smtp.mailfrom']).to.equal(cleaned(res.spf.status.smtp.mailfrom));
                    }

                    let receivedSpf = parseReceivedSpf(fields.find(field => field.name === 'Received-SPF').value);
                    expect(receivedSpf.result).to.equal(spfResult.result);
                    expect(receivedSpf.comments.length).to.be.at.most(1);
                    for (let [key, value] of Object.entries(receivedSpf.pairs)) {
                        expect(['client-ip', 'envelope-from', 'helo']).to.include(key);
                        let expected = { 'client-ip': res.spf['client-ip'], 'envelope-from': res.spf['envelope-from'], helo: res.spf.helo }[key];
                        expect(value).to.equal(cleaned(expected));
                    }
                }),
                200
            ));
    }

    it('spf() keeps the client address, sender and HELO name in their own key-value pairs', () =>
        check(
            fc.asyncProperty(ip, sender, helo, fc.domain(), async (clientIp, mailFrom, heloName, mta) => {
                let res = await spf({ ip: clientIp, sender: mailFrom, helo: heloName, mta, resolver });

                assertNoControls(res.header);
                assertNoControls(res.info);

                let receivedSpf = parseReceivedSpf(res.header.replace(/^Received-SPF: /, ''));
                expect(receivedSpf.result).to.equal(res.status.result);
                for (let [key, value] of Object.entries(receivedSpf.pairs)) {
                    let expected = { 'client-ip': res['client-ip'], 'envelope-from': res['envelope-from'], helo: res.helo }[key];
                    expect(value, key).to.equal(cleaned(expected));
                }
                if (!('envelope-from' in receivedSpf.pairs) && mailFrom) {
                    // only left out when it is too long to fit on a line
                    expect(Buffer.byteLength(cleaned(res['envelope-from']))).to.be.above(800);
                }

                let ar = parseAuthResults(`${mta}; ${res.info}`);
                expect(ar.results).to.have.lengthOf(1);
                expect(ar.results[0].method).to.equal('spf');
                expect(ar.results[0].result).to.equal(res.status.result);
            }),
            300
        ));
});
