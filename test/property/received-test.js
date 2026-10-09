'use strict';

const { expect } = require('chai');

const { parseReceived, getClientAddress, getClientHelo } = require('../../lib/parse-received');
const { fc, check, timeout } = require('./helper');

// The address of the connection, written by the receiving server
const clientIp = fc.oneof(fc.ipV4(), fc.ipV6());
// Addresses the client puts into its HELO argument to impersonate another host
const fakeIp = fc.constantFrom('198.51.100.66', '203.0.113.9', '2001:db8::bad', '10.0.0.1');

// A HELO argument as an attacker can send it. Postfix copies the argument into the Received
// header as it is, and Exim writes it after "helo=" in the TCP-info comment. It mixes address
// literals, comments, keywords of the from clause, quotes and backslashes
const heloArgument = fc
    .array(
        fc.oneof(
            fc.constantFrom('mail', 'example.com', '.', '-', ' ', '  ', '(', ')', '[', ']', '"', '\\', ';', 'by', 'from', 'with', 'helo=', 'unknown', 'IPv6:'),
            fakeIp,
            fakeIp.map(ip => `[${ip}]`),
            fakeIp.map(ip => `(unknown [${ip}])`),
            fakeIp.map(ip => `(rdns.example [${ip}])`),
            fakeIp.map(ip => ` by mx.example (${ip}) `)
        ),
        { minLength: 1, maxLength: 8 }
    )
    .map(parts => parts.join(''));

// A HELO name with no special characters, which every format has to read correctly
const plainHelo = fc.domain();

const rdns = fc.oneof(fc.constant('unknown'), fc.domain());

const BY = 'by mx.receiver.example (Postfix) with ESMTPS id 4ABC123\r\n\tfor <rcpt@receiver.example>; Mon, 1 Jan 2024 00:00:00 +0000';

const formats = {
    // Postfix: from HELO (rDNS [IP])
    postfix: (helo, name, ip) => `Received: from ${helo} (${name} [${ip}])\r\n\t${BY}`,
    // Postfix with an IPv6 client
    postfixIPv6Tag: (helo, name, ip) => `Received: from ${helo} (${name} [${ip.includes(':') ? 'IPv6:' + ip : ip}])\r\n\t${BY}`,
    // Exim: from rDNS ([IP] helo=HELO)
    exim: (helo, name, ip) => `Received: from ${name} ([${ip}] helo=${helo})\r\n\t${BY}`,
    // Exim, a client without reverse DNS: from [IP] (helo=HELO)
    eximNoRdns: (helo, name, ip) => `Received: from [${ip}] (helo=${helo})\r\n\t${BY}`,
    // Exim with a port: from rDNS ([IP]:port helo=HELO)
    eximPort: (helo, name, ip) => `Received: from ${name} ([${ip}]:52344 helo=${helo})\r\n\t${BY}`
};

const format = fc.constantFrom(...Object.keys(formats));

const clientAddress = header => getClientAddress(parseReceived(header));

describe('Property: client address from a Received header (getClientAddress)', function () {
    this.timeout(timeout(500));

    it('never returns an address that only the HELO argument has', () =>
        check(
            fc.property(format, heloArgument, rdns, clientIp, (name, helo, reverse, ip) => {
                let header = formats[name](helo, reverse, ip);
                let address = clientAddress(header);
                // either the real address or nothing, never a guess
                expect([ip, false], header).to.deep.include(address);
            }),
            500
        ));

    it('finds the address of the connection when the HELO name is a plain host name', () =>
        check(
            fc.property(format, plainHelo, rdns, clientIp, (name, helo, reverse, ip) => {
                let header = formats[name](helo, reverse, ip);
                expect(clientAddress(header), header).to.equal(ip);
            }),
            300
        ));

    it('reads the HELO name of a plain host name in every format', () =>
        check(
            fc.property(format, plainHelo, fc.domain(), clientIp, (name, helo, reverse, ip) => {
                let header = formats[name](helo, reverse, ip);
                expect(getClientHelo(parseReceived(header)), header).to.equal(helo);
            }),
            300
        ));

    it('never throws, for any input', () =>
        check(
            fc.property(
                fc.oneof(
                    fc.string({ unit: 'binary' }),
                    heloArgument.map(helo => `Received: from ${helo}`)
                ),
                value => {
                    let parsed = parseReceived(value);
                    let address = getClientAddress(parsed);
                    expect(address === false || typeof address === 'string').to.equal(true);
                    let helo = getClientHelo(parsed);
                    expect(helo === false || typeof helo === 'string').to.equal(true);
                }
            ),
            500
        ));
});
