'use strict';

const { dkimVerify } = require('./dkim/verify');
const { spf } = require('./spf');
const { dmarc } = require('./dmarc');
const { arc } = require('./arc');
const libmime = require('libmime');
const os = require('os');

/**
 * Verifies DKIM and SPF for an email message
 *
 * @param {ReadableStream|Buffer|String} input RFC822 formatted message
 * @param {Object} opts Message options
 * @param {String} opts.sender Address from MAIL FROM
 * @param {String} opts.ip Client IP address
 * @param {String} opts.helo Hostname from EHLO/HELO
 * @param {String} [opts.mta] MTA/MX hostname (defaults to os.hostname)
 * @returns {Object} Authentication result
 */
const authenticate = async (input, opts) => {
    opts.mta = opts.mta || os.hostname();

    const [dkimResult, spfResult] = await Promise.all([
        dkimVerify(input, {
            resolver: opts.resolver,
            sender: opts.sender
        }),
        spf(opts)
    ]);

    const arcResult = await arc(dkimResult.arc, {
        resolver: opts.resolver
    });

    let headers = [];

    let arHeader = [];
    if (dkimResult && dkimResult.results) {
        dkimResult.results.forEach(row => {
            arHeader.push(`${libmime.foldLines(row.info, 160)}`);
        });
    }

    if (spfResult) {
        arHeader.push(libmime.foldLines(spfResult.info, 160));
        headers.push(spfResult.header);
    }

    if (arcResult && arcResult.info) {
        arHeader.push(`${libmime.foldLines(arcResult.info, 160)}`);
    }

    let dmarcResult;
    if (dkimResult && dkimResult.headerFrom) {
        dmarcResult = await dmarc({
            headerFrom: dkimResult.headerFrom,
            spfDomains: [].concat((spfResult && spfResult.status.result === 'pass' && spfResult.domain) || []),
            dkimDomains: (dkimResult.results || []).filter(r => r.status.result === 'pass').map(r => r.signingDomain),
            arcResult,
            resolver: opts.resolver
        });
        if (dmarcResult.info) {
            arHeader.push(`${libmime.foldLines(dmarcResult.info, 160)}`);
        }
    }

    headers.push(`Authentication-Results: ${opts.mta};\r\n ` + arHeader.join(';\r\n '));

    return {
        dkim: dkimResult,
        spf: spfResult,
        dmarc: dmarcResult,
        arc: arcResult,
        headers: headers.join('\r\n') + '\r\n'
    };
};

module.exports = { authenticate };
