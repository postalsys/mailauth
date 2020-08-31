'use strict';

const { dkimVerify } = require('./dkim/verify');
const { spf } = require('./spf');
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

    let headers = [];

    let arHeader = [];
    if (dkimResult && dkimResult.results) {
        dkimResult.results.forEach(row => {
            arHeader.push(`${libmime.foldLines(row.info)}`);
        });
    }

    if (spfResult) {
        arHeader.push(
            libmime.foldLines(
                `spf=${spfResult.status}${spfResult.info ? ` (${spfResult.info})` : ''}${
                    spfResult['envelope-from'] ? ` smtp.mailfrom=${spfResult['envelope-from']};` : ''
                }`
            )
        );
        headers.push(spfResult.header);
    }

    headers.push(`Authentication-Results: ${opts.mta};\r\n ` + arHeader.join('\r\n '));

    return { dkim: dkimResult, spf: spfResult, headers: headers.join('\r\n') + '\r\n' };
};

module.exports = { authenticate };
