'use strict';

const { dkimVerify } = require('./dkim/verify');
const { spf } = require('./spf');
const { dmarc } = require('./dmarc');
const { arc, createSeal } = require('./arc');
const { bimi } = require('./bimi');
const { parseReceived } = require('./parse-received');
const libmime = require('libmime');
const os = require('os');

/**
 * Verifies DKIM and SPF for an email message
 *
 * @param {ReadableStream|Buffer|String} input RFC822 formatted message
 * @param {Object} opts Message options
 * @param {Boolean} [opts.trustReceived] If true then parses ip and helo values from Received header
 * @param {String} [opts.sender] Address from MAIL FROM. Parsed from Return-Path if not set
 * @param {String} [opts.ip] Client IP address
 * @param {String} [opts.helo] Hostname from EHLO/HELO
 * @param {String} [opts.mta] MTA/MX hostname (defaults to os.hostname)
 * @param {Object} [opts.seal] ARC sealing options
 * @param {String} [opts.seal.signingDomain] ARC key domain name
 * @param {String} [opts.seal.selector] ARC key selector
 * @param {String|Buffer} [opts.seal.privateKey] Private key for signing
 * @param {Boolean} [opts.disableArc=false] If true then do not perform ARC validation and sealing
 * @param {Boolean} [opts.disableDmarc=false] If true then do not perform DMARC check
 * @param {Boolean} [opts.disableBimi=false] If true then do not perform BIMI check
 * @returns {Object} Authentication result
 */
const authenticate = async (input, opts) => {
    opts = Object.assign({}, opts); // copy keys

    opts.mta = opts.mta || os.hostname();

    const dkimResult = await dkimVerify(input, {
        resolver: opts.resolver,
        sender: opts.sender, // defaults to Return-Path header
        seal: opts.seal
    });

    const receivedChain = dkimResult.headers?.parsed.filter(r => r.key === 'received').map(row => parseReceived(row.line));

    // parse client information from last Received header if needed
    if (opts.trustReceived) {
        if (dkimResult.envelopeFrom && !opts.sender) {
            opts.sender = dkimResult.envelopeFrom;
        }

        let rcvd = receivedChain?.[0];
        if (rcvd?.from) {
            let helo = rcvd.from.value;
            let ip;
            if (rcvd.from.comment) {
                let ipMatch = rcvd.from.comment.match(/\[([^\]]+)\]/);
                if (ipMatch) {
                    ip = ipMatch[1].replace(/^IPv6:/i, '');
                }
            }

            if (ip && !opts.ip) {
                opts.ip = ip;
            }

            if (helo && !opts.helo) {
                opts.helo = helo;
            }
        }
    }

    const spfResult = await spf(opts);

    let arcResult;
    if (!opts.disableArc) {
        arcResult = await arc(dkimResult.arc, {
            resolver: opts.resolver
        });
    }

    let headers = [];
    let arHeader = [];

    dkimResult?.results?.forEach(row => {
        arHeader.push(`${libmime.foldLines(row.info, 160)}`);
    });

    if (spfResult) {
        arHeader.push(libmime.foldLines(spfResult.info, 160));
        headers.push(spfResult.header);
    }

    if (arcResult?.info) {
        arHeader.push(`${libmime.foldLines(arcResult.info, 160)}`);
    }

    let dmarcResult;
    if (!opts.disableDmarc && dkimResult?.headerFrom) {
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

    let bimiResult;
    if (!opts.disableBimi) {
        bimiResult = await bimi({
            dmarc: dmarcResult,
            headers: dkimResult.headers,
            resolver: opts.resolver
        });
    }

    if (bimiResult?.info) {
        arHeader.push(`${libmime.foldLines(bimiResult.info, 160)}`);
    }

    headers.push(`Authentication-Results: ${opts.mta};\r\n ` + arHeader.join(';\r\n '));

    if (arcResult) {
        arcResult.authResults = `${opts.mta};\r\n ` + arHeader.join(';\r\n ');
    }

    // seal only messages with a valid ARC chain
    if (dkimResult?.seal && (['none', 'pass'].includes(arcResult?.status?.result) || arcResult?.status?.shouldSeal)) {
        let i = arcResult.i + 1;
        let seal = Object.assign(
            {
                i,
                cv: arcResult.status.result,
                authResults: arcResult.authResults,
                signTime: new Date()
            },
            dkimResult.seal
        );

        // get ARC sealing headers to prepend to the message
        let sealResult = await createSeal(false, {
            headers: dkimResult.headers,
            arc: dkimResult.arc,
            seal
        });

        sealResult?.headers?.reverse().forEach(header => headers.unshift(header));
    }

    return {
        receivedChain,
        dkim: dkimResult,
        spf: spfResult,
        dmarc: dmarcResult || false,
        arc: arcResult || false,
        bimi: bimiResult || false,
        headers: headers.join('\r\n') + '\r\n'
    };
};

module.exports = { authenticate };
