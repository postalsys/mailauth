'use strict';

const { dkimVerify } = require('./dkim/verify');
const { spf } = require('./spf');
const { dmarc } = require('./dmarc');
const { arc, createSeal } = require('./arc');
const { bimi, validateVMC: validateBimiVmc } = require('./bimi');
const { validateSvg: validateBimiSvg } = require('./bimi/validate-svg');
const { parseReceived } = require('./parse-received');
const { sealMessage } = require('./arc');
const libmime = require('libmime');
const os = require('node:os');
const { isIP } = require('net');

/**
 * Verifies DKIM and SPF for an email message
 *
 * @param {ReadableStream|Buffer|String} input RFC822 formatted message
 * @param {Object} opts Message options
 * @param {Boolean} [opts.trustReceived] If true then parses ip and helo values from Received header and sender value from Return-Path
 * @param {String} [opts.sender] Address from MAIL FROM
 * @param {String} [opts.ip] Client IP address
 * @param {String} [opts.helo] Hostname from EHLO/HELO
 * @param {String} [opts.mta] MTA/MX hostname (defaults to os.hostname)
 * @param {Number} [opts.minBitLength=1024] Minimal allowed length of public keys. If DKIM/ARC key is smaller, then verification fails
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
        seal: opts.seal,
        minBitLength: opts.minBitLength
    });

    const receivedChain = dkimResult.headers?.parsed.filter(r => r.key === 'received').map(row => parseReceived(row.line));

    // parse client information from last Received header if needed
    if (opts.trustReceived) {
        let rcvd = receivedChain?.find(row => row.from?.value);
        if (rcvd) {
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

            if (helo && !opts.helo && !opts.ip) {
                // if IP was provided then do not use helo even if it is missing
                opts.helo = helo;
            }

            if (rcvd['envelope-from']?.value && !opts.sender) {
                // prefer Received:envelope-from to Return-Path
                opts.sender = rcvd['envelope-from'].value.replace(/[<>]/g, '').trim();
            }
        }

        if (dkimResult.envelopeFrom && !opts.sender) {
            opts.sender = dkimResult.envelopeFrom;
        }
    }

    if (!opts.helo && opts.ip) {
        opts.helo = opts.ip;
    }

    if (opts.helo && isIP(opts.helo)) {
        // use the bracket syntax
        opts.helo = `[${opts.helo}]`;
    }

    const spfResult = await spf(opts);

    let arcResult;
    if (!opts.disableArc) {
        arcResult = await arc(dkimResult.arc, {
            resolver: opts.resolver,
            minBitLength: opts.minBitLength
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
            dkimDomains: (dkimResult.results || [])
                .filter(r => r.status.result === 'pass')
                .map(r => ({
                    id: r.id,
                    domain: r.signingDomain,
                    aligned: r.status.aligned,
                    underSized: r.status.underSized
                })),
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
            bimiWithAlignedDkim: opts.bimiWithAlignedDkim,
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
        dkim: dkimResult,
        spf: spfResult,
        dmarc: dmarcResult || false,
        arc: arcResult || false,
        bimi: bimiResult || false,
        receivedChain,
        headers: headers.join('\r\n') + '\r\n'
    };
};

module.exports = {
    authenticate,
    sealMessage,
    validateBimiVmc,
    validateBimiSvg
};
