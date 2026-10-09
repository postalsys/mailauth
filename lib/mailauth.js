'use strict';

const { dkimSign, DkimSignStream } = require('./dkim/sign');
const { dkimVerify } = require('./dkim/verify');
const { spf } = require('./spf');
const { dmarc, evaluateDmarc } = require('./dmarc');
const { arc, createSeal, sealMessage, getARChain, verifyASChain } = require('./arc');
const { bimi, validateVMC: validateBimiVmc } = require('./bimi');
const { validateSvg: validateBimiSvg } = require('./bimi/validate-svg');
const { parseReceived, getClientAddress } = require('./parse-received');
const { formatDomain, getAlignment, formatAuthservId } = require('./tools');
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
 * @param {Boolean} [opts.rejectRsaSha1=false] If true then rsa-sha1 DKIM signatures get dkim=policy (weak-algorithm) as in strict mode (RFC 8301), the other checks stay lenient
 * @param {Object} [opts.seal] ARC sealing options
 * @param {String} [opts.seal.signingDomain] ARC key domain name
 * @param {String} [opts.seal.selector] ARC key selector
 * @param {String|Buffer} [opts.seal.privateKey] Private key for signing
 * @param {Boolean} [opts.disableArc=false] If true then do not perform ARC validation and sealing
 * @param {Boolean} [opts.disableDmarc=false] If true then do not perform DMARC check
 * @param {Boolean} [opts.disableBimi=false] If true then do not perform BIMI check
 * @param {Boolean} [opts.strict=false] If true then every check follows its RFC exactly instead of the lenient defaults
 * @returns Authentication result
 */
const authenticate = async (input, opts) => {
    opts = Object.assign({}, opts); // copy keys

    opts.mta = opts.mta || os.hostname();
    opts.strict = !!opts.strict;

    // RFC 8601 section 2.5: the authserv-id, usually a host name. A value that is not a token is
    // quoted, or throws under strict, before any work is done
    const authservId = formatAuthservId(opts.mta, opts.strict);

    const dkimResult = await dkimVerify(input, {
        resolver: opts.resolver,
        sender: opts.sender, // defaults to Return-Path header
        seal: opts.seal,
        minBitLength: opts.minBitLength,
        rejectRsaSha1: opts.rejectRsaSha1,
        strict: opts.strict
    });

    const receivedChain = dkimResult.headers?.parsed.filter(r => r.key === 'received').map(row => parseReceived(row.line));

    // parse client information from last Received header if needed
    if (opts.trustReceived) {
        let rcvd = receivedChain?.find(row => row.from?.value);
        if (rcvd) {
            let helo = rcvd.from.value;
            // the address of the connection from the TCP-info part of the from clause
            // (RFC 5321 section 4.4), never an address the client claimed in its HELO
            let ip = getClientAddress(rcvd.from);

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
            minBitLength: opts.minBitLength,
            strict: opts.strict,
            // reported as smtp.remote-ip in strict mode (RFC 8617 section 6)
            ip: opts.ip
        });
    }

    let headers = [];
    let arHeader = [];
    let receivedSpfHeader = false;

    dkimResult?.results?.forEach(row => {
        arHeader.push(`${libmime.foldLines(row.info, 160)}`);
    });

    if (spfResult) {
        arHeader.push(libmime.foldLines(spfResult.info, 160));
        receivedSpfHeader = spfResult.header;
    }

    if (arcResult?.info) {
        arHeader.push(`${libmime.foldLines(arcResult.info, 160)}`);
    }

    let dmarcResult;
    let dmarcSkipReason;
    if (!opts.disableDmarc && dkimResult?.headerFrom) {
        let dkimAligned;
        ({
            response: dmarcResult,
            dkimAligned,
            reason: dmarcSkipReason
        } = await evaluateDmarc({
            headerFrom: dkimResult.headerFrom,
            fromFields: dkimResult.fromFields,
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
            resolver: opts.resolver,
            strict: opts.strict
        }));
        if (dmarcResult?.info) {
            arHeader.push(`${libmime.foldLines(dmarcResult.info, 160)}`);
        }

        if (dkimAligned && dmarcResult) {
            // The DKIM verifier runs before the DMARC record and the Tree Walks are known, so its
            // per signature flag only guesses relaxed alignment from the Public Suffix List.
            // Passing signatures take the DMARC verdict, failing ones the record's alignment mode.
            let fromDomain = dmarcResult.status.header.from;
            for (let row of dkimResult.results || []) {
                if (row.status.result === 'pass') {
                    row.status.aligned = dkimAligned.has(formatDomain(row.signingDomain)) ? row.signingDomain : false;
                } else if (dmarcResult.alignment.dkim.strict) {
                    row.status.aligned = (row.status.aligned && getAlignment(fromDomain, [row.signingDomain], true)?.domain) || false;
                }
            }
        }
    }

    let bimiResult;
    if (!opts.disableBimi) {
        bimiResult = await bimi({
            dmarc: dmarcResult,
            headers: dkimResult.headers,
            bimiWithAlignedDkim: opts.bimiWithAlignedDkim,
            resolver: opts.resolver,
            strict: opts.strict
        });
    }

    if (bimiResult?.info) {
        arHeader.push(`${libmime.foldLines(bimiResult.info, 160)}`);
    }

    const arValue = `${authservId};\r\n ` + arHeader.join(';\r\n ');
    const authResultsHeader = `Authentication-Results: ${arValue}`;

    if (opts.strict) {
        // RFC 8601 section 5: Authentication-Results "SHOULD be inserted above any other
        // trace header fields", and Received-SPF is one (RFC 7208 section 9.1)
        headers.push(authResultsHeader);
        if (receivedSpfHeader) {
            headers.push(receivedSpfHeader);
        }
    } else {
        if (receivedSpfHeader) {
            headers.push(receivedSpfHeader);
        }
        headers.push(authResultsHeader);
    }

    if (arcResult) {
        arcResult.authResults = arValue;
    }

    // seal only messages with a valid ARC chain
    if (dkimResult?.seal && (['none', 'pass'].includes(arcResult?.status?.result) || arcResult?.status?.shouldSeal)) {
        // createSeal picks the instance: the next one after the highest on the message, even if
        // some of the ARC headers were not part of a valid chain, and never a 51st set
        let sealResult = await createSeal(false, {
            headers: dkimResult.headers,
            arc: dkimResult.arc,
            // the chain status, the AAR and the instance always come from this message, never
            // from the caller's seal options (RFC 8617 section 5.1 step 4)
            seal: Object.assign({ signTime: new Date() }, dkimResult.seal, {
                cv: arcResult.status.result,
                authResults: arcResult.authResults,
                i: undefined
            }),
            strict: opts.strict
        });

        if (sealResult?.errors?.length) {
            // sealing failed, usually an unusable key or a chain that is already full. The
            // message goes out unsealed, so say why somewhere the caller can find it rather
            // than dropping it silently
            arcResult.sealErrors = sealResult.errors;
        }

        // the ARC headers go on top of the message
        headers.unshift(...(sealResult?.headers || []));
    }

    const result = {
        dkim: dkimResult,
        spf: spfResult,
        dmarc: dmarcResult || false,
        arc: arcResult || false,
        bimi: bimiResult || false,
        receivedChain,
        headers: headers.join('\r\n') + '\r\n'
    };

    if (!dmarcResult && dmarcSkipReason) {
        // RFC 9989 section 5.3.1: DMARC can not be evaluated for a message with no Author
        // Domain or with more than one, and section 11.5 suggests treating such a message as
        // suspicious. `dmarc` stays false, this says why
        result.dmarcSkipReason = dmarcSkipReason;
    }

    return result;
};

module.exports = {
    authenticate,
    dkimSign,
    DkimSignStream,
    dkimVerify,
    spf,
    dmarc,
    arc,
    sealMessage,
    getARChain,
    verifyASChain,
    createSeal,
    bimi,
    validateBimiVmc,
    validateBimiSvg
};
