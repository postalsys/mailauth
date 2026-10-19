import { dkimSign, DkimSignStream } from './dkim/sign.js';
import { dkimVerify } from './dkim/verify.js';
import { dkim2Sign, Dkim2SignStream } from './dkim2/sign.js';
import { dkim2Verify } from './dkim2/verify.js';
import { dkim2Hash } from './dkim2/hash.js';
import { spf } from './spf/index.js';
import { dmarc, evaluateDmarc } from './dmarc/index.js';
import { arc, createSeal, sealMessage, getARChain, verifyASChain } from './arc/index.js';
import { bimi, validateVMC as validateBimiVmc } from './bimi/index.js';
import { validateSvg as validateBimiSvg } from './bimi/validate-svg.js';
import { parseReceived, getClientAddress, getClientHelo } from './parse-received.js';
import { formatDomain, getAlignment, formatAuthservId } from './tools.js';
import { buffer as readStream } from 'node:stream/consumers';
import libmime from 'libmime';
import os from 'node:os';
import { isIP } from 'net';
import type { Readable } from 'node:stream';
import type { AlignmentEntry } from './tools.js';
import type {
    ARCResult,
    AuthenticateOptions,
    AuthenticateResult,
    BIMIResult,
    DKIM2VerifyResult,
    DMARCResult,
    MessageInput,
    ReceivedChainEntry,
    SPFOptions
} from './types.js';

export type * from './types.js';

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
 * @param {Boolean} [opts.dkim2=false] If true then DKIM2 header fields are verified as well (draft-ietf-dkim-dkim2-spec-06)
 * @param {String|String[]} [opts.rcptTo] RCPT TO addresses of the delivery, checked against the DKIM2 chain of custody
 * @param {Object} [opts.dkim2Options] Extra options for the DKIM2 verifier (maxSignatureAge, maxFutureTime, maxInstances, checkReplay, curTime)
 * @returns Authentication result
 */
const authenticate = async (input: MessageInput, opts?: AuthenticateOptions): Promise<AuthenticateResult> => {
    opts = Object.assign({}, opts); // copy keys

    opts.mta = opts.mta || os.hostname();
    opts.strict = !!opts.strict;

    // RFC 8601 section 2.5: the authserv-id, usually a host name. A value that is not a token is
    // quoted, or throws under strict, before any work is done
    const authservId = formatAuthservId(opts.mta, opts.strict);

    if (opts.dkim2 && typeof (input as Readable)?.on === 'function') {
        // DKIM2 reads the message a second time, so a stream is read into memory first
        input = await readStream(input as Readable);
    }

    const dkimResult = await dkimVerify(input, {
        resolver: opts.resolver,
        sender: opts.sender, // defaults to Return-Path header
        seal: opts.seal,
        minBitLength: opts.minBitLength,
        rejectRsaSha1: opts.rejectRsaSha1,
        strict: opts.strict
    });

    // parseReceived() returns false for a header line without a colon, which a "received" row
    // only is when it is the first line of the header block and has no colon at all. Such a row
    // is left out, the result lists parsed Received header fields only
    const receivedChain = dkimResult.headers?.parsed
        .filter(r => r.key === 'received')
        .map(row => parseReceived(row.line))
        .filter((entry): entry is ReceivedChainEntry => !!entry);

    // parse client information from last Received header if needed
    if (opts.trustReceived) {
        let rcvd = receivedChain?.find(row => row.from?.value);
        if (rcvd) {
            let helo = getClientHelo(rcvd);
            // the address of the connection from the TCP-info part of the from clause
            // (RFC 5321 section 4.4), never an address the client claimed in its HELO
            let ip = getClientAddress(rcvd);

            // the HELO name of the header belongs to its connection, it is not combined with
            // an address the caller provided
            let callerIp = !!opts.ip;

            if (ip && !callerIp) {
                opts.ip = ip;
            }

            if (helo && !opts.helo && !callerIp) {
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

    // DKIM2 runs alongside SPF. The delivery is compared with the highest DKIM2-Signature only
    // when it is known
    const dkim2Verification =
        opts.dkim2 &&
        dkim2Verify(
            input,
            Object.assign({}, opts.dkim2Options, {
                resolver: opts.resolver,
                mailFrom: typeof opts.sender === 'string' ? opts.sender : undefined,
                rcptTo: opts.rcptTo
            })
        );
    // a rejection is handled by the await below, this keeps it from being reported as unhandled
    // while SPF runs
    // (`false` has no catch method, so nothing is called for it)
    (dkim2Verification as Promise<DKIM2VerifyResult> | undefined)?.catch?.(() => false);

    // spf() handles a missing ip, SPFOptions declares it as required
    const spfResult = await spf(opts as SPFOptions);
    const dkim2Result = await dkim2Verification;

    let arcResult: ARCResult | undefined;
    if (!opts.disableArc) {
        // the DKIM verifier always sets the ARC data, so dkimVerify() always returns it
        arcResult = await arc(dkimResult.arc!, {
            resolver: opts.resolver,
            minBitLength: opts.minBitLength,
            strict: opts.strict,
            // reported as smtp.remote-ip in strict mode (RFC 8617 section 6)
            ip: opts.ip
        });
    }

    let headers: string[] = [];
    let arHeader: string[] = [];
    let receivedSpfHeader: string | false = false;

    dkimResult?.results?.forEach(row => {
        arHeader.push(`${libmime.foldLines(row.info, 160)}`);
    });

    if ((dkim2Result as DKIM2VerifyResult | undefined)?.info) {
        // draft-gondwana-dkim2-authres-00: the method is not registered yet. DKIM2 results do not
        // take part in DMARC, that is an open question (draft-ietf-dkim-dkim2-bcp-01 section 7.2)
        arHeader.push(libmime.foldLines((dkim2Result as DKIM2VerifyResult).info, 160));
    }

    if (spfResult) {
        arHeader.push(libmime.foldLines(spfResult.info, 160));
        receivedSpfHeader = spfResult.header;
    }

    if (arcResult?.info) {
        arHeader.push(`${libmime.foldLines(arcResult.info, 160)}`);
    }

    let dmarcResult: DMARCResult | false | undefined;
    let dmarcSkipReason: AuthenticateResult['dmarcSkipReason'];
    if (!opts.disableDmarc && dkimResult?.headerFrom) {
        let dkimAligned;
        ({
            response: dmarcResult,
            dkimAligned,
            reason: dmarcSkipReason
        } = await evaluateDmarc({
            headerFrom: dkimResult.headerFrom,
            fromFields: dkimResult.fromFields,
            fromSyntax: dkimResult.fromSyntax,
            spfDomains: ([] as string[]).concat((spfResult && spfResult.status.result === 'pass' && spfResult.domain) || []),
            dkimDomains: (dkimResult.results || [])
                .filter(r => r.status.result === 'pass')
                .map(r => ({
                    id: r.id,
                    // a passing signature always has a signing domain
                    domain: r.signingDomain as string,
                    aligned: r.status.aligned,
                    underSized: r.status.underSized
                })),
            arcResult,
            resolver: opts.resolver,
            strict: opts.strict
        }));
        if ((dmarcResult as DMARCResult | undefined)?.info) {
            arHeader.push(`${libmime.foldLines((dmarcResult as DMARCResult).info, 160)}`);
        }

        if (dkimAligned && dmarcResult) {
            // The DKIM verifier runs before the DMARC record and the Tree Walks are known, so its
            // per signature flag only guesses relaxed alignment from the Public Suffix List.
            // Passing signatures take the DMARC verdict, failing ones the record's alignment mode.
            // dkimAligned is only returned with a complete result, which has status.header and alignment
            let fromDomain = dmarcResult.status.header!.from;
            for (let row of dkimResult.results || []) {
                if (row.status.result === 'pass') {
                    row.status.aligned = dkimAligned.has(formatDomain(row.signingDomain as string)) ? row.signingDomain : false;
                } else if (dmarcResult.alignment!.dkim.strict) {
                    // getAlignment() returns false or an entry, `?.domain` of false is undefined
                    row.status.aligned =
                        (row.status.aligned && (getAlignment(fromDomain, [row.signingDomain as string], true) as Partial<AlignmentEntry>)?.domain) || false;
                }
            }
        }
    }

    let bimiResult: BIMIResult | false | undefined;
    if (!opts.disableBimi) {
        bimiResult = await bimi({
            dmarc: dmarcResult,
            headers: dkimResult.headers,
            bimiWithAlignedDkim: opts.bimiWithAlignedDkim,
            resolver: opts.resolver,
            strict: opts.strict
        });
    }

    if ((bimiResult as BIMIResult | undefined)?.info) {
        arHeader.push(`${libmime.foldLines((bimiResult as BIMIResult).info, 160)}`);
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
    // arcResult is always set here: without it neither condition after the seal check holds
    if (dkimResult?.seal && (['none', 'pass'].includes(arcResult?.status?.result as string) || arcResult?.status?.shouldSeal)) {
        // createSeal picks the instance: the next one after the highest on the message, even if
        // some of the ARC headers were not part of a valid chain, and never a 51st set
        let sealResult = await createSeal(false, {
            headers: dkimResult.headers,
            arc: dkimResult.arc,
            // the chain status, the AAR and the instance always come from this message, never
            // from the caller's seal options (RFC 8617 section 5.1 step 4)
            seal: Object.assign({ signTime: new Date() }, dkimResult.seal, {
                cv: arcResult!.status.result,
                authResults: arcResult!.authResults,
                i: undefined
            }),
            strict: opts.strict
        });

        if (sealResult?.errors?.length) {
            // sealing failed, usually an unusable key or a chain that is already full. The
            // message goes out unsealed, so say why somewhere the caller can find it rather
            // than dropping it silently
            arcResult!.sealErrors = sealResult.errors;
        }

        // the ARC headers go on top of the message
        headers.unshift(...(sealResult?.headers || []));
    }

    const result: AuthenticateResult = {
        dkim: dkimResult,
        dkim2: dkim2Result || false,
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

export {
    authenticate,
    dkimSign,
    DkimSignStream,
    dkimVerify,
    dkim2Sign,
    Dkim2SignStream,
    dkim2Verify,
    dkim2Hash,
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

// `import mailauth from 'mailauth'` gets every function, the way the CommonJS package was
// loaded as a default import. The CommonJS build makes the default export the module itself
export default {
    authenticate,
    dkimSign,
    DkimSignStream,
    dkimVerify,
    dkim2Sign,
    Dkim2SignStream,
    dkim2Verify,
    dkim2Hash,
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
