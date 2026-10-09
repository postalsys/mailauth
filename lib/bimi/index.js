'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const dns = require('node:dns');
const net = require('node:net');
const zlib = require('node:zlib');
const { formatAuthHeaderRow, parseDkimHeaders, parseTagList, formatDomain, getAlignment } = require('../tools');
const Joi = require('joi');
const libmime = require('libmime');
const addressparser = require('nodemailer/lib/addressparser');
const getDmarcRecord = require('../dmarc/get-dmarc-record');
const { parseDmarcRecord } = getDmarcRecord;
//const packageData = require('../../package.json');
const httpsSchema = Joi.string().uri({
    scheme: ['https']
});

const FETCH_TIMEOUT = 5 * 1000;
// overall time limit for a download, including redirects and the response body
const DOWNLOAD_TIMEOUT = 30 * 1000;
const MAX_REDIRECTS = 3;
// SVG Tiny PS 2.4: an Indicator SHOULD NOT exceed 32 kilobytes, uncompressed
const MAX_LOGO_SIZE = 64 * 1024;
const MAX_EVIDENCE_SIZE = 256 * 1024;

const { fetch: fetchCmd, Agent } = require('undici');
const fetchAgent = new Agent({
    connect: { timeout: FETCH_TIMEOUT }
});

const { vmc } = require('@postalsys/vmc');
const { validateSvg } = require('./validate-svg');

// Records that do not start with a "v=" tag for the current version are discarded (7.2 steps 4 and 7)
const BIMI_VERSION_RE = /^v[ \t]*=[ \t]*BIMI1[ \t]*(?:;|$)/i;

const POLICY_VALUES = new Set(['none', 'quarantine', 'reject']);

// 4.3: avp= values, any other value is ignored and not added to headers
const AVATAR_PREFERENCES = new Set(['personal', 'brand']);

const createError = (message, code, details) => {
    let error = new Error(message);
    error.code = code;
    if (details) {
        error.details = details;
    }
    return error;
};

// Checks that a URL is an HTTPS URL with a fully qualified domain name (4.3): IP literals,
// single-label names and localhost are not allowed
const isValidHttpsUrl = value => {
    if (httpsSchema.validate(value).error) {
        return false;
    }
    let url;
    try {
        url = new URL(value);
    } catch (err) {
        return false;
    }
    let hostname = url.hostname
        .replace(/^\[|\]$/g, '')
        .replace(/\.$/, '')
        .toLowerCase();
    if (url.protocol !== 'https:' || !hostname || net.isIP(hostname) || !hostname.includes('.')) {
        return false;
    }
    // URL parsing already turns numeric hosts like "https://2130706433/" into IPv4 addresses
    if (/^[0-9.]+$/.test(hostname) || hostname === 'localhost' || hostname.endsWith('.localhost')) {
        return false;
    }
    return true;
};

// Returns the reason a DMARC record does not meet the policy requirements of
// draft-brand-indicators-for-message-identification 7.1 steps 7 to 9, or false if it does
const checkDmarcRecord = record => {
    // a record without a valid "p" is applied as p=none, or not at all (RFC 9989 4.10.1)
    if (!POLICY_VALUES.has(record.p) || record.p === 'none') {
        return 'too lax DMARC policy';
    }
    if (record.sp === 'none') {
        return 'too lax DMARC subdomain policy';
    }
    if (record.p === 'quarantine' && record.pct !== undefined && record.pct !== 100) {
        return 'DMARC policy applied to a percentage of messages';
    }
    return false;
};

// Parses a BIMI Assertion Record, which uses the DKIM tag-list syntax (4.3, RFC 6376 3.2). The
// values are the strings of the tag list: the parsed map of parseTagList would turn an empty "l="
// into the number 0. Tag names are case-folded and the last duplicate wins, as before.
const parseAssertionRecord = record => {
    let tags = {};
    for (let tag of parseTagList(record).tags) {
        let name = tag.name.trim().toLowerCase();
        if (name) {
            tags[name] = tag.value;
        }
    }
    return tags;
};

// Counts the addresses in the From header fields, including members of a group
const countFromAddresses = headerRows => {
    let fromRows = headerRows.filter(row => row.key === 'from');
    if (fromRows.length > 1) {
        return fromRows.length;
    }
    let count = 0;
    for (let row of fromRows) {
        let value = (row.line || '').toString();
        let splitterPos = value.indexOf(':');
        let list = addressparser((splitterPos >= 0 ? value.substr(splitterPos + 1) : value).trim());
        for (let entry of list) {
            count += Array.isArray(entry.group) ? entry.group.length : 1;
        }
    }
    return count;
};

const lookup = async data => {
    let { dmarc, headers, resolver, bimiWithAlignedDkim, strict } = data;
    let headerRows = (headers && headers.parsed) || [];

    resolver = resolver || dns.promises.resolve;

    if (!dmarc) {
        // DMARC check not performed
        return false;
    }

    let response = { status: { header: {} } };

    const finish = (result, comment) => {
        response.status.result = result;
        if (comment) {
            response.status.comment = comment;
        }
        response.info = formatAuthHeaderRow('bimi', response.status, { strict });
        return response;
    };

    // 7.1 step 1: one From header field with one address. DMARC evaluates several addresses of the same domain.
    let mailboxes = typeof dmarc.authorMailboxes === 'number' ? dmarc.authorMailboxes : 0;
    if (mailboxes > 1 || countFromAddresses(headerRows) > 1) {
        return finish('skipped', 'multiple From addresses');
    }

    if (dmarc.status?.result !== 'pass') {
        return finish('skipped', dmarc.status?.result === 'none' ? 'DMARC not enabled' : 'message failed DMARC');
    }

    // a domain testing its policy (t=y) is not enforcing it yet
    if (dmarc.policy === 'none' || dmarc.testMode) {
        return finish('skipped', 'too lax DMARC policy');
    }

    if (!dmarc.alignment?.dkim?.result && bimiWithAlignedDkim) {
        return finish('skipped', 'Aligned DKIM signature required');
    }

    if (dmarc.alignment?.dkim?.underSized) {
        return finish('skipped', 'undersized DKIM signature');
    }

    const authorDomain = dmarc.status?.header?.from;
    const orgDomain = dmarc.domain;

    if (!authorDomain || !orgDomain) {
        // should this even happen?
        return finish('skipped', 'could not determine domain');
    }

    // 7.1 steps 7 to 9: neither the record for the Author Domain nor the one for the Author
    // Organizational Domain may be p=none or sp=none, or apply quarantine to a percentage only.
    // dmarc() provides both records, for a result built elsewhere they are looked up here.
    let dmarcRecords = [];
    let appliedRecord = dmarc.record || (dmarc.rr ? parseDmarcRecord(dmarc.rr) : null);
    if (appliedRecord) {
        dmarcRecords.push(appliedRecord);
    }
    let orgRecord = dmarc.orgRecord;
    if (orgRecord === undefined) {
        let appliedDomain = dmarc.policyDomain || dmarc.status?.header?.d || formatDomain(authorDomain);
        if (formatDomain(orgDomain) !== formatDomain(appliedDomain) || !appliedRecord) {
            try {
                orgRecord = await getDmarcRecord(orgDomain, resolver);
            } catch (err) {
                orgRecord = null;
            }
        } else {
            orgRecord = false;
        }
    }
    if (orgRecord === null) {
        // the Tree Walk that finds the Organizational Domain failed
        return finish('temperror', 'failed to resolve the DMARC policy of the organizational domain');
    }
    if (orgRecord) {
        dmarcRecords.push(orgRecord);
    }
    for (let record of dmarcRecords) {
        let reason = checkDmarcRecord(record);
        if (reason) {
            return finish('skipped', reason);
        }
    }

    let selector;

    let bimiSelectorHeader;
    for (let row of headerRows) {
        if (['bimi-selector'].includes(row.key)) {
            if (bimiSelectorHeader) {
                // already found one
                return finish('fail', 'multiple BIMI-Selector headers');
            }

            bimiSelectorHeader = parseDkimHeaders(row.line);
            if (bimiSelectorHeader?.parsed?.v?.value?.toLowerCase() !== 'bimi1') {
                return finish('fail', 'missing bimi version in selector header');
            }

            selector = bimiSelectorHeader?.parsed?.s?.value;
        }
    }

    selector = selector?.trim() || 'default';

    // 7.2 steps 3 and 6: the selector at the Author Domain, then the same selector at the
    // Organizational Domain. A custom selector does not fall back to "default".
    let bimiTags = [`${selector}._bimi.${authorDomain}`];
    if (formatDomain(authorDomain) !== formatDomain(orgDomain)) {
        bimiTags.push(`${selector}._bimi.${orgDomain}`);
    }

    let record;
    for (let d of bimiTags) {
        let txt;
        try {
            txt = await resolver(d, 'TXT');
        } catch (err) {
            if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
                continue;
            }
            // "temperror" is the result keyword of the draft (7.7), older versions used "temperr"
            return finish('temperror', `failed to resolve ${d}`);
        }

        // 7.2 steps 4 and 7: other TXT records, such as site verification tokens, are discarded
        let records = []
            .concat(txt || [])
            .map(row => (Array.isArray(row) ? row.join('') : String(row)).trim())
            .filter(row => BIMI_VERSION_RE.test(row));

        if (records.length === 1) {
            record = records[0];
            response.status.header.selector = d.split('._bimi.').shift();
            response.status.header.d = d.split('._bimi.').pop();
            response.rr = record;
            break;
        } else if (records.length > 1) {
            // 7.2 step 9: several records end the discovery
            return finish('fail', `multiple BIMI records for ${d}`);
        }
    }

    if (!record) {
        return finish('none');
    }

    let recordData = parseAssertionRecord(record);
    if (recordData.v?.toLowerCase() !== 'bimi1') {
        return finish('fail', 'missing bimi version in dns record');
    }

    let location = recordData.l;
    let authority = recordData.a;

    // 4.3.1 and 7.5: an empty l= with an empty or missing a= is a Declination to Publish
    if (location === '' && !authority) {
        return finish('declined');
    }

    // l= is required (4.3), and 7.3 step 1 needs a valid one even when a= is set
    if (!location) {
        return finish('fail', 'missing location value in dns record');
    }

    if (!isValidHttpsUrl(location)) {
        return finish('fail', 'invalid location value in dns record');
    }

    if (authority && !isValidHttpsUrl(authority)) {
        return finish('fail', 'invalid authority value in dns record');
    }

    response.status.result = 'pass';

    response.location = location;

    if (authority) {
        response.authority = authority;

        // Apple Mail requires additional policy header values in Authentication-Results header
        response.status.policy = { authority: 'none', 'authority-uri': authority }; // VMC has not been actually checked here yet, so authority is none
    }

    if (AVATAR_PREFERENCES.has(recordData.avp)) {
        response.preference = recordData.avp;
    }

    response.info = formatAuthHeaderRow('bimi', response.status, { strict });
    return response;
};

const tooLarge = maxSize => createError(`File is larger than ${maxSize} bytes`, 'FILE_TOO_LARGE');

// Reads a response body, stops at maxSize bytes (7.6 step 1 allows a retrieval limit)
const readBody = async (res, maxSize) => {
    if (Number(res.headers.get('content-length')) > maxSize) {
        await res.body?.cancel().catch(() => false);
        throw tooLarge(maxSize);
    }
    let chunks = [];
    let size = 0;
    if (res.body) {
        // leaving the loop early cancels the stream
        for await (let chunk of res.body) {
            size += chunk.length;
            if (size > maxSize) {
                throw tooLarge(maxSize);
            }
            chunks.push(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
        }
    }
    return Buffer.concat(chunks, size);
};

const downloadPromise = async (url, cachedFile, maxSize, opts) => {
    if (cachedFile) {
        if (cachedFile.length > maxSize) {
            throw tooLarge(maxSize);
        }
        return cachedFile;
    }

    if (!url) {
        return false;
    }

    let timeout = typeof opts.timeout === 'number' && opts.timeout > 0 ? opts.timeout : DOWNLOAD_TIMEOUT;
    let signal = AbortSignal.timeout(timeout);

    try {
        // Redirects are followed manually, each target has to be a valid HTTPS URL (7.5 step 1)
        for (let redirects = 0; ; redirects++) {
            if (!isValidHttpsUrl(url)) {
                throw createError('Download URL must be an HTTPS URL with a domain name', 'INVALID_URL', { url });
            }

            let res = await fetchCmd(url, {
                headers: {
                    // Comment: AKAMAI does some strange UA based filtering that messes up the request
                    // 'User-Agent': `mailauth/${packageData.version} (+${packageData.homepage}`
                },
                redirect: 'manual',
                signal,
                dispatcher: opts.dispatcher || fetchAgent
            });

            if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
                await res.body?.cancel().catch(() => false);
                let target;
                try {
                    target = new URL(res.headers.get('location'), url).href;
                } catch (err) {
                    target = res.headers.get('location');
                }
                if (redirects >= MAX_REDIRECTS || !isValidHttpsUrl(target)) {
                    let error = createError(
                        redirects >= MAX_REDIRECTS ? 'Too many redirects' : 'Redirect target must be an HTTPS URL with a domain name',
                        'HTTP_REDIRECT_NOT_ALLOWED'
                    );
                    error.redirect = target;
                    throw error;
                }
                url = target;
                continue;
            }

            if (!res.ok) {
                await res.body?.cancel().catch(() => false);
                throw createError(`Request failed with status ${res.status}`, 'HTTP_REQUEST_FAILED');
            }

            return await readBody(res, maxSize);
        }
    } catch (err) {
        // DOMException codes are numbers
        if (signal.aborted && typeof err.code !== 'string') {
            throw createError(`Request timed out after ${timeout} ms`, 'HTTP_REQUEST_TIMEOUT');
        }
        throw err;
    }
};

// Returns the SVG document of a downloaded Indicator. An SVGZ file is uncompressed (5.3, 7.10).
const getIndicatorSvg = (data, maxSize) => {
    if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b) {
        try {
            return zlib.gunzipSync(data, { maxOutputLength: maxSize });
        } catch (err) {
            if (err.code === 'ERR_BUFFER_TOO_LARGE') {
                throw tooLarge(maxSize);
            }
            throw createError('Invalid SVGZ file', 'INVALID_SVGZ_FILE');
        }
    }
    return data;
};

const getSizeOption = (value, defaultValue) => (typeof value === 'number' && value > 0 ? value : defaultValue);

const validateVMC = async (bimiData, opts) => {
    opts = opts || {};
    if (!bimiData) {
        return false;
    }

    let selector = bimiData?.status?.header?.selector;
    let d = bimiData?.status?.header?.d;

    let promises = [];

    let maxLogoSize = getSizeOption(opts.maxLogoSize, MAX_LOGO_SIZE);
    let maxEvidenceSize = getSizeOption(opts.maxEvidenceSize, MAX_EVIDENCE_SIZE);

    promises.push(downloadPromise(bimiData.location, bimiData.locationPath, maxLogoSize, opts));
    promises.push(downloadPromise(bimiData.authority, bimiData.authorityPath, maxEvidenceSize, opts));

    if (!promises.length) {
        return false;
    }

    let [{ reason: locationError, value: locationValue, status: locationStatus }, { reason: authorityError, value: authorityValue, status: authorityStatus }] =
        await Promise.allSettled(promises);

    let result = {};
    if (locationValue || locationError) {
        result.location = {
            url: bimiData.location,
            success: locationStatus === 'fulfilled'
        };

        if (locationError) {
            let err = locationError;
            result.location.error = { message: err.message };
            if (err.redirect) {
                result.location.error.redirect = err.redirect;
            }
            if (err.code) {
                result.location.error.code = err.code;
            }
        }

        if (result.location.success) {
            // 7.6: the Indicator is validated whether or not an evidence document vouches for it
            try {
                let svg = getIndicatorSvg(locationValue, maxLogoSize);
                validateSvg(svg);
                result.location.logoFile = svg.toString('base64');
            } catch (err) {
                result.location.success = false;
                if (err.code === 'FILE_TOO_LARGE') {
                    // an SVGZ file that is too large when uncompressed
                    result.location.error = { message: err.message, code: err.code };
                } else {
                    result.location.error = {
                        message: 'Logo SVG validation failed',
                        details: Object.assign({ message: err.message }, err.details ? { details: err.details } : {}, err.code ? { code: err.code } : {}),
                        code: 'SVG_VALIDATION_FAILED'
                    };
                }
            }
        }
    }

    if (authorityValue || authorityError) {
        result.authority = {
            url: bimiData.authority,
            success: authorityStatus === 'fulfilled'
        };

        if (authorityError) {
            let err = authorityError;
            result.authority.error = { message: err.message };
            if (err.redirect) {
                result.authority.error.redirect = err.redirect;
            }
            if (err.code) {
                result.authority.error.code = err.code;
            }
        }

        if (authorityValue) {
            try {
                let vmcData = await vmc(authorityValue, opts);

                if (!vmcData.logoFile) {
                    let error = new Error('VMC does not contain a log file');
                    error.code = 'MISSING_VMC_LOGO';
                    throw error;
                }

                if (vmcData?.mediaType?.toLowerCase() !== 'image/svg+xml') {
                    let error = new Error('Invalid media type for the logo file');
                    error.details = {
                        mediaType: vmcData.mediaType
                    };
                    error.code = 'INVALID_MEDIATYPE';
                    throw error;
                }

                if (!vmcData.validHash) {
                    let error = new Error('VMC hash does not match logo file');
                    error.details = {
                        hashAlgo: vmcData.hashAlgo,
                        hashValue: vmcData.hashValue,
                        logoFile: vmcData.logoFile
                    };
                    error.code = 'INVALID_LOGO_HASH';
                    throw error;
                }

                // throws on invalid logo file
                try {
                    validateSvg(Buffer.from(vmcData.logoFile, 'base64'));
                } catch (err) {
                    let error = new Error('VMC logo SVG validation failed');
                    error.details = Object.assign(
                        {
                            message: err.message
                        },
                        error.details || {},
                        err.code ? { code: err.code } : {}
                    );
                    error.code = 'SVG_VALIDATION_FAILED';
                    throw error;
                }

                if (d) {
                    // validate domain
                    let selectorSet = [];
                    let domainSet = [];
                    vmcData?.certificate?.subjectAltName?.map(formatDomain)?.forEach(domain => {
                        if (/\b_bimi\./.test(domain)) {
                            selectorSet.push(domain);
                        } else {
                            domainSet.push(domain);
                        }
                    });

                    let domainVerified = false;

                    if (selector && selectorSet.includes(formatDomain(`${selector}._bimi.${d}`))) {
                        domainVerified = true;
                    } else {
                        let alignedDomain = getAlignment(d, domainSet, false);
                        if (alignedDomain) {
                            domainVerified = true;
                        }
                    }

                    if (!domainVerified) {
                        let error = new Error('Domain can not be verified');
                        error.details = {
                            subjectAltName: vmcData?.certificate?.subjectAltName,
                            selector,
                            d
                        };
                        error.code = 'VMC_DOMAIN_MISMATCH';
                        throw error;
                    } else {
                        result.authority.domainVerified = true;
                    }
                }

                result.authority.vmc = vmcData;
            } catch (err) {
                result.authority.success = false;
                result.authority.error = { message: err.message };
                if (err.details) {
                    result.authority.error.details = err.details;
                }
                if (err.code) {
                    result.authority.error.code = err.code;
                }
            }
        }

        if (result.location && result.location.success && result.authority.success) {
            try {
                if (result.location.success && result.authority.vmc.hashAlgo && result.authority.vmc.validHash) {
                    let hash = crypto.createHash(result.authority.vmc.hashAlgo).update(locationValue).digest('hex');
                    result.location.hashAlgo = result.authority.vmc.hashAlgo;
                    result.location.hashValue = hash;
                    result.authority.hashMatch = hash === result.authority.vmc.hashValue;
                }
            } catch (err) {
                result.authority.success = false;
                result.authority.error = { message: err.message };
                if (err.details) {
                    result.authority.error.details = err.details;
                }
                if (err.code) {
                    result.authority.error.code = err.code;
                }
            }
        }
    }

    // Generate headers when validation succeeds
    let canGenerateHeaders =
        result.location?.success && result.location?.logoFile && (!result.authority || (result.authority.success && result.authority.hashMatch !== false));

    if (canGenerateHeaders) {
        result.headers = {
            indicator: libmime.foldLines(`BIMI-Indicator: ${result.location.logoFile}`, 160),
            location: `BIMI-Location: v=BIMI1; l=${bimiData.location}`
        };

        // 5.4 and 7.11: the header is not added for an invalid value
        if (AVATAR_PREFERENCES.has(bimiData.preference)) {
            result.headers.preference = `BIMI-Logo-Preference: avp=${bimiData.preference}`;
        }
    }

    return result;
};

module.exports = { bimi: lookup, validateVMC };
