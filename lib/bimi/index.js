'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const dns = require('node:dns');
const { formatAuthHeaderRow, parseDkimHeaders, formatDomain, getAlignment } = require('../tools');
const Joi = require('joi');
//const packageData = require('../../package.json');
const httpsSchema = Joi.string().uri({
    scheme: ['https']
});

const FETCH_TIMEOUT = 5 * 1000;

const { fetch: fetchCmd, Agent } = require('undici');
const fetchAgent = new Agent({
    connect: { timeout: FETCH_TIMEOUT }
});

const { vmc } = require('@postalsys/vmc');
const { validateSvg } = require('./validate-svg');

const lookup = async data => {
    let { dmarc, headers, resolver, bimiWithAlignedDkim } = data;
    let headerRows = (headers && headers.parsed) || [];

    resolver = resolver || dns.promises.resolve;

    if (!dmarc) {
        // DMARC check not performed
        return false;
    }

    let response = { status: { header: {} } };

    if (dmarc.status?.result !== 'pass') {
        response.status.result = 'skipped';
        response.status.comment = dmarc.status?.result === 'none' ? 'DMARC not enabled' : 'message failed DMARC';
        response.info = formatAuthHeaderRow('bimi', response.status);
        return response;
    }

    if (dmarc.policy === 'none' || (dmarc.policy === 'quarantine' && dmarc.pct && dmarc.pct < 100)) {
        response.status.result = 'skipped';
        response.status.comment = 'too lax DMARC policy';
        response.info = formatAuthHeaderRow('bimi', response.status);
        return response;
    }

    if (!dmarc.alignment?.dkim?.result && bimiWithAlignedDkim) {
        response.status.result = 'skipped';
        response.status.comment = 'Aligned DKIM signature required';
        response.info = formatAuthHeaderRow('bimi', response.status);
        return response;
    }

    if (dmarc.alignment?.dkim?.underSized) {
        response.status.result = 'skipped';
        response.status.comment = 'undersized DKIM signature';
        response.info = formatAuthHeaderRow('bimi', response.status);
        return response;
    }

    const authorDomain = dmarc.status?.header?.from;
    const orgDomain = dmarc.domain;

    if (!authorDomain || !orgDomain) {
        // should this even happen?
        response.status.result = 'skipped';
        response.status.comment = 'could not determine domain';
        response.info = formatAuthHeaderRow('bimi', response.status);
        return response;
    }

    let selector;

    let bimiSelectorHeader;
    for (let row of headerRows) {
        if (['bimi-selector'].includes(row.key)) {
            if (bimiSelectorHeader) {
                // already found one
                response.status.result = 'fail';
                response.status.comment = 'multiple BIMI-Selector headers';
                response.info = formatAuthHeaderRow('bimi', response.status);
                return response;
            }

            bimiSelectorHeader = parseDkimHeaders(row.line);
            if (bimiSelectorHeader?.parsed?.v?.value?.toLowerCase() !== 'bimi1') {
                response.status.result = 'fail';
                response.status.comment = 'missing bimi version in selector header';
                response.info = formatAuthHeaderRow('bimi', response.status);
                return response;
            }

            selector = bimiSelectorHeader?.parsed?.s?.value;
        }
    }

    selector = selector?.trim() || 'default';

    let bimiTags = [`${selector}._bimi.${authorDomain}`];
    if (selector !== 'default' || authorDomain !== orgDomain) {
        bimiTags.push(`default._bimi.${orgDomain}`);
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
            response.status.result = 'temperr';
            response.status.comment = `failed to resolve ${d}`;
            response.info = formatAuthHeaderRow('bimi', response.status);
            return response;
        }

        if (txt?.length === 1 && Array.isArray(txt?.[0])) {
            record = txt[0]?.join('').trim();
            response.status.header.selector = d.split('._bimi.').shift();
            response.status.header.d = d.split('._bimi.').pop();
            response.rr = record;
            break;
        } else if (txt) {
            response.status.result = 'temperr';
            response.status.comment = `invalid BIMI response for ${d}`;
            response.info = formatAuthHeaderRow('bimi', response.status);
            return response;
        }
    }

    if (!record) {
        response.status.result = 'none';
        response.info = formatAuthHeaderRow('bimi', response.status);
        return response;
    }

    let recordData = parseDkimHeaders(`DNS: TXT;${record}`);
    if (recordData?.parsed?.v?.value?.toLowerCase() !== 'bimi1') {
        response.status.result = 'fail';
        response.status.comment = 'missing bimi version in dns record';
        response.info = formatAuthHeaderRow('bimi', response.status);
        return response;
    }

    if (!recordData?.parsed?.l?.value && !recordData?.parsed?.a?.value) {
        response.status.result = 'fail';
        response.status.comment = 'missing location value in dns record';
        response.info = formatAuthHeaderRow('bimi', response.status);
        return response;
    }

    if (recordData?.parsed?.l?.value) {
        let locationValidation = httpsSchema.validate(recordData?.parsed?.l?.value);
        if (locationValidation.error) {
            response.status.result = 'fail';
            response.status.comment = 'invalid location value in dns record';
            response.info = formatAuthHeaderRow('bimi', response.status);
            return response;
        }
    }

    if (recordData?.parsed?.a?.value) {
        let authorityValidation = httpsSchema.validate(recordData?.parsed?.a?.value);
        if (authorityValidation.error) {
            response.status.result = 'fail';
            response.status.comment = 'invalid authority value in dns record';
            response.info = formatAuthHeaderRow('bimi', response.status);
            return response;
        }
    }

    response.status.result = 'pass';

    if (recordData?.parsed?.l?.value) {
        response.location = recordData.parsed.l.value;
    }

    if (recordData?.parsed?.a?.value) {
        response.authority = recordData.parsed.a.value;

        // Apple Mail requires additional policy header values in Authentication-Results header
        response.status.policy = { authority: 'none', 'authority-uri': recordData.parsed.a.value }; // VMC has not been actually checked here yet, so authority is none
    }

    response.info = formatAuthHeaderRow('bimi', response.status);
    return response;
};

const downloadPromise = async (url, cachedFile) => {
    if (cachedFile) {
        return cachedFile;
    }

    if (!url) {
        return false;
    }

    let res = await fetchCmd(url, {
        headers: {
            // Comment: AKAMAI does some strange UA based filtering that messes up the request
            // 'User-Agent': `mailauth/${packageData.version} (+${packageData.homepage}`
        },
        dispatcher: fetchAgent
    });

    if (!res.ok) {
        let error = new Error(`Request failed with status ${res.status}`);
        error.code = 'HTTP_REQUEST_FAILED';
        throw error;
    }

    const arrayBufferValue = await res.arrayBuffer();
    return Buffer.from(arrayBufferValue);
};

const validateVMC = async (bimiData, opts) => {
    opts = opts || {};
    if (!bimiData) {
        return false;
    }

    let selector = bimiData?.status?.header?.selector;
    let d = bimiData?.status?.header?.d;

    let promises = [];

    promises.push(downloadPromise(bimiData.location, bimiData.locationPath));
    promises.push(downloadPromise(bimiData.authority, bimiData.authorityPath));

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
            result.location.logoFile = locationValue.toString('base64');
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

    return result;
};

module.exports = { bimi: lookup, validateVMC };
