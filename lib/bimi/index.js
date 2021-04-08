'use strict';

const dns = require('dns');
const { formatAuthHeaderRow, parseDkimHeaders } = require('../tools');
const Joi = require('joi');
const httpsSchema = Joi.string().uri({
    scheme: ['https']
});

const lookup = async data => {
    let { dmarc, headers, resolver } = data;
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
        response.location = recordData?.parsed?.l?.value;
    }

    if (recordData?.parsed?.a?.value) {
        response.authority = recordData?.parsed?.a?.value;
    }

    response.info = formatAuthHeaderRow('bimi', response.status);
    return response;
};

module.exports = { bimi: lookup };
