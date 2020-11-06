'use strict';

const { formatAuthHeaderRow, parseDkimHeaders } = require('../tools');

const lookup = async data => {
    const { dmarc, headers, resolver } = data;
    let headerRows = (headers && headers.parsed) || [];

    let response = { status: {} };

    if (dmarc?.status?.result !== 'pass') {
        response.status.result = 'skipped';
        response.status.comment = dmarc?.status?.result === 'none' ? 'DMARC not enabled' : 'message failed DMARC';
        response.info = formatAuthHeaderRow('bimi', response.status);
        return response;
    }

    if (!dmarc?.domain) {
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

    let selectors = Array.from(new Set([selector, 'default']));
    let record;
    for (let s of selectors) {
        let txt;
        let d = `${s}._bimi.${dmarc?.domain}`;
        try {
            txt = await resolver(d, 'TXT');
        } catch (err) {
            if (err.code === 'ENOTFOUND') {
                continue;
            }
            response.status.result = 'temperr';
            response.status.comment = `failed to resolve ${d}`;
            response.info = formatAuthHeaderRow('bimi', response.status);
            return response;
        }

        if (Array.isArray(txt?.[0])) {
            record = txt[0]?.join('').trim();
            selector = s;
            break;
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

    if (!recordData?.parsed?.l?.value) {
        response.status.result = 'fail';
        response.status.comment = 'missing link value in dns record';
        response.info = formatAuthHeaderRow('bimi', response.status);
        return response;
    }

    response.status.result = 'pass';
    response.status.header = {
        d: dmarc?.domain
    };
    response.status.selector = selector;
    response.link = recordData?.parsed?.l?.value;

    response.info = formatAuthHeaderRow('bimi', response.status);
    return response;
};

module.exports = { bimi: lookup };
