'use strict';

const dns = require('node:dns').promises;
const punycode = require('punycode.js');
const tldts = require('tldts');
const { formatAuthHeaderRow, getAlignment, TLDTS_OPTS } = require('../tools');
const getDmarcRecord = require('./get-dmarc-record');

const verifyDmarc = async opts => {
    let { headerFrom, spfDomains, dkimDomains, resolver, arcResult } = opts;

    resolver = resolver || dns.resolve;

    if (Array.isArray(headerFrom)) {
        if (headerFrom.length === 1) {
            headerFrom = headerFrom[0];
        } else {
            // invalid number of FROM addresses found
            return false;
        }
    }

    let atPos = headerFrom.indexOf('@');
    let domain = atPos >= 0 ? headerFrom.substr(atPos + 1) : headerFrom;

    domain = domain.toLowerCase().trim();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        // ignore punycode conversion errors
    }

    let formatResponse = response => {
        response.info = formatAuthHeaderRow('dmarc', response.status);

        if (typeof response.status.comment === 'boolean') {
            delete response.status.comment;
        }

        return response;
    };

    let orgDomain = tldts.getDomain(domain, TLDTS_OPTS);

    let status = {
        result: 'neutral',
        comment: false,
        // ptype properties
        header: {
            from: orgDomain || domain
        }
    };

    let dmarcRecord;
    try {
        dmarcRecord = await getDmarcRecord(domain, resolver);
    } catch (err) {
        // temperror?
        status.result = 'temperror';
        return formatResponse({ status, domain: orgDomain || domain, error: err.message });
    }

    if (!dmarcRecord) {
        // nothing to do here
        // none
        status.result = 'none';
        return formatResponse({ status, domain: orgDomain || domain });
    }

    status.header = status.header || {};
    status.header.d = domain.split('_dmarc.').pop();

    status.comment = []
        .concat(dmarcRecord.p ? `p=${dmarcRecord.p.toUpperCase()}` : [])
        .concat(dmarcRecord.sp ? `sp=${dmarcRecord.sp.toUpperCase()}` : [])
        .concat(arcResult?.status?.result ? `arc=${arcResult?.status?.result}` : [])
        .join(' ');

    // use "sp" if this is a subdomain of an org domain and "sp" is set, otherwise use "p"
    const policy = dmarcRecord.isOrgRecord && dmarcRecord.sp ? dmarcRecord.sp : dmarcRecord.p;

    const dkimAlignment = getAlignment(domain, dkimDomains, { strict: dmarcRecord.adkim === 's' });
    const spfAlignment = getAlignment(domain, spfDomains, { strict: dmarcRecord.aspf === 's' });

    if (dkimAlignment || spfAlignment) {
        // pass
        status.result = 'pass';
    } else {
        // fail
        status.result = 'fail';
    }

    return formatResponse({
        status,
        domain: orgDomain || domain,
        policy,
        p: dmarcRecord.p,
        sp: dmarcRecord.sp || dmarcRecord.p,
        pct: dmarcRecord.pct,
        rr: dmarcRecord.rr,

        alignment: {
            spf: { result: spfAlignment?.domain, strict: dmarcRecord.aspf === 's' },
            dkim: { result: dkimAlignment?.domain, strict: dmarcRecord.adkim === 's', underSized: dkimAlignment?.underSized }
        }
    });
};

module.exports = verifyDmarc;
