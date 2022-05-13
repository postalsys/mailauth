'use strict';

const dns = require('dns').promises;
const punycode = require('punycode/');
const psl = require('psl');
const { formatAuthHeaderRow, getAlignment } = require('../tools');

const resolveTxt = async (domain, resolver) => {
    try {
        let txt = await resolver(`_dmarc.${domain}`, 'TXT');
        if (!txt || !txt.length) {
            return false;
        }

        txt = txt.map(row => row.join('').trim()).filter(row => /^v=DMARC1\b/i.test(row));

        if (txt.length !== 1) {
            //no records or multiple records yield in no policy
            return false;
        }

        return txt[0];
    } catch (err) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
            return false;
        }
        throw err;
    }
};

const getDmarcRecord = async (domain, resolver) => {
    let txt = await resolveTxt(domain, resolver);
    let isOrgRecord = false;

    if (!txt) {
        let orgDomain = psl.get(domain);
        if (orgDomain !== domain) {
            // try org domain as well
            txt = await resolveTxt(orgDomain, resolver);
            isOrgRecord = true;
        }
    }

    if (!txt) {
        return false;
    }

    let parsed = Object.fromEntries(
        txt
            .split(';')
            .map(e => e.trim())
            .filter(e => e)
            .map(e => {
                let splitPos = e.indexOf('=');
                if (splitPos < 0) {
                    return [e.toLowerCase().trim(), false];
                } else if (splitPos === 0) {
                    return [false, e];
                }
                let key = e.substr(0, splitPos).toLowerCase().trim();
                let val = e.substr(splitPos + 1);
                if (['pct', 'ri'].includes(key)) {
                    val = parseInt(val, 10) || 0;
                }
                return [key, val];
            })
    );

    parsed.rr = txt;
    parsed.isOrgRecord = isOrgRecord;

    return parsed;
};

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

    let orgDomain = psl.get(domain);

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
            spf: { result: spfAlignment, strict: dmarcRecord.aspf === 's' },
            dkim: { result: dkimAlignment, strict: dmarcRecord.adkim === 's' }
        }
    });
};

module.exports = verifyDmarc;
