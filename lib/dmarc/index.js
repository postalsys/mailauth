'use strict';

const dns = require('dns').promises;
const punycode = require('punycode');

const psl = require('psl');

const resolveTxt = async (domain, resolver) => {
    try {
        let txt = await resolver(`_dmarc.${domain}`, 'TXT');
        console.log(domain, txt);
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
        if (err.code === 'ENOTFOUND') {
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
            if (!txt) {
                return false;
            }
        }
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

    parsed.isOrgRecord = isOrgRecord;

    return parsed;
};

const dmarc = async opts => {
    let { fromAddress, /* spfDomains, dkimDomains,*/ resolver } = opts;

    resolver = resolver || dns.resolve;

    let atPos = fromAddress.indexOf('@');
    let domain = atPos >= 0 ? fromAddress.substr(atPos + 1) : fromAddress;

    domain = domain.toLowerCase().trim();

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        // ignore punycode conversion errors
    }

    let orgDomain = psl.get(domain);

    let dmarcRecord = await getDmarcRecord(domain, resolver);
    if (!dmarcRecord) {
        // nothing to do here
        return false;
    }

    // use "sp" if this is a subdomain of an org domain and "sp" is set, otherwise use "p"
    const policy = dmarcRecord.isOrgRecord && dmarcRecord.sp ? dmarcRecord.sp : dmarcRecord.p;

    console.log({ domain, orgDomain, dmarcRecord, policy });
};

module.exports = { dmarc };

dmarc({ fromAddress: 'andris@www.kreata.ee' });
