'use strict';

const dns = require('node:dns').promises;
const tldts = require('tldts');
const { TLDTS_OPTS } = require('../tools');

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
    resolver = resolver || dns.resolve;

    let txt = await resolveTxt(domain, resolver);
    let isOrgRecord = false;

    if (!txt) {
        let orgDomain = tldts.getDomain(domain, TLDTS_OPTS);
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

module.exports = getDmarcRecord;
