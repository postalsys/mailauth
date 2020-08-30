'use strict';

const punycode = require('punycode');
const net = require('net');
const macro = require('./macro');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

const matchIp = (addr, range) => {
    if (/\/\d+$/.test(range)) {
        // seems CIDR
        return addr.match(ipaddr.parseCIDR(range));
    } else {
        return addr.toNormalizedString() === ipaddr.parse(range).toNormalizedString();
    }
};

const parseCidrValue = (val, defaultValue) => {
    val = val || '';
    let domain;
    let cidr;
    let cidr4 = '';
    let cidr6 = '';

    let match = val.match(/\/\d+$/);

    cidr = match ? val.substr(match.index + 1) : '';
    domain = match ? val.substr(0, match.index) : val;
    domain = domain.toLowerCase().trim() || defaultValue;

    if (cidr) {
        // if cidr is "/12/34" then left for A, and right is for AAAA
        let cidrParts = cidr.split('/');
        cidr4 = cidrParts[0]; // first
        cidr6 = cidrParts.pop(); // last
    }

    return {
        domain,
        cidr4: cidr4 ? `/${cidr4}` : '',
        cidr6: cidr6 ? `/${cidr6}` : ''
    };
};

const spfVerify = async (domain, opts) => {
    opts = opts || {};
    if (!opts.ip || !net.isIP(opts.ip)) {
        return false;
    }

    try {
        domain = punycode.toASCII(domain);
    } catch (err) {
        // ignore punycode conversion errors
    }

    let addr = ipaddr.parse(opts.ip);

    let resolver = opts.resolver || dns.resolve;

    let responses = await resolver(domain, 'TXT');
    let spfRecord;

    for (let row of responses) {
        row = row.join('');
        let parts = row.trim().split(/\s+/);
        if (parts[0].toLowerCase() === 'v=spf1') {
            if (spfRecord) {
                // multiple records, return permerror
                let err = new Error('SPF failure');
                err.spfResult = { error: 'permerror', message: `multiple SPF records found for ${domain}` };
                throw err;
            }
            spfRecord = parts.slice(1);
            break;
        }
    }

    if (!spfRecord) {
        let err = new Error('SPF failure');
        err.spfResult = { error: 'none', message: `no SPF records found for ${domain}` };
        throw err;
    }

    for (let i = 0; i < spfRecord.length; i++) {
        let part = spfRecord[i];

        if (/^exp=/i.test(part)) {
            // ignore, not supported by this implementation
            continue;
        }

        if (/^redirect=/i.test(part)) {
            if (spfRecord.some(p => /^[?\-~+]?all$/i.test(p))) {
                // ignore redirect if "all" condition is set
                continue;
            }

            let redirect = macro(part.slice(part.indexOf('=') + 1), opts);
            let subResult = await spfVerify(redirect, opts);
            if (subResult) {
                return subResult;
            }
            continue;
        }

        let key = '';
        let val = '';
        let qualifier = '+'; // default is pass

        let splitterPos = part.indexOf(':');
        if (splitterPos >= 0) {
            key = part.substr(0, splitterPos);
            val = part.substr(splitterPos + 1);
        } else {
            let splitterPos = part.indexOf('/');
            if (splitterPos >= 0) {
                key = part.substr(0, splitterPos);
                val = part.substr(splitterPos); // keep the / for CIDR
            } else {
                key = part;
            }
        }

        if (/^[?\-~+]/.test(key)) {
            qualifier = key.charAt(0);
            key = key.substr(1);
        }

        let type = key.toLowerCase();
        switch (type) {
            case 'all':
                return { type, qualifier };

            case 'include':
                {
                    try {
                        let redirect = macro(val, opts);
                        let sub = await spfVerify(redirect, opts);
                        if (sub && sub.qualifier === '+') {
                            // ignore other valid responses
                            return { type, val, include: sub, qualifier };
                        }
                        if (sub && sub.error) {
                            return sub;
                        }
                    } catch (err) {
                        // kind of ignore
                        if (err.spfResult) {
                            return err.spfResult;
                        }
                    }
                }
                break;

            case 'ip4':
            case 'ip6':
                {
                    if (net.isIP(val)) {
                        let { domain: range, cidr4, cidr6 } = parseCidrValue(val);
                        let cidr = net.isIPv6(opts.ip) ? cidr6 : cidr4;
                        if (matchIp(addr, range + cidr)) {
                            return { type, val, qualifier };
                        }
                    }
                }
                break;

            case 'a':
                {
                    let { domain: a, cidr4, cidr6 } = parseCidrValue(val, domain);
                    let cidr = net.isIPv6(opts.ip) ? cidr6 : cidr4;

                    try {
                        a = punycode.toASCII(a);
                    } catch (err) {
                        // ignore punycode conversion errors
                    }

                    let responses = await resolver(a, net.isIPv6(opts.ip) ? 'AAAA' : 'A');
                    if (responses) {
                        for (let ip of responses) {
                            if (matchIp(addr, ip + cidr)) {
                                return { type, val: domain, qualifier };
                            }
                        }
                    }
                }
                break;

            case 'mx':
                {
                    let { domain: mxDomain, cidr4, cidr6 } = parseCidrValue(val, domain);
                    let cidr = net.isIPv6(opts.ip) ? cidr6 : cidr4;

                    try {
                        mxDomain = punycode.toASCII(mxDomain);
                    } catch (err) {
                        // ignore punycode conversion errors
                    }

                    let mxList = await resolver(mxDomain, 'MX');
                    if (mxList) {
                        mxList = mxList.sort((a, b) => a.priority - b.priority);
                        for (let mx of mxList) {
                            if (mx.exchange) {
                                let responses = await resolver(mx.exchange, net.isIPv6(opts.ip) ? 'AAAA' : 'A');
                                if (responses) {
                                    for (let a of responses) {
                                        if (matchIp(addr, a + cidr)) {
                                            return { type, val: mx.exchange, qualifier };
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                break;

            case 'exists':
                {
                    let existDomain = macro(val, opts);
                    try {
                        existDomain = punycode.toASCII(existDomain);
                    } catch (err) {
                        // ignore punycode conversion errors
                    }

                    let responses = await resolver(existDomain, 'A');
                    if (responses && responses.length) {
                        return { type, val: existDomain, qualifier };
                    }
                }
                break;

            case 'prt':
                // ignore, not supported
                break;
        }
    }

    return false;
};

module.exports = { spfVerify };
