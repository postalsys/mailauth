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
    let domain = '';
    let cidr4 = '';
    let cidr6 = '';

    if (val) {
        let cidrMatch = val.match(/^(.*?)(\/\d+)?(\/\/\d+)?$/);
        if (!cidrMatch || /^\/0+[1-9]/.test(cidrMatch[2]) || /^\/\/0+[1-9]/.test(cidrMatch[3])) {
            let err = new Error('SPF failure');
            err.spfResult = { error: 'permerror', message: `invalid address definition: ${val}` };
            throw err;
        }
        domain = cidrMatch[1] || '';
        cidr4 = cidrMatch[2] ? Number(cidrMatch[2].substr(1)) : '';
        cidr6 = cidrMatch[3] ? Number(cidrMatch[3].substr(2)) : '';
    }

    domain = domain.toLowerCase().trim() || defaultValue;

    if ((typeof cidr4 === 'number' && cidr4 > 32 && !net.isIPv6(domain)) || (typeof cidr6 === 'number' && cidr6 > 128)) {
        let err = new Error('SPF failure');
        err.spfResult = { error: 'permerror', message: `invalid cidr definition: ${val}` };
        throw err;
    }

    return {
        domain,
        cidr4: typeof cidr4 === 'number' ? `/${cidr4}` : '',
        cidr6: typeof cidr6 === 'number' ? `/${cidr6}` : ''
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
        }
    }

    if (!spfRecord) {
        let err = new Error('SPF failure');
        err.spfResult = { error: 'none', message: `no SPF records found for ${domain}` };
        throw err;
    }

    // this check is only for passing test suite
    for (let i = spfRecord.length - 1; i >= 0; i--) {
        let part = spfRecord[i];
        if (/^[^:/]+=/.test(part)) {
            //modifier, not mechanism

            if (!/^[a-z](a-z0-9-_\.)*/i.test(part)) {
                let err = new Error('SPF failure');
                err.spfResult = { error: 'permerror', message: `invalid modifier ${part}` };
                throw err;
            }

            let splitPos = part.indexOf('=');
            let modifier = part.substr(0, splitPos).toLowerCase();
            let value = part.substr(splitPos + 1);

            value = macro(value, opts)
                // remove trailing dot
                .replace(/\.$/, '');

            if (!value) {
                let err = new Error('SPF failure');
                err.spfResult = { error: 'permerror', message: `Empty modifier value for ${modifier}` };
                throw err;
            } else if (modifier === 'redirect' && !/^([\x21-\x2D\x2f-\x7e]+\.)+[a-z]+[a-z\-0-9]*$/.test(value)) {
                let err = new Error('SPF failure');
                err.spfResult = { error: 'permerror', message: `Invalid redirect target ${value}` };
                throw err;
            }

            spfRecord.splice(i, 1);
            spfRecord.push({ modifier, value });
            continue;
        }

        let mechanism = part
            .split(/[:/=]/)
            .shift()
            .toLowerCase()
            .replace(/^[?\-~+]/, '');

        if (!['all', 'include', 'a', 'mx', 'ip4', 'ip6', 'exists', 'ptr'].includes(mechanism)) {
            let err = new Error('SPF failure');
            err.spfResult = { error: 'permerror', message: `Unknown mechanism ${mechanism}` };
            throw err;
        }
    }

    if (spfRecord.filter(p => p && p.modifier === 'redirect').length > 1) {
        // too many redirects
        let err = new Error('SPF failure');
        err.spfResult = { error: 'permerror', message: `more than 1 redirect found` };
        throw err;
    }

    for (let i = 0; i < spfRecord.length; i++) {
        let part = spfRecord[i];

        if (typeof part === 'object' && part.modifier) {
            let { modifier, value } = part;

            switch (modifier) {
                case 'redirect':
                    {
                        if (spfRecord.some(p => /^[?\-~+]?all$/i.test(p))) {
                            // ignore redirect if "all" condition is set
                            continue;
                        }

                        try {
                            let subResult = await spfVerify(value, opts);
                            if (subResult) {
                                return subResult;
                            }
                        } catch (err) {
                            // kind of ignore
                            if (err.spfResult) {
                                if (err.spfResult.error === 'none') {
                                    err.spfResult.error = 'permerror';
                                }
                                throw err;
                            }
                        }
                    }
                    break;

                case 'exp':
                default:
                // do nothing
            }

            continue;
        }

        let key = '';
        let val = '';
        let qualifier = '+'; // default is pass

        let splitterPos = part.indexOf(':');
        if (splitterPos === part.length - 1) {
            let err = new Error('SPF failure');
            err.spfResult = { error: 'permerror', message: `unexpected empty value` };
            throw err;
        }
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
                if (val) {
                    let err = new Error('SPF failure');
                    err.spfResult = { error: 'permerror', message: `unexpected extension for all` };
                    throw err;
                }
                return { type, qualifier };

            case 'include':
                {
                    try {
                        let redirect = macro(val, opts)
                            // remove trailing dot
                            .replace(/\.$/, '');
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
                            if (err.spfResult.error === 'none') {
                                err.spfResult.error = 'permerror';
                            }
                            return err.spfResult;
                        }
                    }
                }
                break;

            case 'ip4':
            case 'ip6':
                {
                    let { domain: range, cidr4, cidr6 } = parseCidrValue(val);
                    if (!range) {
                        let err = new Error('SPF failure');
                        err.spfResult = { error: 'permerror', message: `bare IP address` };
                        throw err;
                    }

                    let originalRange = range;
                    let mappingMatch = (range || '').toString().match(/^[:A-F]+:((\d+\.){3}\d+)$/i);
                    if (mappingMatch) {
                        range = mappingMatch[1];
                    }

                    if (net.isIP(range)) {
                        if (type === 'ip6' && net.isIPv6(opts.ip) && net.isIPv6(originalRange) && net.isIPv4(range) && cidr4 === '/0') {
                            // map all IPv6 addresses
                            return { type, val, qualifier };
                        }

                        // validate ipv4 range only, skip ipv6
                        if (cidr6 && net.isIPv4(range)) {
                            let err = new Error('SPF failure');
                            err.spfResult = { error: 'permerror', message: `invalid CIDR for IP` };
                            throw err;
                        }

                        if (net.isIP(range) !== net.isIP(opts.ip) || net.isIP(range) !== Number(type.charAt(2))) {
                            // nothing to do here
                            break;
                        }

                        let cidr = net.isIPv6(range) ? cidr6 : cidr4;
                        if (matchIp(addr, range + cidr)) {
                            return { type, val, qualifier };
                        }
                    } else {
                        let err = new Error('SPF failure');
                        err.spfResult = { error: 'permerror', message: `invalid IP address` };
                        throw err;
                    }
                }
                break;

            case 'a':
                {
                    let { domain: a, cidr4, cidr6 } = parseCidrValue(val, domain);
                    let cidr = net.isIPv6(opts.ip) ? cidr6 : cidr4;

                    a = macro(a, opts);

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

            case 'ptr':
                // ignore, not supported
                break;
        }
    }

    return false;
};

module.exports = { spfVerify };
