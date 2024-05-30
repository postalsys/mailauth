'use strict';

const punycode = require('punycode.js');
const net = require('net');
const macro = require('./macro');
const dns = require('node:dns').promises;
const ipaddr = require('ipaddr.js');
const { getPtrHostname, formatDomain } = require('../tools');

const LIMIT_PTR_RESOLVE_RECORDS = 10;

const matchIp = (addr, range) => {
    if (/\/\d+$/.test(range)) {
        // seems CIDR
        return addr.match(ipaddr.parseCIDR(range));
    } else {
        return addr.toNormalizedString() === ipaddr.parse(range).toNormalizedString();
    }
};

const parseCidrValue = (val, defaultValue, type) => {
    val = val || '';
    let domain = '';
    let cidr4 = '';
    let cidr6 = '';

    if (val) {
        let cidrMatch = val.match(/^(.*?)(\/\d+)?(\/\/\d+)?$/);
        if (!cidrMatch || /^\/0+[1-9]/.test(cidrMatch[2]) || /^\/\/0+[1-9]/.test(cidrMatch[3])) {
            let err = new Error('SPF failure');
            err.spfResult = { error: 'permerror', text: `invalid address definition: ${val}` };
            throw err;
        }
        domain = cidrMatch[1] || '';

        cidr4 = cidrMatch[2] ? Number(cidrMatch[2].substr(1)) : '';
        cidr6 = cidrMatch[3] ? Number(cidrMatch[3].substr(2)) : '';

        if (type === 'ip6' && cidr4 && !cidr6) {
            // there is no dual cidr for IP addresses
            cidr6 = cidr4;
            cidr4 = '';
        }
    }

    domain = domain.toLowerCase().trim() || defaultValue;

    if ((typeof cidr4 === 'number' && cidr4 > 32 && !net.isIPv6(domain)) || (typeof cidr6 === 'number' && cidr6 > 128)) {
        let err = new Error('SPF failure');
        err.spfResult = { error: 'permerror', text: `invalid cidr definition: ${val}` };
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

    let responses;
    try {
        responses = await resolver(domain, 'TXT');
    } catch (err) {
        if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
            throw err;
        }
        responses = [];
    }

    let spfRecord;
    let spfRr;

    for (let row of responses) {
        row = row.join('');
        let parts = row.trim().split(/\s+/);

        if (parts[0].toLowerCase() === 'v=spf1') {
            if (spfRecord) {
                // multiple records, return permerror
                let err = new Error('SPF failure');
                err.spfResult = { error: 'permerror', text: `multiple SPF records found for ${domain}` };
                throw err;
            }
            spfRr = row;
            spfRecord = parts.slice(1);

            if (spfRr && /[^\x20-\x7E]/.test(spfRr)) {
                let err = new Error('Invalid characters in DNS response');
                err.spfResult = {
                    error: 'permerror',
                    text: 'DNS response includes invalid characters'
                };
                throw err;
            }
        }
    }

    if (!spfRecord) {
        let err = new Error('SPF failure');
        err.spfResult = { error: 'none', text: `no SPF records found for ${domain}` };
        throw err;
    }

    let getResult = async () => {
        // this check is only for passing test suite
        for (let i = spfRecord.length - 1; i >= 0; i--) {
            let part = spfRecord[i];
            if (/^[^:/]+=/.test(part)) {
                //modifier, not mechanism

                if (!/^[a-z](a-z0-9-_\.)*/i.test(part)) {
                    let err = new Error('SPF failure');
                    err.spfResult = { error: 'permerror', text: `invalid modifier ${part}` };
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
                    err.spfResult = { error: 'permerror', text: `Empty modifier value for ${modifier}` };
                    throw err;
                } else if (modifier === 'redirect' && !/^([\x21-\x2D\x2f-\x7e]+\.)+[a-z]+[a-z\-0-9]*$/.test(value)) {
                    let err = new Error('SPF failure');
                    err.spfResult = { error: 'permerror', text: `Invalid redirect target ${value}` };
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
                err.spfResult = { error: 'permerror', text: `Unknown mechanism ${mechanism}` };
                throw err;
            }
        }

        if (spfRecord.filter(p => p && p.modifier === 'redirect').length > 1) {
            // too many redirects
            let err = new Error('SPF failure');
            err.spfResult = { error: 'permerror', text: `more than 1 redirect found` };
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
                err.spfResult = { error: 'permerror', text: `unexpected empty value` };
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
                        err.spfResult = { error: 'permerror', text: `unexpected extension for all` };
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
                        let { domain: range, cidr4, cidr6 } = parseCidrValue(val, false, type);
                        if (!range) {
                            let err = new Error('SPF failure');
                            err.spfResult = { error: 'permerror', text: `bare IP address` };
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
                                err.spfResult = { error: 'permerror', text: `invalid CIDR for IP` };
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
                            err.spfResult = { error: 'permerror', text: `invalid IP address` };
                            throw err;
                        }
                    }
                    break;

                case 'a':
                    {
                        let { domain: a, cidr4, cidr6 } = parseCidrValue(val, domain, type);
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
                        let { domain: mxDomain, cidr4, cidr6 } = parseCidrValue(val, domain, type);
                        let cidr = net.isIPv6(opts.ip) ? cidr6 : cidr4;

                        try {
                            mxDomain = punycode.toASCII(mxDomain);
                        } catch (err) {
                            // ignore punycode conversion errors
                        }

                        let mxList = await resolver(mxDomain, 'MX');
                        if (mxList) {
                            // MX resolver has separate counter
                            let subResolver = typeof opts.createSubResolver === 'function' ? opts.createSubResolver() : resolver;
                            try {
                                mxList = mxList.sort((a, b) => a.priority - b.priority);
                                for (let mx of mxList) {
                                    if (mx.exchange) {
                                        let responses = await subResolver(mx.exchange, net.isIPv6(opts.ip) ? 'AAAA' : 'A');
                                        if (responses) {
                                            for (let a of responses) {
                                                if (matchIp(addr, a + cidr)) {
                                                    return { type, val: mx.exchange, qualifier };
                                                }
                                            }
                                        }
                                    }
                                }
                            } finally {
                                if (typeof resolver.updateSubQueries === 'function') {
                                    resolver.updateSubQueries('mx', subResolver.getResolveCount());
                                    resolver.updateSubQueries('mx:void', subResolver.getVoidCount());
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
                    {
                        let { cidr4, cidr6 } = parseCidrValue(val, false, type);
                        if (cidr4 || cidr6) {
                            let err = new Error('SPF failure');
                            err.spfResult = { error: 'permerror', text: `invalid domain-spec definition: ${val}` };
                            throw err;
                        }

                        let ptrDomain;
                        if (val) {
                            ptrDomain = macro(val, opts);
                        } else {
                            ptrDomain = macro('%{d}', opts);
                        }
                        ptrDomain = formatDomain(ptrDomain);

                        // Step 1. Resolve PTR hostnames
                        let ptrValues;
                        if (opts._resolvedPtr) {
                            ptrValues = opts._resolvedPtr;
                        } else {
                            let responses = await resolver(getPtrHostname(addr), 'PTR');
                            opts._resolvedPtr = ptrValues = responses && responses.length ? responses : [];
                        }

                        // PTR resolver has separate counter
                        let subResolver = typeof opts.createSubResolver === 'function' ? opts.createSubResolver() : resolver;

                        let resolvers = [];
                        for (let ptrValue of ptrValues) {
                            if (resolvers.length < LIMIT_PTR_RESOLVE_RECORDS) {
                                // resolve up to 10 PTR A/AAAA records
                                // https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
                                resolvers.push(subResolver(ptrValue, net.isIPv6(opts.ip) ? 'AAAA' : 'A'));
                            }
                        }

                        // Step 2. Validate PTR hostnames by reverse resolving these
                        let validatedPtrRecords = [];
                        let results = await Promise.allSettled(resolvers);

                        if (typeof resolver.updateSubQueries === 'function') {
                            resolver.updateSubQueries('ptr', subResolver.getResolveCount());
                            resolver.updateSubQueries('ptr:void', subResolver.getVoidCount());
                        }

                        for (let i = 0; i < results.length; i++) {
                            let result = results[i];
                            let ptrHostname = ptrValues[i];
                            if (
                                result.status === 'fulfilled' &&
                                Array.isArray(result.value) &&
                                result.value.map(val => ipaddr.parse(val).toNormalizedString()).includes(addr.toNormalizedString())
                            ) {
                                validatedPtrRecords.push(ptrHostname);
                            }
                        }

                        // Step 3. Check subdomain alignment
                        for (let ptrRecord of validatedPtrRecords) {
                            let formattedPtrRecord = formatDomain(ptrRecord);

                            if (formattedPtrRecord === ptrDomain || formattedPtrRecord.substr(-(ptrDomain.length + 1)) === `.${ptrDomain}`) {
                                return { type, val: ptrRecord, qualifier };
                            }
                        }
                    }
                    break;
            }
        }

        return false;
    };

    try {
        let res = await getResult();

        if (res && spfRr) {
            res.rr = spfRr;
        } else if (spfRr) {
            res = {
                // default is neutral
                qualifier: '?',
                rr: spfRr
            };
        }
        return res;
    } catch (err) {
        if (spfRr && err.spfResult) {
            err.spfResult.rr = spfRr;
        }
        throw err;
    }
};

module.exports = { spfVerify };
