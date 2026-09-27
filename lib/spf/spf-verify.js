'use strict';

const net = require('net');
const macro = require('./macro');
const dns = require('node:dns').promises;
const { getPtrHostname, formatDomain, toALabel } = require('../tools');
const { parseIp, ipInNetwork, normalizeTargetName, isValidTargetName, parseMacroString, validateTerms } = require('./syntax');

const LIMIT_PTR_RESOLVE_RECORDS = 10;

// the lookup limit, the void lookup limit and the time limit end the evaluation, a DNS error
// in a PTR lookup only makes the "ptr" mechanism (or the %{p} macro) not match
const isFatalError = err => !!(err && ((err.spfResult && err.spfResult.error === 'permerror') || err.code === 'ESPFTIMELIMIT'));

// checks if a macro-string uses one of the given macro letters, "%%" is a literal percent sign
const usesMacro = (input, letters) =>
    (input || '')
        .toString()
        .replace(/%%/g, '')
        .split('%{')
        .slice(1)
        .some(part => letters.includes(part.charAt(0).toLowerCase()));

const permError = text => {
    let err = new Error('SPF failure');
    err.spfResult = { error: 'permerror', text };
    return err;
};

const matchIp = (addr, range) => {
    let prefix;
    let rangeMatch = range.match(/^(.*)\/(\d+)$/);
    if (rangeMatch) {
        // seems CIDR
        range = rangeMatch[1];
        prefix = Number(rangeMatch[2]);
    }

    let network = parseIp(range);
    if (!network) {
        throw new Error(`Invalid IP address ${range}`);
    }

    if (typeof prefix !== 'number') {
        prefix = network.kind() === 'ipv4' ? 32 : 128;
    }

    return ipInNetwork(addr, network, prefix);
};

const parseCidrValue = (val, defaultValue, type) => {
    val = val || '';
    let domain = '';
    let cidr4 = '';
    let cidr6 = '';
    let dualCidr = false;

    if (val) {
        let cidrMatch = val.match(/^(.*?)(\/\d+)?(\/\/\d+)?$/);
        if (!cidrMatch || /^\/0+[1-9]/.test(cidrMatch[2]) || /^\/\/0+[1-9]/.test(cidrMatch[3])) {
            throw permError(`invalid address definition: ${val}`);
        }
        domain = cidrMatch[1] || '';

        cidr4 = cidrMatch[2] ? Number(cidrMatch[2].substr(1)) : '';
        cidr6 = cidrMatch[3] ? Number(cidrMatch[3].substr(2)) : '';
        dualCidr = !!cidrMatch[3];

        if (type === 'ip6' && typeof cidr4 === 'number' && cidr6 === '') {
            // there is no dual cidr for IP addresses, a single prefix length of an ip6 term is
            // the IPv6 prefix length, including "/0"
            cidr6 = cidr4;
            cidr4 = '';
        }
    }

    // the domain-spec is not lower cased here, an uppercase macro letter means URL escaping
    domain = domain.trim() || defaultValue;

    if ((typeof cidr4 === 'number' && cidr4 > 32 && !net.isIPv6(domain)) || (typeof cidr6 === 'number' && cidr6 > 128)) {
        throw permError(`invalid cidr definition: ${val}`);
    }

    return {
        domain,
        cidr4: typeof cidr4 === 'number' ? `/${cidr4}` : '',
        cidr6: typeof cidr6 === 'number' ? `/${cidr6}` : '',
        dualCidr
    };
};

/**
 * Resolves the validated domain names of the client IP (RFC 7208 section 5.5). The PTR query
 * goes through the given resolver, so with the limited resolver every "ptr" term and every
 * %{p} expansion counts toward the DNS lookup limit (RFC 7208 section 4.6.4).
 *
 * @returns {Array} Validated names, empty if there are none or the PTR lookup failed
 */
const getValidatedNames = async (addr, resolver, subResolver) => {
    let ptrValues;
    try {
        ptrValues = await resolver(getPtrHostname(addr), 'PTR');
    } catch (err) {
        if (isFatalError(err)) {
            throw err;
        }
        // "If a DNS error occurs while doing the PTR RR lookup, then this mechanism fails to match."
        return [];
    }

    ptrValues = (Array.isArray(ptrValues) ? ptrValues : []).slice(0, LIMIT_PTR_RESOLVE_RECORDS);

    // resolve up to 10 PTR A/AAAA records
    // https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
    let results = await Promise.allSettled(ptrValues.map(ptrValue => subResolver(ptrValue, addr.kind() === 'ipv6' ? 'AAAA' : 'A')));

    let timeLimit = results.find(result => result.status === 'rejected' && result.reason && result.reason.code === 'ESPFTIMELIMIT');
    if (timeLimit) {
        throw timeLimit.reason;
    }

    let kind = addr.kind();
    let normalized = addr.toNormalizedString();

    let validated = [];
    for (let i = 0; i < results.length; i++) {
        let result = results[i];
        if (
            result.status === 'fulfilled' &&
            Array.isArray(result.value) &&
            result.value.some(val => {
                let parsed = parseIp(val);
                return parsed && parsed.kind() === kind && parsed.toNormalizedString() === normalized;
            })
        ) {
            validated.push(ptrValues[i]);
        }
    }

    return validated;
};

/**
 * Picks the %{p} value from the validated names (RFC 7208 section 7.3): the <domain> itself,
 * else a subdomain of it, else any validated name, else "unknown"
 */
const selectPtrName = (validatedNames, domain) => {
    let target = formatDomain(domain || '');
    let names = validatedNames.map(name => ({ name: name.toString().replace(/\.+$/, ''), formatted: formatDomain(name.toString()) }));

    let match =
        names.find(entry => entry.formatted === target) ||
        names.find(entry => target && entry.formatted.substr(-(target.length + 1)) === `.${target}`) ||
        names[0];

    return match ? match.name : 'unknown';
};

// Adds the sub resolver's lookup counts of a mx or ptr term to the main resolver's report
const reportSubQueries = (resolver, subResolver, type) => {
    if (typeof resolver.updateSubQueries === 'function' && typeof subResolver.getResolveCount === 'function') {
        resolver.updateSubQueries(type, subResolver.getResolveCount());
        resolver.updateSubQueries(`${type}:void`, subResolver.getVoidCount());
    }
};

const spfVerify = async (domain, opts) => {
    opts = opts || {};

    // the client IP is parsed once, include and redirect recursion reuse it through opts.addr
    let addr = opts.addr || (opts.ip ? parseIp(opts.ip) : null);
    if (!addr) {
        return false;
    }

    let strict = !!opts.strict;
    // shared across include and redirect recursion
    let ctx = opts.ctx || { warnings: new Set() };
    if (!opts.ctx || !opts.addr) {
        opts = Object.assign({}, opts, { ctx, addr });
    }

    domain = toALabel(domain);

    let isIPv6 = addr.kind() === 'ipv6';

    // %{d} must expand to the domain currently being evaluated, which changes on include/redirect recursion
    let macroValues = { sender: opts.sender, ip: opts.ip, addr, helo: opts.helo, mta: opts.mta, domain };

    let resolver = opts.resolver || dns.resolve;

    let createSubResolver = options => (typeof opts.createSubResolver === 'function' ? opts.createSubResolver(options) : resolver);

    // RFC 8616 section 4: a non-ASCII local-part can not be used in a DNS label
    let senderStr = (opts.sender || '').toString();
    let nonAsciiLocalPart = /[^\x00-\x7F]/.test(senderStr.substr(0, Math.max(senderStr.lastIndexOf('@'), 0)));

    // The macro values with %{p}, the validated domain name of the client IP (RFC 7208 section 7.3)
    let withPtr = async (ptrResolver, subResolver) =>
        Object.assign({}, macroValues, { p: selectPtrName(await getValidatedNames(addr, ptrResolver, subResolver), domain) });

    /**
     * Expands a domain-spec into a target name
     *
     * @param {String} spec domain-spec
     * @param {Object} [options]
     * @param {Boolean} [options.lowercase] If true, lower case the literal parts of the domain-spec
     * @param {Function} [options.ptrResolver] Resolver to use for the %{p} PTR lookup
     * @returns {Object} Either { name } or { skip: reason } when the term must not match
     */
    let expandTarget = async (spec, options) => {
        options = options || {};

        if (usesMacro(spec, 'sl')) {
            if (!options.explanation) {
                // the policy has explicit provisions for the local-part (RFC 8601 section 2.7.2)
                ctx.usedLocalPart = true;
            }
            if (nonAsciiLocalPart) {
                // RFC 8616 section 4: terms that include %{s} or %{l} do not match anything
                if (strict) {
                    return { skip: 'local-part' };
                }
                ctx.warnings.add('non-ascii-local-part');
            }
        }

        let values = usesMacro(spec, 'p')
            ? await withPtr(options.ptrResolver || resolver, options.ptrResolver || createSubResolver({ ignoreVoid: true }))
            : macroValues;

        if (options.lowercase) {
            // lower case the literal parts only, an uppercase macro letter means URL escaping
            spec = spec.replace(/%\{[^}]*\}|%[%_-]|[^%]+|%/g, part => (part.charAt(0) === '%' ? part : part.toLowerCase()));
        }

        let name = toALabel(macro(spec, values).replace(/\.$/, ''));

        // names longer than 253 characters are truncated from the left (RFC 7208 section 7.3)
        name = normalizeTargetName(name);

        if (strict && !isValidTargetName(name)) {
            return { skip: 'invalid', name };
        }

        return { name };
    };

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

    for (let row of responses || []) {
        row = [].concat(row || []).join('');

        let parts;
        // RFC 7208 section 4.5: the record begins with "v=spf1", terminated by SP or the end of the record
        let exactVersion = /^v=spf1(?: |$)/i.test(row);
        if (strict) {
            if (!exactVersion) {
                continue;
            }
            // terms = *( 1*SP ( directive / modifier ) ), record = version terms *SP
            parts = row.split(' ').filter(part => part);
        } else {
            parts = row.trim().split(/\s+/);
            if (parts[0].toLowerCase() !== 'v=spf1') {
                continue;
            }
            if (!exactVersion) {
                // selected only because leading whitespace was trimmed
                ctx.warnings.add('syntax-error');
            }
        }

        if (spfRecord) {
            // multiple records, return permerror
            throw permError(`multiple SPF records found for ${domain}`);
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

    if (!spfRecord) {
        let err = new Error('SPF failure');
        err.spfResult = { error: 'none', text: `no SPF records found for ${domain}` };
        throw err;
    }

    // RFC 7208 section 4.6: the syntax of the whole record is validated first
    let syntaxError = validateTerms(spfRecord);
    if (syntaxError) {
        if (strict) {
            throw permError(syntaxError);
        }
        // the default mode evaluates the record lazily, so errors after the matching term are ignored
        ctx.warnings.add('syntax-error');
    }

    // set if the result comes from a redirect, the explanation of this record is then not used
    let redirected = false;

    let getResult = async () => {
        // this check is only for passing test suite
        for (let i = spfRecord.length - 1; i >= 0; i--) {
            let part = spfRecord[i];
            if (/^[^:/]+=/.test(part)) {
                //modifier, not mechanism

                if (!/^[a-z](a-z0-9-_\.)*/i.test(part)) {
                    throw permError(`invalid modifier ${part}`);
                }

                let splitPos = part.indexOf('=');
                let modifier = part.substr(0, splitPos).toLowerCase();
                let rawValue = part.substr(splitPos + 1);

                if (!strict) {
                    // the default mode checks the expanded values up front
                    let value = macro(rawValue, macroValues)
                        // remove trailing dot
                        .replace(/\.$/, '');

                    if (!value && (modifier === 'redirect' || modifier === 'exp')) {
                        // an unknown modifier may have an empty value (RFC 7208 section 6)
                        throw permError(`Empty modifier value for ${modifier}`);
                    } else if (modifier === 'redirect' && !/^([\x21-\x2D\x2f-\x7e]+\.)+[a-z]+[a-z\-0-9]*$/i.test(value)) {
                        throw permError(`Invalid redirect target ${value}`);
                    }
                }

                spfRecord.splice(i, 1);
                spfRecord.push({ modifier, value: rawValue });
                continue;
            }

            let mechanism = part
                .split(/[:/=]/)
                .shift()
                .toLowerCase()
                .replace(/^[?\-~+]/, '');

            if (!['all', 'include', 'a', 'mx', 'ip4', 'ip6', 'exists', 'ptr'].includes(mechanism)) {
                throw permError(`Unknown mechanism ${mechanism}`);
            }
        }

        if (spfRecord.filter(p => p && p.modifier === 'redirect').length > 1) {
            // too many redirects
            throw permError(`more than 1 redirect found`);
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

                            let target = await expandTarget(value);
                            if (target.skip) {
                                // RFC 7208 section 6.1: a malformed target name is a permerror, not "none"
                                throw permError(`Invalid redirect target ${target.name || value}`);
                            }

                            try {
                                let subResult = await spfVerify(target.name, opts);
                                if (subResult) {
                                    redirected = true;
                                    return subResult;
                                }
                            } catch (err) {
                                if (err.spfResult && err.spfResult.error === 'none') {
                                    err.spfResult.error = 'permerror';
                                }
                                // DNS errors (without spfResult) end up as temperror
                                throw err;
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
                throw permError(`unexpected empty value`);
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
                        throw permError(`unexpected extension for all`);
                    }
                    return { type, qualifier };

                case 'include':
                    {
                        let sub;
                        try {
                            let target = await expandTarget(val);
                            if (target.skip === 'local-part') {
                                // does not match
                                break;
                            }
                            if (target.skip) {
                                // a malformed target name gives "none" (RFC 7208 section 4.3), that is permerror for include
                                throw permError(`Invalid include target ${target.name}`);
                            }
                            // the explanation of the included record is never used (RFC 7208 section 6.2)
                            sub = await spfVerify(target.name, Object.assign({}, opts, { inInclude: true }));
                        } catch (err) {
                            if (err.spfResult) {
                                if (err.spfResult.error === 'none') {
                                    err.spfResult.error = 'permerror';
                                }
                                return err.spfResult;
                            }
                            // any other DNS error: "return temperror" (RFC 7208 section 5.2)
                            throw err;
                        }
                        if (sub && sub.qualifier === '+') {
                            // ignore other valid responses
                            return { type, val, include: sub, qualifier };
                        }
                        if (sub && sub.error) {
                            return sub;
                        }
                    }
                    break;

                case 'ip4':
                case 'ip6':
                    {
                        let res = strict ? matchIpTermStrict(type, val, addr) : matchIpTermLax(type, val, addr, opts.ip);
                        if (res) {
                            return { type, val, qualifier };
                        }
                    }
                    break;

                case 'a':
                    {
                        let { domain: a, cidr4, cidr6 } = parseCidrValue(val, domain, type);
                        let cidr = isIPv6 ? cidr6 : cidr4;

                        let target = await expandTarget(a, { lowercase: true });
                        if (target.skip) {
                            break;
                        }

                        // Query A or AAAA based on client IP type, with dual-stack void optimization
                        // Pass clientIpType to enable smart void counting (see dualStackResolver in index.js)
                        let responses = await resolver(target.name, isIPv6 ? 'AAAA' : 'A', { clientIpType: isIPv6 ? 6 : 4 });
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
                        let cidr = isIPv6 ? cidr6 : cidr4;

                        let target = await expandTarget(mxDomain, { lowercase: true });
                        if (target.skip) {
                            break;
                        }

                        let mxList = await resolver(target.name, 'MX');
                        if (mxList) {
                            // MX mechanism uses a separate resolver with independent DNS lookup counter
                            // This prevents MX A/AAAA lookups from consuming the main query limit.
                            // The void limit counts terms, and the MX query of this term was not void,
                            // so address lookups of the MX hosts are not counted as void lookups
                            let subResolver = createSubResolver({ ignoreVoid: true });
                            try {
                                mxList = mxList.sort((a, b) => a.priority - b.priority);
                                for (let mx of mxList) {
                                    // a trailing dot is accepted, and a null MX (".") has no hosts
                                    let exchange = mx && mx.exchange ? mx.exchange.toString().replace(/\.$/, '') : '';
                                    if (exchange) {
                                        // Query A or AAAA for each MX host, with dual-stack void optimization
                                        // Pass clientIpType to enable smart void counting (see dualStackResolver in index.js)
                                        let responses = await subResolver(exchange, isIPv6 ? 'AAAA' : 'A', {
                                            clientIpType: isIPv6 ? 6 : 4
                                        });
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
                                reportSubQueries(resolver, subResolver, 'mx');
                            }
                        }
                    }
                    break;

                case 'exists':
                    {
                        let target = await expandTarget(val);
                        if (target.skip) {
                            break;
                        }

                        let responses = await resolver(target.name, 'A');
                        if (responses && responses.length) {
                            return { type, val: target.name, qualifier };
                        }
                    }
                    break;

                case 'ptr':
                    {
                        let { cidr4, cidr6 } = parseCidrValue(val, false, type);
                        if (cidr4 || cidr6) {
                            throw permError(`invalid domain-spec definition: ${val}`);
                        }

                        // bare "ptr" defaults to %{d}, the currently evaluated domain
                        let ptrDomain = domain;
                        if (val) {
                            let target = await expandTarget(val);
                            if (target.skip) {
                                break;
                            }
                            ptrDomain = target.name;
                        }
                        ptrDomain = formatDomain(ptrDomain);

                        // PTR name validation uses a resolver with a separate counter
                        let subResolver = createSubResolver({ ignoreVoid: true });

                        // Step 1 and 2. Resolve PTR hostnames and validate these by resolving their addresses.
                        // Every ptr term makes its own PTR query, so every ptr term counts toward the lookup limit
                        let validatedPtrRecords = await getValidatedNames(addr, resolver, subResolver);
                        reportSubQueries(resolver, subResolver, 'ptr');

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

    /**
     * Computes the explanation string (RFC 7208 section 6.2). Any problem means that there is no explanation.
     */
    let getExplanation = async spec => {
        let expResolver = opts.expResolver || resolver;
        try {
            let target = await expandTarget(spec, { explanation: true, ptrResolver: expResolver });
            if (target.skip || !target.name) {
                return false;
            }

            let records = await expResolver(target.name, 'TXT');
            if (!Array.isArray(records) || records.length !== 1) {
                return false;
            }

            let text = [].concat(records[0] || []).join('');
            // the explanation string is limited to US-ASCII
            if (!text || /[^\x20-\x7E]/.test(text)) {
                return false;
            }

            // explain-string = *( macro-string / SP ), throws on syntax errors
            parseMacroString(text, { explain: true });

            if (usesMacro(text, 'sl') && nonAsciiLocalPart && strict) {
                return false;
            }

            return macro(text, usesMacro(text, 'p') ? await withPtr(expResolver, expResolver) : macroValues);
        } catch (err) {
            return false;
        }
    };

    try {
        let res = await getResult();

        if (res && res.qualifier === '-' && !redirected && !opts.inInclude) {
            // a mechanism of this record matched with "-", so the explanation of this record is used
            let exp = spfRecord.find(p => p && typeof p === 'object' && p.modifier === 'exp');
            if (exp) {
                let explanation = await getExplanation(exp.value);
                if (explanation) {
                    res.explanation = explanation;
                }
            }
        }

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

// strict: the term has already passed the syntax validation (RFC 7208 section 5.6)
const matchIpTermStrict = (type, val, addr) => {
    let match = val.match(/^(.*?)(?:\/(\d+))?$/);
    let network = parseIp(match[1]);
    if (!network || network.kind() !== (type === 'ip4' ? 'ipv4' : 'ipv6')) {
        throw permError(`invalid IP address`);
    }
    let prefix = typeof match[2] === 'string' ? Number(match[2]) : type === 'ip4' ? 32 : 128;
    // an IPv4 client only matches ip4 terms, an IPv6 client only matches ip6 terms
    return ipInNetwork(addr, network, prefix);
};

// the default mode, keeps the historical handling of malformed ip4 and ip6 terms
const matchIpTermLax = (type, val, addr, clientIp) => {
    let { domain: range, cidr4, cidr6, dualCidr } = parseCidrValue(val, false, type);
    if (!range) {
        throw permError(`bare IP address`);
    }

    // an IPv4 address written in the IPv4-mapped IPv6 form
    let mappingMatch = range.match(/^[:A-F]+:((\d+\.){3}\d+)$/i);

    if (type === 'ip6') {
        if (net.isIPv6(range)) {
            if (dualCidr && mappingMatch) {
                throw permError(`invalid CIDR for IP`);
            }
            // an ip6 network is never converted to IPv4, and only IPv6 clients match it
            // (IPv4-mapped clients are converted to IPv4 before evaluation)
            return addr.kind() === 'ipv6' && matchIp(addr, range + cidr6);
        }
        if (net.isIPv4(range)) {
            if (cidr6) {
                throw permError(`invalid CIDR for IP`);
            }
            return false;
        }
        throw permError(`invalid IP address`);
    }

    if (mappingMatch) {
        range = mappingMatch[1];
    }

    if (!net.isIP(range)) {
        throw permError(`invalid IP address`);
    }

    // validate ipv4 range only, skip ipv6
    if (cidr6 && net.isIPv4(range)) {
        throw permError(`invalid CIDR for IP`);
    }

    if (net.isIP(range) !== net.isIP(clientIp) || !net.isIPv4(range)) {
        // nothing to do here
        return false;
    }

    return matchIp(addr, range + cidr4);
};

module.exports = { spfVerify };
