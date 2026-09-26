'use strict';

const { spfVerify } = require('./spf-verify');
const { parseIp, isValidTargetName } = require('./syntax');
const os = require('node:os');
const dns = require('node:dns');
const libmime = require('libmime');
const Joi = require('joi');
const domainSchema = Joi.string().domain({ allowUnicode: false, tlds: false });
const { formatAuthHeaderRow, escapeCommentValue, formatDotAtomOrQuoted, MAX_HEADER_VALUE_LENGTH, toALabel } = require('../tools');

const MAX_RESOLVE_COUNT = 10;
const MAX_VOID_COUNT = 2;

/**
 * Formats the Received-SPF header field (RFC 7208 section 9.1)
 */
const formatHeaders = (result, keys) => {
    let pairs = [];
    for (let key of ['client-ip', 'envelope-from', 'helo']) {
        if (keys[key]) {
            let value = formatDotAtomOrQuoted(keys[key]);
            // a value this long can not be folded and would take the line past the 998
            // character limit of RFC 5322 section 2.1.1, so the optional pair is left out
            if (Buffer.byteLength(value) <= MAX_HEADER_VALUE_LENGTH) {
                pairs.push(`${key}=${value};`);
            }
        }
    }

    let header = `Received-SPF: ${result.status.result}${result.status.comment ? ` (${escapeCommentValue(result.status.comment)})` : ''}${
        pairs.length ? ` ${pairs.join(' ')}` : ''
    }`;

    return libmime.foldLines(header, 160);
};

const timeLimitError = () => {
    let err = new Error('SPF evaluation time limit exceeded');
    err.code = 'ESPFTIMELIMIT';
    err.spfResult = {
        error: 'temperror',
        text: 'SPF evaluation time limit exceeded'
    };
    return err;
};

/**
 * Dual-stack DNS resolver for SPF A/AAAA mechanism queries
 *
 * When evaluating A or AAAA mechanisms, both record types should be considered
 * to determine if a lookup is "void" (empty). This prevents incorrectly counting
 * IPv4-only or IPv6-only hosts as void lookups.
 *
 * Behavior:
 * - Queries both A and AAAA records in parallel (optimization)
 * - Only counts as void if BOTH A and AAAA return ENOTFOUND/ENODATA
 * - Real errors (ETIMEOUT, EREFUSED) for the client's IP type are propagated
 * - Returns only the records matching the client's IP type (IPv4 → A, IPv6 → AAAA)
 *
 * Example: IPv6 client checking an IPv4-only host
 *   - A query returns: 192.0.2.1
 *   - AAAA query returns: ENODATA (empty)
 *   - Result: Returns empty AAAA array (no match), but does NOT count as void
 *
 * RFC 7208 section 4.6.4 counts the query for the client's address type only, so this is used
 * in the default mode only. `state.clientVoid` is set if that query alone was void.
 *
 * @param {Function} resolver - Base DNS resolver function
 * @param {String} domain - Domain to query
 * @param {Object} opts - Options object with clientIpType (4 or 6)
 * @param {Object} [state] - Updated with the clientVoid flag
 * @returns {Promise<Array>} - Array of IP addresses matching client type
 * @throws {Error} - Throws on real DNS errors or when both A and AAAA are void
 */
let dualStackResolver = async (resolver, domain, opts, state) => {
    const isIPv6 = opts.clientIpType === 6;

    // Query both A and AAAA records in parallel for efficiency
    const [aResult, aaaaResult] = await Promise.allSettled([resolver(domain, 'A'), resolver(domain, 'AAAA')]);

    // Extract successful records and error details
    const aRecords = aResult.status === 'fulfilled' ? aResult.value : [];
    const aError = aResult.status === 'rejected' ? aResult.reason : null;

    const aaaaRecords = aaaaResult.status === 'fulfilled' ? aaaaResult.value : [];
    const aaaaError = aaaaResult.status === 'rejected' ? aaaaResult.reason : null;

    // Classify errors: void (no records exist) vs real (DNS server error)
    // Void errors: ENOTFOUND (no such domain), ENODATA (domain exists but no records)
    const aIsVoid = aError && (aError.code === 'ENOTFOUND' || aError.code === 'ENODATA');
    const aaaaIsVoid = aaaaError && (aaaaError.code === 'ENOTFOUND' || aaaaError.code === 'ENODATA');

    // Propagate real DNS errors for the record type matching the client's IP family
    // IPv6 client: throw AAAA errors (except void), ignore A errors
    if (isIPv6 && aaaaError && !aaaaIsVoid) {
        throw aaaaError;
    }
    // IPv4 client: throw A errors (except void), ignore AAAA errors
    if (!isIPv6 && aError && !aIsVoid) {
        throw aError;
    }

    // Only throw void error if BOTH record types are void
    // This prevents single-stack hosts from being counted as void lookups
    if (aIsVoid && aaaaIsVoid) {
        // Prefer the error matching client IP type for better error messages
        let voidError = isIPv6 ? aaaaError || aError : aError || aaaaError;
        throw voidError;
    }

    if (state && (isIPv6 ? aaaaIsVoid : aIsVoid)) {
        // RFC 7208 would count this as a void lookup
        state.clientVoid = true;
    }

    // Return only the records matching the client's IP type
    // Empty arrays are valid (host exists but doesn't match client IP type)
    return isIPv6 ? aaaaRecords : aRecords;
};

/**
 * Creates a rate-limited DNS resolver with SPF-specific constraints
 *
 * SPF evaluation must enforce limits to prevent DoS:
 * - Maximum 10 DNS lookups per SPF check (mechanisms that trigger DNS: a, mx, ptr, exists, include, redirect)
 * - Maximum 2 "void" lookups (queries returning no records)
 * Mailauth allows to configure both if different limits are required.
 *
 * @param {Function} resolver - Base DNS resolver function (e.g., dns.promises.resolve)
 * @param {Number} maxResolveCount - Maximum DNS lookups allowed (default: 10)
 * @param {Number} maxVoidCount - Maximum void lookups allowed (default: 2)
 * @param {Boolean} ignoreFirst - If true, don't count the first DNS lookup (used for initial TXT record fetch)
 * @param {Object} [options]
 * @param {Boolean} [options.strict] - If true, follow RFC 7208 exactly (no dual-stack void optimization)
 * @param {Object} [options.ctx] - Shared evaluation state, lax acceptances are added to ctx.warnings
 * @param {Number} [options.deadline] - Timestamp after which no more queries are made
 * @returns {Function} - Rate-limited resolver function with signature: (domain, type, opts) => Promise<Array>
 */
let limitedResolver = (resolver, maxResolveCount, maxVoidCount, ignoreFirst, options) => {
    options = options || {};

    let resolveCount = 0;
    let voidCount = 0;
    // void lookups as RFC 7208 counts them, without the dual-stack optimization
    let rfcVoidCount = 0;

    let subResolveCounts = {};
    let firstCounted = !ignoreFirst;

    maxResolveCount = maxResolveCount || MAX_RESOLVE_COUNT;
    maxVoidCount = maxVoidCount || MAX_VOID_COUNT;

    let checkRfcVoidCount = () => {
        if (rfcVoidCount > maxVoidCount && options.ctx && options.ctx.warnings) {
            // strict mode would have returned permerror here
            options.ctx.warnings.add('void-lookup-limit');
        }
    };

    let resolverFunc = async (domain, type, opts) => {
        if (options.deadline && Date.now() >= options.deadline) {
            throw timeLimitError();
        }

        // Increment DNS lookup counter
        // Note: Dual-stack queries (A+AAAA) still count as 1 lookup
        if (firstCounted) {
            resolveCount++;
        } else {
            firstCounted = true;
        }

        // Enforce maximum DNS lookup limit
        if (resolveCount > maxResolveCount) {
            let error = new Error('Too many DNS requests');
            error.spfResult = {
                error: 'permerror',
                text: 'Too many DNS requests'
            };
            throw error;
        }

        // Validate domain name format before querying
        // This is a lenient check to pass test suites and prevent obvious invalid queries
        try {
            // strict mode also accepts every name that follows the domain-spec rules of RFC 7208
            if (!/^([\x20-\x2D\x2f-\x7e]+\.)+[a-z]+[a-z\-0-9]*$/i.test(domain) && !(options.strict && isValidTargetName(domain))) {
                throw new Error('Failed to validate domain');
            }
        } catch (err) {
            err.spfResult = {
                error: 'permerror',
                text: `Invalid domain ${domain}`
            };
            throw err;
        }

        // Execute DNS query with dual-stack optimization for A/AAAA queries
        let state = {};
        try {
            // Use dual-stack resolver when:
            // 1. Query type is A or AAAA (address lookups)
            // 2. Client IP type is provided (4 for IPv4, 6 for IPv6)
            // 3. Not in strict mode, RFC 7208 only looks at the query for the client's address type
            // This prevents single-stack hosts from being counted as void lookups
            let result;
            if (!options.strict && opts?.clientIpType && (type === 'A' || type === 'AAAA')) {
                result = await dualStackResolver(resolver, domain, opts, state);
            } else {
                // Standard single-query resolution for other record types (TXT, MX, PTR, etc.) and A if no client info provided.
                result = await resolver(domain, type);
            }

            if (state.clientVoid) {
                rfcVoidCount++;
                checkRfcVoidCount();
            }

            return result;
        } catch (err) {
            if (!err || typeof err !== 'object') {
                // a custom resolver rejected with something other than an error object
                let wrapped = new Error(`DNS error when resolving ${domain}: ${err}`);
                wrapped.spfResult = {
                    error: 'temperror',
                    text: wrapped.message
                };
                throw wrapped;
            }

            switch (err.code) {
                case 'ENOTFOUND': // Domain does not exist
                case 'ENODATA': {
                    // Domain exists but has no records of this type
                    // Increment void lookup counter
                    voidCount++;
                    rfcVoidCount++;
                    if (voidCount > maxVoidCount) {
                        err.spfResult = {
                            error: 'permerror',
                            text: 'Too many void DNS results'
                        };
                        throw err;
                    }
                    checkRfcVoidCount();
                    // Return empty array to continue SPF evaluation
                    return [];
                }

                case 'ETIMEOUT':
                    // DNS server timeout - temporary error
                    err.spfResult = {
                        error: 'temperror',
                        text: 'DNS timeout'
                    };
                    throw err;

                case 'EREFUSED':
                    // DNS server refused query - temporary error
                    err.spfResult = {
                        error: 'temperror',
                        text: `DNS request refused by server when resolving ${domain}`
                    };
                    throw err;

                case 'ESPFTIMELIMIT':
                    throw err;

                case 'EBADNAME':
                    // the resolver rejected the name (for example a label longer than 63 characters),
                    // handled like the names that fail the format check above
                    err.spfResult = {
                        error: 'permerror',
                        text: `Invalid domain ${domain}`
                    };
                    throw err;

                default:
                    // Any other DNS error (SERVFAIL, connection refused, bad response, ...) is a
                    // temporary error (RFC 7208 sections 4.4 and 5), also inside include and redirect
                    if (!err.spfResult) {
                        err.spfResult = {
                            error: 'temperror',
                            text: err.message
                        };
                    }
                    throw err;
            }
        }
    };

    resolverFunc.updateSubQueries = (type, count) => {
        if (!subResolveCounts[type]) {
            subResolveCounts[type] = count;
        } else {
            subResolveCounts[type] += count;
        }
    };

    resolverFunc.getResolveCount = () => resolveCount;
    resolverFunc.getResolveLimit = () => maxResolveCount;
    resolverFunc.getSubResolveCounts = () => subResolveCounts;
    resolverFunc.getVoidCount = () => voidCount;

    return resolverFunc;
};

/**
 * Wraps a DNS resolver so that each question is sent once per SPF evaluation. The lookup limits
 * are counted by limitedResolver before it calls this, so every query still counts. Nothing
 * mutable is handed out twice: limitedResolver writes spfResult onto the error it gets, and
 * the MX list is sorted in place, so every caller gets its own copy of the error or the list
 *
 * @param {Function} resolver Base DNS resolver
 * @returns {Function} Resolver with the same signature
 */
const memoizeResolver = resolver => {
    const answers = new Map();

    const copyError = err => {
        if (!err || typeof err !== 'object') {
            // not an error object, there is nothing on it to share
            return err;
        }
        let copy = Object.assign(new Error(err.message), err);
        copy.code = err.code;
        if (err.spfResult && typeof err.spfResult === 'object') {
            copy.spfResult = Object.assign({}, err.spfResult);
        }
        return copy;
    };

    return (name, type) => {
        let key = `${type}:${name}`;
        let answer = answers.get(key);
        if (!answer) {
            // a resolver that throws synchronously still does so, and is not cached
            answer = Promise.resolve(resolver(name, type));
            // failures are reported to the callers below, never as an unhandled rejection
            answer.catch(() => false);
            answers.set(key, answer);
        }
        return answer.then(
            value => (Array.isArray(value) ? value.slice() : value),
            err => {
                throw copyError(err);
            }
        );
    };
};

/**
 *
 * @param {Object} opts
 * @param {String} opts.sender Email address
 * @param {String} opts.ip Client IP address
 * @param {String} opts.helo Client EHLO/HELO hostname
 * @param {String} [opts.mta] Hostname of the MTA or MX server that processes the message
 * @param {String} [opts.maxResolveCount=10] Maximum DNS lookups allowed
 * @param {String} [opts.maxVoidCount=2] Maximum empty DNS lookups allowed
 * @param {Number} [opts.maxElapsedTime] Maximum time in milliseconds for the whole evaluation, temperror if exceeded (no limit by default)
 * @param {Boolean} [opts.strict=false] If true, follow RFC 7208 exactly instead of the lenient default
 */
const verify = async opts => {
    let { sender, ip, helo, mta, maxResolveCount, maxVoidCount, resolver, strict, maxElapsedTime } = opts || {};

    strict = !!strict;

    mta = mta || os.hostname();

    // a null reverse-path means that the HELO identity is checked (RFC 7208 section 2.4)
    let nullSender = !sender;

    sender = sender || `postmaster@${helo}`;

    // IPv4-mapped IPv6 addresses (::ffff:0:0/96, dotted or hex form) are IPv4 clients (RFC 7208 section 5),
    // no other IPv6 address is ever treated as IPv4
    let parsedIp = ip ? parseIp(ip) : null;
    if (parsedIp) {
        ip = ip.toString().trim();
    }
    if (parsedIp && parsedIp.kind() === 'ipv6' && parsedIp.isIPv4MappedAddress()) {
        parsedIp = parsedIp.toIPv4Address();
        ip = parsedIp.toString();
    }

    // the local-part may be a quoted string that contains "@", the domain follows the last "@"
    let atPos = sender.lastIndexOf('@');
    if (atPos < 0) {
        sender = `postmaster@${sender}`;
    } else if (atPos === 0) {
        sender = `postmaster${sender}`;
    }
    atPos = sender.lastIndexOf('@');

    let domain =
        sender
            .substr(atPos + 1)
            .toLowerCase()
            .trim() || '-';

    // RFC 8616 section 4: U-labels are converted to A-labels before SPF validation, this also
    // applies to the sender domain used in macro expansion
    let evalSender = sender;
    if (/[^\x00-\x7F]/.test(domain)) {
        domain = toALabel(domain);
        evalSender = `${sender.substr(0, atPos)}@${domain}`;
    }

    // one DNS query per question for the whole evaluation, includes and redirects included
    resolver = memoizeResolver(resolver || dns.promises.resolve);

    let status = {
        result: 'neutral',
        comment: false,
        // ptype properties
        smtp: {
            mailfrom: sender,
            helo
        }
    };

    // shared evaluation state
    let ctx = { warnings: new Set(), usedLocalPart: false };

    let deadline = typeof maxElapsedTime === 'number' && maxElapsedTime > 0 ? Date.now() + maxElapsedTime : false;
    let resolverOptions = { strict, ctx, deadline };

    let verifyResolver = limitedResolver(resolver, maxResolveCount, maxVoidCount, true, resolverOptions);

    // the explanation lookup is not counted toward the lookup limits (RFC 7208 section 4.6.4)
    let expResolver = async (name, type) => {
        if (deadline && Date.now() >= deadline) {
            throw timeLimitError();
        }
        return await resolver(name, type);
    };

    let result;
    let timer;
    try {
        if (!parsedIp) {
            // <ip> is a required argument of check_host() (RFC 7208 section 4.1)
            let err = new Error('Invalid client IP');
            err.spfResult = {
                error: 'temperror',
                text: 'missing or invalid client IP address'
            };
            throw err;
        }

        let validation = domainSchema.validate(domain);
        if (validation.error) {
            let err = validation.error;
            err.spfResult = {
                error: 'none',
                text: `Invalid domain ${domain}`
            };
            throw err;
        }

        let evaluation = spfVerify(domain, {
            sender: evalSender,
            ip,
            mta,
            helo,
            strict,
            ctx,
            expResolver,

            // generate DNS handler
            resolver: verifyResolver,

            // allow to create sub resolvers. Address lookups of MX and PTR names do not count as void lookups
            createSubResolver: subOptions =>
                limitedResolver(resolver, maxResolveCount, subOptions && subOptions.ignoreVoid ? Infinity : maxVoidCount, false, resolverOptions)
        });

        if (deadline) {
            // RFC 7208 section 4.6.4: a limit on the elapsed time, temperror if exceeded
            evaluation.catch(() => false);
            result = await Promise.race([
                evaluation,
                new Promise((resolve, reject) => {
                    timer = setTimeout(() => reject(timeLimitError()), Math.max(deadline - Date.now(), 0));
                })
            ]);
        } else {
            result = await evaluation;
        }
    } catch (err) {
        if (err.spfResult) {
            result = err.spfResult;
        } else {
            result = {
                error: 'temperror',
                text: err.message
            };
        }
    } finally {
        clearTimeout(timer);
    }

    if (result && typeof result === 'object') {
        result.lookups = {
            limit: verifyResolver.getResolveLimit(),
            count: verifyResolver.getResolveCount(),
            void: verifyResolver.getVoidCount(),
            subqueries: verifyResolver.getSubResolveCounts()
        };
    }

    let response = { domain, 'client-ip': ip };
    if (helo) {
        response.helo = helo;
    }
    if (sender) {
        response['envelope-from'] = sender;
    }

    result = result || {
        // default is neutral
        qualifier: '?'
    };

    switch (result.qualifier || result.error) {
        // qualifiers
        case '+':
            status.result = 'pass';
            status.comment = `${mta}: domain of ${sender} designates ${ip} as permitted sender`;
            break;

        case '~':
            status.result = 'softfail';
            status.comment = `${mta}: domain of transitioning ${sender} does not designate ${ip} as permitted sender`;
            break;

        case '-':
            status.result = 'fail';
            status.comment = `${mta}: domain of ${sender} does not designate ${ip} as permitted sender`;
            break;

        case '?':
            status.result = 'neutral';
            status.comment = `${mta}: ${ip} is neither permitted nor denied by domain of ${sender}`;
            break;

        // errors
        case 'none':
            status.result = 'none';
            status.comment = `${mta}: ${domain} does not designate permitted sender hosts`;
            break;

        case 'permerror':
            status.result = 'permerror';
            status.comment = `${mta}: permanent error in processing during lookup of ${sender}${result.text ? `: ${result.text}` : ''}`;
            break;

        case 'temperror':
        default:
            status.result = 'temperror';
            status.comment = `${mta}: error in processing during lookup of ${sender}${result.text ? `: ${result.text}` : ''}`;
            break;
    }

    if (strict) {
        // RFC 8601 section 2.7.2: only the identity that was checked is reported, and the
        // local-part only if the policy has provisions for it
        status.smtp = nullSender ? { helo } : { mailfrom: ctx.usedLocalPart ? sender : sender.substr(atPos + 1) };
    }

    if (result.rr) {
        response.rr = result.rr;
    }

    response.status = status;
    response.header = formatHeaders(response, {
        'client-ip': parsedIp ? ip : false,
        // RFC 7208 section 9.1: "envelope-from" if the "MAIL FROM" identity was checked
        'envelope-from': nullSender ? false : sender,
        helo
    });
    response.info = formatAuthHeaderRow('spf', status, { strict });

    if (typeof response.status.comment === 'boolean') {
        delete response.status.comment;
    }

    if (result.lookups) {
        response.lookups = result.lookups;
    }

    if (result.explanation && status.result === 'fail') {
        // explanation string published by the domain owner (RFC 7208 section 6.2), third party text
        response.explanation = result.explanation;
    }

    if (ctx.warnings.size && status.result !== 'permerror') {
        // the default mode accepted something that strict mode would have rejected
        response.warnings = Array.from(ctx.warnings);
    }

    return response;
};

module.exports = { spf: verify };
