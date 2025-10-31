'use strict';

const { spfVerify } = require('./spf-verify');
const os = require('node:os');
const dns = require('node:dns');
const libmime = require('libmime');
const Joi = require('joi');
const domainSchema = Joi.string().domain({ allowUnicode: false, tlds: false });
const { formatAuthHeaderRow, escapeCommentValue } = require('../tools');

const MAX_RESOLVE_COUNT = 10;
const MAX_VOID_COUNT = 2;

const formatHeaders = result => {
    let header = `Received-SPF: ${result.status.result}${result.status.comment ? ` (${escapeCommentValue(result.status.comment)})` : ''} client-ip=${
        result['client-ip']
    };`;

    return libmime.foldLines(header, 160);
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
 * @param {Function} resolver - Base DNS resolver function
 * @param {String} domain - Domain to query
 * @param {Object} opts - Options object with clientIpType (4 or 6)
 * @returns {Promise<Array>} - Array of IP addresses matching client type
 * @throws {Error} - Throws on real DNS errors or when both A and AAAA are void
 */
let dualStackResolver = async (resolver, domain, opts) => {
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
 * @returns {Function} - Rate-limited resolver function with signature: (domain, type, opts) => Promise<Array>
 */
let limitedResolver = (resolver, maxResolveCount, maxVoidCount, ignoreFirst) => {
    let resolveCount = 0;
    let voidCount = 0;

    let subResolveCounts = {};
    let firstCounted = !ignoreFirst;

    maxResolveCount = maxResolveCount || MAX_RESOLVE_COUNT;
    maxVoidCount = maxVoidCount || MAX_VOID_COUNT;

    let resolverFunc = async (domain, type, opts) => {
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
            if (!/^([\x20-\x2D\x2f-\x7e]+\.)+[a-z]+[a-z\-0-9]*$/i.test(domain)) {
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
        try {
            // Use dual-stack resolver when:
            // 1. Query type is A or AAAA (address lookups)
            // 2. Client IP type is provided (4 for IPv4, 6 for IPv6)
            // This prevents single-stack hosts from being counted as void lookups
            if (opts?.clientIpType && (type === 'A' || type === 'AAAA')) {
                return await dualStackResolver(resolver, domain, opts);
            } else {
                // Standard single-query resolution for other record types (TXT, MX, PTR, etc.) and A if no client info provided.
                return await resolver(domain, type);
            }
        } catch (err) {
            switch (err.code) {
                case 'ENOTFOUND': // Domain does not exist
                case 'ENODATA': {
                    // Domain exists but has no records of this type
                    // Increment void lookup counter
                    voidCount++;
                    if (voidCount > maxVoidCount) {
                        err.spfResult = {
                            error: 'permerror',
                            text: 'Too many void DNS results'
                        };
                        throw err;
                    }
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

                default:
                    // Unknown error - propagate as-is
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
 *
 * @param {Object} opts
 * @param {String} opts.sender Email address
 * @param {String} opts.ip Client IP address
 * @param {String} opts.helo Client EHLO/HELO hostname
 * @param {String} [opts.mta] Hostname of the MTA or MX server that processes the message
 * @param {String} [opts.maxResolveCount=10] Maximum DNS lookups allowed
 * @param {String} [opts.maxVoidCount=2] Maximum empty DNS lookups allowed
 */
const verify = async opts => {
    let { sender, ip, helo, mta, maxResolveCount, maxVoidCount, resolver } = opts || {};

    mta = mta || os.hostname();

    sender = sender || `postmaster@${helo}`;

    // convert mapped IPv6 IP addresses to IPv4
    let mappingMatch = (ip || '').toString().match(/^[:A-F]+:((\d+\.){3}\d+)$/i);
    if (mappingMatch) {
        ip = mappingMatch[1];
    }

    let atPos = sender.indexOf('@');
    if (atPos < 0) {
        sender = `postmaster@${sender}`;
    } else if (atPos === 0) {
        sender = `postmaster${sender}`;
    }

    let domain = sender.split('@').pop().toLowerCase().trim() || '-';

    resolver = resolver || dns.promises.resolve;

    let status = {
        result: 'neutral',
        comment: false,
        // ptype properties
        smtp: {
            mailfrom: sender,
            helo
        }
    };

    let verifyResolver = limitedResolver(resolver, maxResolveCount, maxVoidCount, true);

    let result;
    try {
        let validation = domainSchema.validate(domain);
        if (validation.error) {
            let err = validation.error;
            err.spfResult = {
                error: 'none',
                text: `Invalid domain ${domain}`
            };
            throw err;
        }

        result = await spfVerify(domain, {
            sender,
            ip,
            mta,
            helo,

            // generate DNS handler
            resolver: verifyResolver,

            // allow to create sub resolvers
            createSubResolver: () => limitedResolver(resolver, maxResolveCount, maxVoidCount)
        });
    } catch (err) {
        if (err.spfResult) {
            result = err.spfResult;
        } else {
            result = {
                error: 'temperror',
                text: err.message
            };
        }
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

    if (result.rr) {
        response.rr = result.rr;
    }

    response.status = status;
    response.header = formatHeaders(response);
    response.info = formatAuthHeaderRow('spf', status);

    if (typeof response.status.comment === 'boolean') {
        delete response.status.comment;
    }

    if (result.lookups) {
        response.lookups = result.lookups;
    }

    return response;
};

module.exports = { spf: verify };
