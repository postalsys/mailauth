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

const spfVerify = async (domain, opts, depth) => {
    depth = depth || 0;
    if (depth > 10) {
        // Should it throw instead?
        return false;
    }

    opts = opts || {};
    if (!opts.ip || !net.isIP(opts.ip)) {
        return false;
    }

    let addr = ipaddr.parse(opts.ip);
    let senderDomain = (opts.sender || '').split('@').pop().toLowerCase().trim();

    let responses = await (opts.resolver || dns).resolveTxt(domain);
    let spfRecord;

    for (let row of responses) {
        row = row.join('');
        let parts = row.trim().split(/\s+/);
        if (parts[0].toLowerCase() === 'v=spf1') {
            spfRecord = parts.slice(1);
            break;
        }
    }

    if (!spfRecord) {
        // Should it throw?
        return false;
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
            let subResult = await spfVerify(redirect, opts, depth);
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
                        let sub = await spfVerify(redirect, opts, depth);
                        if (sub && sub.qualifier === '+') {
                            return { type, val, include: sub, qualifier };
                        }
                    } catch (err) {
                        // kind of ignore
                    }
                }
                break;

            case 'ip4':
            case 'ip6':
                {
                    if (matchIp(addr, val)) {
                        return { type, val, qualifier };
                    }
                }
                break;

            case 'a':
                {
                    let match = val.match(/\/\d+$/);
                    let cidr = match ? val.substr(match.index) : '';
                    let domain = match ? val.substr(0, match.index) : val;
                    domain = domain.toLowerCase().trim();
                    if (!domain) {
                        domain = senderDomain;
                    }
                    try {
                        domain = punycode.toASCII(domain);
                    } catch (err) {
                        // ignore punycode conversion errors
                    }

                    try {
                        let responses = await (opts.resolver || dns)[net.isIPv6(opts.ip) ? 'resolve6' : 'resolve4'](domain);
                        if (responses) {
                            for (let a of responses) {
                                if (matchIp(addr, a + cidr)) {
                                    return { type, val: domain, qualifier };
                                }
                            }
                        }
                    } catch (err) {
                        switch (err.code) {
                            case 'ENOTFOUND':
                                // Do nothing?
                                break;
                            default:
                                throw err;
                        }
                    }
                }
                break;

            case 'mx':
                {
                    let match = val.match(/\/\d+$/);
                    let cidr = match ? val.substr(match.index) : '';
                    let domain = match ? val.substr(0, match.index) : val;
                    domain = domain.toLowerCase().trim();
                    if (!domain) {
                        domain = senderDomain;
                    }
                    try {
                        domain = punycode.toASCII(domain);
                    } catch (err) {
                        // ignore punycode conversion errors
                    }

                    try {
                        let mxList = await (opts.resolver || dns).resolveMx(domain);
                        if (mxList) {
                            mxList = mxList.sort((a, b) => a.priority - b.priority);
                            for (let mx of mxList) {
                                if (mx.exchange) {
                                    try {
                                        let responses = await (opts.resolver || dns)[net.isIPv6(opts.ip) ? 'resolve6' : 'resolve4'](mx.exchange);
                                        if (responses) {
                                            for (let a of responses) {
                                                if (matchIp(addr, a + cidr)) {
                                                    return { type, val: mx.exchange, qualifier };
                                                }
                                            }
                                        }
                                    } catch (err) {
                                        switch (err.code) {
                                            case 'ENOTFOUND':
                                                // Do nothing?
                                                break;
                                            default:
                                                throw err;
                                        }
                                    }
                                }
                            }
                        }
                    } catch (err) {
                        switch (err.code) {
                            case 'ENOTFOUND':
                                // Do nothing?
                                break;
                            default:
                                throw err;
                        }
                    }
                }
                break;
        }
    }

    return false;
};

module.exports = { spfVerify };
