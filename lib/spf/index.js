'use strict';

const { spfVerify } = require('./spf-verify');
const os = require('os');
const dns = require('dns');
const libmime = require('libmime');
const Joi = require('joi');
const domainSchema = Joi.string().domain({ allowUnicode: false, tlds: false });
const { formatAuthHeaderRow, escapeCommentValue } = require('../tools');

const MAX_RESOLVE_COUNT = 50;

const formatHeaders = result => {
    let header = `Received-SPF: ${result.status.result}${result.status.comment ? ` (${escapeCommentValue(result.status.comment)})` : ''} client-ip=${
        result['client-ip']
    };`;

    return libmime.foldLines(header);
};

// DNS resolver method
let limitedResolver = (resolver, maxResolveCount) => {
    let resolveCount = 0;
    maxResolveCount = maxResolveCount || MAX_RESOLVE_COUNT;

    return async (domain, type) => {
        // do not allow to make more that MAX_RESOLVE_COUNT DNS requests per SPF check
        resolveCount++;
        if (resolveCount > maxResolveCount) {
            let error = new Error('Too many DNS requests');
            error.spfResult = {
                error: 'permerror',
                text: 'Too many DNS requests'
            };
            throw error;
        }

        try {
            // domain check is pretty lax, mostly to pass the test suite
            if (!/^([\x20-\x2D\x2f-\x7e]+\.)+[a-z]+[a-z\-0-9]*$/.test(domain)) {
                throw new Error('Failed to validate domain');
            }
        } catch (err) {
            err.spfResult = {
                error: 'permerror',
                text: `Invalid domain ${domain}`
            };
            throw err;
        }

        try {
            let result = await resolver(domain, type);

            switch (type) {
                case 'TXT':
                    for (let row of result) {
                        if (/[^\x20-\x7E]/.test([].concat(row || []).join(''))) {
                            let err = new Error('Invalid characters in DNS response');
                            err.spfResult = {
                                error: 'permerror',
                                text: 'DNS response includes invalid characters'
                            };
                            throw err;
                        }
                    }
                    break;
            }

            return result;
        } catch (err) {
            switch (err.code) {
                case 'ENOTFOUND':
                    return [];

                case 'ETIMEOUT':
                    err.spfResult = {
                        error: 'temperror',
                        text: 'DNS timeout'
                    };
                    throw err;

                default:
                    throw err;
            }
        }
    };
};

/**
 *
 * @param {Object} opts
 * @param {String} opts.sender Email address
 * @param {String} opts.ip Client IP address
 * @param {String} [opts.mta] Hostname of the MTA or MX server that processes the message
 * @param {String} opts.helo Client EHLO/HELO hostname
 */
const verify = async opts => {
    let { sender, ip, mta, helo, resolver, maxResolveCount } = opts || {};

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

    let domain = sender.split('@').pop().toLowerCase().trim();

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
            resolver: limitedResolver(resolver, maxResolveCount)
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

    response.status = status;
    response.header = formatHeaders(response);
    response.info = formatAuthHeaderRow('spf', status);

    return response;
};

module.exports = { spf: verify };
