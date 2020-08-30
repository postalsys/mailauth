'use strict';

const { spfVerify } = require('./spf-verify');
const os = require('os');
const dns = require('dns');
const libmime = require('libmime');

const MAX_RESOLVE_COUNT = 50;

const formatHeaders = result => {
    let header = `Received-SPF: ${result.status}${result.info ? ` (${result.info})` : ''} client-ip=${result['client-ip']}; envelope-from="${
        result['envelope-from']
    }";`;

    return libmime.foldLines(header);
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

    let atPos = sender.indexOf('@');
    if (atPos < 0) {
        sender = `postmaster@${sender}`;
    } else if (atPos === 0) {
        sender = `postmaster${sender}`;
    }

    let domain = sender.split('@').pop().toLowerCase().trim();

    resolver = resolver || dns.promises.resolve;

    let resolveCount = 0;
    maxResolveCount = maxResolveCount || MAX_RESOLVE_COUNT;
    let limitedResolver = async (...args) => {
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
            let result = await resolver(...args);
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

    let result;
    try {
        result = await spfVerify(domain, { sender, ip, mta, helo, resolver: limitedResolver });
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

    let response = { 'client-ip': ip };
    if (helo) {
        response.helo = helo;
    }
    if (sender) {
        response['envelope-from'] = sender;
    }

    result = result || {};
    switch (result.qualifier || result.error) {
        // qualifiers
        case '+':
            response.status = 'pass';
            response.info = `${mta}: domain of ${sender} designates ${ip} as permitted sender`;
            break;

        case '~':
            response.status = 'softfail';
            response.info = `${mta}: domain of transitioning ${sender} does not designate ${ip} as permitted sender`;
            break;

        case '-':
            response.status = 'fail';
            response.info = `${mta}: domain of ${sender} does not designate ${ip} as permitted sender`;
            break;

        case '?':
            response.status = 'neutral';
            response.info = `${mta}: ${ip} is neither permitted nor denied by domain of ${sender}`;
            break;

        // errors
        case 'none':
            response.status = 'none';
            response.info = `${mta}: ${domain} does not designate permitted sender hosts`;
            break;

        case 'permerror':
            response.status = 'permerror';
            response.info = `${mta}: permanent error in processing during lookup of ${sender}${result.text ? `: ${result.text}` : ''}`;
            break;

        case 'temperror':
        default:
            response.status = 'temperror';
            response.info = `${mta}: error in processing during lookup of ${sender}${result.text ? `: ${result.text}` : ''}`;
            break;
    }

    response.header = formatHeaders(response) + '\r\n';
    return response;
};

module.exports = { spf: verify };
