'use strict';

const { Buffer } = require('node:buffer');
const punycode = require('punycode.js');
const dns = require('node:dns');
const parseDkimHeaders = require('./parse-dkim-headers');
const https = require('node:https');

const HTTP_REQUEST_TIMEOUT = 15 * 1000;

/**
 * Resolve MTA-STS policy ID
 * @param {String} address Either email address or a domain name
 * @param {Object} opts
 * @param {Function} [opts.resolver] Optional async DNS resolver function
 * @returns {String|Boolean} Either string ID or false if policy was not defined in DNS
 */
const resolvePolicy = async (address, opts) => {
    opts = opts || {};
    let { resolver } = opts;
    resolver = resolver || dns.promises.resolve;

    address = (address || '').toString();
    let atPos = address.indexOf('@');
    let domain = atPos < 0 ? address : atPos.substr(atPos + 1);
    if (/[\x7e-\xff]/.test(domain)) {
        // high bytes, probably U-label
        try {
            domain = punycode.toASCII(domain);
        } catch (err) {
            // ignore
        }
    }

    let record;
    try {
        let txt = await resolver(`_mta-sts.${domain}`, 'TXT');
        txt = (txt || []).map(row => row?.join('').trim()).filter(row => /^v=STSv1\b/i.test(row));
        if (txt.length > 1) {
            let err = new Error('');
            err.code = 'multi_sts_records';
            throw err;
        }
        if (txt.length === 1) {
            record = parseDkimHeaders(txt[0]);
        }
    } catch (err) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
            return false;
        }
        throw err;
    }
    if (!record || !/^STSv1$/i.test(record?.parsed?.v?.value) || !record?.parsed?.id?.value) {
        return false;
    }

    return record?.parsed?.id?.value;
};

/**
 * Parses a MTA-STS policy file
 * @param {Buffer|String} file MTA-STS policy
 * @returns {Object} parsed policy
 */
const parsePolicy = file => {
    let policy = {
        // default
        mode: 'none'
    };

    (file || '')
        .toString()
        .split(/\r?\n/)
        .map(l => {
            let colonPos = l.indexOf(':');
            if (colonPos < 0) {
                return false;
            }

            return {
                key: l.substr(0, colonPos).toLowerCase().trim(),
                value: l.substr(colonPos + 1).trim()
            };
        })
        .filter(l => l)
        .forEach(l => {
            switch (l.key) {
                case 'version':
                    policy[l.key] = l.value;
                    break;
                case 'mode':
                    policy[l.key] = l.value.toLowerCase();
                    break;
                case 'max_age':
                    policy.maxAge = Number(l.value);
                    break;
                case 'mx': {
                    if (!policy.mx) {
                        policy.mx = [];
                    }
                    let mx = l.value.toLowerCase();
                    if (!policy.mx.includes(mx)) {
                        policy.mx.push(mx);
                    }
                    break;
                }
            }
        });

    if (!/^STSv1$/.test(policy.version)) {
        let err = new Error('Invalid version field');
        err.code = 'invalid_sts_version';
        throw err;
    }

    if (!['testing', 'enforce', 'none'].includes(policy.mode)) {
        let err = new Error('Invalid mode field');
        err.code = 'invalid_sts_mode';
        throw err;
    }

    if (isNaN(policy.maxAge) || policy.maxAge < 0 || policy.maxAge > 31557600) {
        let err = new Error('Invalid max_age field');
        err.code = 'invalid_sts_max_age';
        throw err;
    }

    if (policy.mode !== 'none' && (!policy.mx || !policy.mx.length)) {
        let err = new Error('Missing mx field');
        err.code = 'invalid_sts_mx';
        throw err;
    }

    return policy;
};

/**
 * Validate mx hostname against MTA-STS policy
 * @param {String} mx MX hostname
 * @param {Object} policy Policy structure from `parsePolicy`
 * @returns {Boolean} true if validation succeeded
 */
const validateMx = (mx, policy) => {
    policy = policy || { mode: 'none' };
    if (policy.mode === 'none' || !policy.mode) {
        // nothing to check for
        return {
            valid: true,
            mode: policy.mode || 'none',
            testing: policy.mode === 'testing'
        };
    }

    mx = (mx || '').toString().trim().toLowerCase();

    if (/[\x7e-\xff]/.test(mx)) {
        // high bytes, probably U-label
        try {
            mx = punycode.toASCII(mx);
        } catch (err) {
            // ignore
        }
    }

    for (let allowed of policy.mx) {
        allowed = (allowed || '').toString().trim().toLowerCase();
        if (/^\*\./.test(allowed)) {
            // remove wildcard
            allowed = allowed.substr(1);
            if (mx.substr(-allowed.length) === allowed) {
                return {
                    valid: true,
                    mode: policy.mode || 'none',
                    match: allowed,
                    testing: policy.mode === 'testing'
                };
            }
        } else if (allowed === mx) {
            return {
                valid: true,
                mode: policy.mode || 'none',
                match: allowed,
                testing: policy.mode === 'testing'
            };
        }
    }

    // no match found
    return {
        valid: false,
        mode: policy.mode || 'none',
        testing: policy.mode === 'testing'
    };
};

/**
 * Fetches and parses MTA-STS policy file for a domain
 * @param {String} domain
 * @param {Object} opts
 * @param {Function} [opts.resolver] Optional async DNS resolver function
 * @returns {Object|Boolean} false if policy file was not found or structured policy
 */
const fetchPolicy = async (domain, opts) => {
    opts = opts || {};
    let { resolver } = opts;
    resolver = resolver || dns.promises.resolve;

    domain = (domain || '').toString().toLowerCase();
    if (/[\x7e-\xff]/.test(domain)) {
        // high bytes, probably U-label
        try {
            domain = punycode.toASCII(domain);
        } catch (err) {
            // ignore
        }
    }

    const servername = `mta-sts.${domain}`;
    const path = `/.well-known/mta-sts.txt`;

    let addr;
    try {
        addr = await resolver(servername, 'A');
    } catch (err) {
        if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
            throw err;
        }
    }
    if (!addr?.length) {
        try {
            addr = await resolver(servername, 'AAAA');
        } catch (err) {
            if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
                throw err;
            }
        }
    }

    if (!addr?.length) {
        return false;
    }

    const options = {
        protocol: 'https:',
        host: addr[0],
        headers: {
            host: servername
        },
        servername,
        port: 443,
        path,
        method: 'GET',
        rejectUnauthorized: true,

        timeout: HTTP_REQUEST_TIMEOUT
    };

    let data = await new Promise((resolve, reject) => {
        const req = https.request(options, res => {
            let chunks = [],
                chunklen = 0;
            res.on('readable', () => {
                let chunk;
                while ((chunk = res.read()) !== null) {
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
            });
            res.on('end', () => {
                let data = Buffer.concat(chunks, chunklen);
                if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
                    let err = new Error(`Invalid response code ${res.statusCode || '-'}`);
                    err.code = 'http_status_' + (res.statusCode || 'na');
                    return reject(err);
                }
                resolve(data);
            });
            res.on('error', err => reject(err));
        });

        req.on('timeout', () => {
            req.destroy(); // cancel request
            let error = new Error(`Request timeout for https://${servername}${path}`);
            error.code = 'HTTP_SOCKET_TIMEOUT';
            reject(error);
        });

        req.on('error', err => {
            reject(err);
        });
        req.end();
    });

    if (!data) {
        return false;
    }

    return parsePolicy(data, opts);
};

/**
 * Resolves and fetches MTA-STS policy for a domain name
 * @param {String} domain Domain name to fetch the policy for
 * @param {Object} [knownPolicy] currenlty known MTA-STS policy
 * @param {Object} [opts]
 * @param {Function} [opts.resolver] Optional async DNS resolver function
 * @returns {Object|Boolean} Policy information or false
 */
const getPolicy = async (domain, knownPolicy, opts) => {
    let policyId;
    try {
        policyId = await resolvePolicy(domain, opts);
    } catch (err) {
        return { policy: { id: false, mode: 'none', error: err }, status: 'errored' };
    }

    try {
        if (!policyId) {
            return { policy: { id: false, mode: 'none' }, status: 'not_found' };
        }

        if (knownPolicy && knownPolicy.id === policyId && !(knownPolicy?.expires && new Date(knownPolicy?.expires) > new Date())) {
            // no changes, not expired
            return {
                policy: Object.assign({}, knownPolicy, {
                    expires: new Date(Date.now() + knownPolicy.maxAge * 1000).toISOString()
                }),
                status: 'renewed'
            };
        }

        let policy = await fetchPolicy(domain, opts);
        if (!policy) {
            return { policy: { id: false, mode: 'none' }, status: 'not_found' };
        }

        return {
            policy: Object.assign({ id: policyId }, policy, {
                expires: new Date(Date.now() + policy.maxAge * 1000).toISOString()
            }),
            status: 'found'
        };
    } catch (err) {
        if (knownPolicy) {
            // re-use existing policy on error
            return {
                policy: Object.assign({ error: err }, knownPolicy),
                status: 'errored'
            };
        }

        // prevent loading the policy for the next 1 hour and default to "none"
        return {
            policy: {
                id: policyId,
                mode: 'none',
                expires: new Date(Date.now() + 1 * 3600 * 1000).toISOString(),
                error: err
            },
            status: 'errored'
        };
    }
};

module.exports = {
    resolvePolicy,
    fetchPolicy,
    parsePolicy,
    validateMx,
    getPolicy
};
