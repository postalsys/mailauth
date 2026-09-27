'use strict';

const { Buffer } = require('node:buffer');
const dns = require('node:dns');
const https = require('node:https');
const tls = require('node:tls');
const { X509Certificate } = require('node:crypto');
const { toALabel, createError } = require('./tools');

// socket idle timeout for the policy request
const HTTP_IDLE_TIMEOUT = 15 * 1000;
// overall time limit for the policy request, RFC 8461 3.3 suggests one minute
const HTTP_REQUEST_TIMEOUT = 60 * 1000;
// maximum accepted policy body size, RFC 8461 3.3 suggests 64 kilobytes
const MAX_POLICY_SIZE = 64 * 1024;
// how long to wait before retrying a failed policy fetch when there is no cached policy to fall back to
const ERROR_RETRY_DELAY = 1 * 3600 * 1000;
// maximum allowed max_age value
const MAX_AGE_LIMIT = 31557600;

// RFC 8461 3.1 sts-ext-name and 3.2 sts-policy-ext-name share one grammar:
// (ALPHA / DIGIT) 0*31(ALPHA / DIGIT / "_" / "-" / ".")
const EXT_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/;

// RFC 8461 3.1 TXT record syntax
const TXT_RECORD_PREFIX = /^v=STSv1[ \t]*;/;
const TXT_RECORD_PREFIX_LAX = /^v=STSv1[ \t]*;/i;
const TXT_ID = /^[A-Za-z0-9]{1,32}$/;
const TXT_EXT_VALUE = /^[\x21-\x3a\x3c\x3e-\x7e]+$/;

// RFC 8461 3.2 policy file syntax
const POLICY_MAX_AGE = /^[0-9]{1,10}$/;
// ["*."] Domain, where Domain is defined in RFC 5321 4.1.2
const POLICY_MX_PATTERN = /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/i;

/**
 * Normalizes a domain name or an email address into a lowercase A-label domain name without a trailing dot
 * @param {String} address Either email address or a domain name
 * @returns {String} domain name
 */
const normalizeDomain = address => {
    let domain = (address || '').toString().trim();
    let atPos = domain.lastIndexOf('@');
    if (atPos >= 0) {
        domain = domain.substr(atPos + 1);
    }
    domain = domain.trim().toLowerCase().replace(/\.$/, '');
    return toALabel(domain);
};

/**
 * Parses a MTA-STS TXT record according to the RFC 8461 3.1 ABNF
 * @param {String} record TXT record value (strings already concatenated)
 * @returns {String|Boolean} policy ID or false if the record is not syntactically valid
 */
const parseTxtRecordStrict = record => {
    let parts = record.split(';');
    if (parts.length < 2 || !/^v=STSv1[ \t]*$/.test(parts[0])) {
        return false;
    }

    let fields = [];
    for (let i = 1; i < parts.length; i++) {
        let isLast = i === parts.length - 1;
        // WSP around a delimiter belongs to the delimiter
        let field = parts[i].replace(/^[ \t]+/, '');
        if (!isLast) {
            field = field.replace(/[ \t]+$/, '');
        } else if (!field) {
            // optional trailing delimiter
            continue;
        }
        if (!field) {
            // empty field between two delimiters
            return false;
        }
        fields.push(field);
    }

    // if a field is duplicated, then the first entry wins and the others only need to be syntactically valid
    let id;
    for (let field of fields) {
        let eqPos = field.indexOf('=');
        if (eqPos < 1) {
            return false;
        }
        let name = field.substr(0, eqPos);
        let value = field.substr(eqPos + 1);
        if (name === 'id' && typeof id !== 'string') {
            if (!TXT_ID.test(value)) {
                return false;
            }
            id = value;
        } else if (!EXT_NAME.test(name) || !TXT_EXT_VALUE.test(value)) {
            return false;
        }
    }

    return typeof id === 'string' ? id : false;
};

/**
 * Parses a MTA-STS TXT record leniently: the version and field names are case-insensitive,
 * surrounding whitespace is ignored and any non-empty id value is accepted.
 * @param {String} record TXT record value (strings already concatenated)
 * @returns {String|Boolean} policy ID or false if the record does not contain an id
 */
const parseTxtRecordLax = record => {
    let parts = record.trim().split(';');
    if (parts.length < 2 || !/^v=STSv1$/i.test(parts[0].trim())) {
        return false;
    }

    for (let i = 1; i < parts.length; i++) {
        let field = parts[i].trim();
        let eqPos = field.indexOf('=');
        if (eqPos < 1) {
            continue;
        }
        let name = field.substr(0, eqPos).trim().toLowerCase();
        let value = field.substr(eqPos + 1).trim();
        if (name === 'id' && value) {
            // if a field is duplicated, then the first entry wins
            return value;
        }
    }

    return false;
};

/**
 * Resolves the MTA-STS policy ID for a domain
 * @param {String} domain Normalized domain name
 * @param {Object} opts
 * @param {Array} warnings Lax acceptance markers are added here
 * @returns {Object} `{ id }` or `{ id: false, reason }`
 */
const discoverPolicyId = async (domain, opts, warnings) => {
    const strict = !!opts.strict;
    const resolver = opts.resolver || dns.promises.resolve;

    let txt;
    try {
        txt = await resolver(`_mta-sts.${domain}`, 'TXT');
    } catch (err) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
            return { id: false, reason: 'sts_record_not_found' };
        }
        throw err;
    }

    // records that do not begin with "v=STSv1;" are discarded before checking for multiple records
    let records = (txt || [])
        .map(row => (Array.isArray(row) ? row.join('') : (row || '').toString()))
        .filter(record => (strict ? TXT_RECORD_PREFIX.test(record) : TXT_RECORD_PREFIX_LAX.test(record.trim())));

    if (records.length > 1) {
        throw createError('Multiple MTA-STS TXT records found', 'multi_sts_records');
    }

    if (!records.length) {
        return { id: false, reason: 'sts_record_not_found' };
    }

    let strictId = parseTxtRecordStrict(records[0]);
    if (strict) {
        return strictId ? { id: strictId } : { id: false, reason: 'invalid_sts_record' };
    }

    let laxId = parseTxtRecordLax(records[0]);
    if (!laxId) {
        return { id: false, reason: 'invalid_sts_record' };
    }
    if (laxId !== strictId) {
        warnings.push('txt-syntax');
    }
    return { id: laxId };
};

/**
 * Resolve MTA-STS policy ID
 * @param {String} address Either email address or a domain name
 * @param {Object} opts
 * @param {Function} [opts.resolver] Optional async DNS resolver function
 * @param {Boolean} [opts.strict=false] If true, then the TXT record must match the RFC 8461 syntax exactly
 * @returns {String|Boolean} Either string ID or false if policy was not defined in DNS
 */
const resolvePolicy = async (address, opts) => {
    opts = opts || {};
    let { id } = await discoverPolicyId(normalizeDomain(address), opts, []);
    return id;
};

/**
 * Parses a MTA-STS policy file
 * @param {Buffer|String} file MTA-STS policy
 * @param {Boolean} strict If true, then field names, mode and max_age values must match the RFC 8461 syntax exactly
 * @param {Array} warnings Lax acceptance markers are added here
 * @returns {Object} parsed policy
 */
const parsePolicyFile = (file, strict, warnings) => {
    // "mode" is listed first to keep the property order of the result object stable
    let policy = { mode: undefined };
    let seen = new Set();
    let laxSyntax = false;
    let invalidMx = false;

    for (let line of (file || '').toString().split(/\r?\n/)) {
        let colonPos = line.indexOf(':');
        if (colonPos < 0) {
            continue;
        }

        let key, value;
        if (strict) {
            key = line.substr(0, colonPos);
            if (!EXT_NAME.test(key)) {
                continue;
            }
            value = line.substr(colonPos + 1).replace(/^[ \t]+|[ \t]+$/g, '');
        } else {
            key = line.substr(0, colonPos).toLowerCase().trim();
            value = line.substr(colonPos + 1).trim();
            if (['version', 'mode', 'max_age', 'mx'].includes(key) && key !== line.substr(0, colonPos)) {
                laxSyntax = true;
            }
        }

        if (key !== 'mx') {
            if (seen.has(key)) {
                // if a non-repeated field is duplicated, then all entries except for the first are ignored
                continue;
            }
            seen.add(key);
        }

        switch (key) {
            case 'version':
                policy.version = value;
                break;
            case 'mode':
                policy.mode = strict ? value : value.toLowerCase();
                if (policy.mode !== value) {
                    laxSyntax = true;
                }
                break;
            case 'max_age':
                if (POLICY_MAX_AGE.test(value)) {
                    policy.maxAge = Number(value);
                } else if (strict) {
                    policy.maxAge = NaN;
                } else {
                    policy.maxAge = Number(value);
                    laxSyntax = true;
                }
                break;
            case 'mx': {
                if (!policy.mx) {
                    policy.mx = [];
                }
                if (!POLICY_MX_PATTERN.test(value)) {
                    if (strict) {
                        invalidMx = true;
                    } else {
                        laxSyntax = true;
                    }
                }
                let mx = value.toLowerCase();
                if (!policy.mx.includes(mx)) {
                    policy.mx.push(mx);
                }
                break;
            }
        }
    }

    if (!/^STSv1$/.test(policy.version)) {
        throw createError('Invalid version field', 'invalid_sts_version');
    }

    if (!['testing', 'enforce', 'none'].includes(policy.mode)) {
        throw createError(policy.mode === undefined ? 'Missing mode field' : 'Invalid mode field', 'invalid_sts_mode');
    }

    if (typeof policy.maxAge !== 'number' || isNaN(policy.maxAge) || policy.maxAge < 0 || policy.maxAge > MAX_AGE_LIMIT) {
        throw createError('Invalid max_age field', 'invalid_sts_max_age');
    }

    if (invalidMx) {
        throw createError('Invalid mx field', 'invalid_sts_mx');
    }

    if (policy.mode !== 'none' && (!policy.mx || !policy.mx.length)) {
        throw createError('Missing mx field', 'invalid_sts_mx');
    }

    if (laxSyntax && warnings) {
        warnings.push('policy-syntax');
    }

    return policy;
};

/**
 * Parses a MTA-STS policy file
 * @param {Buffer|String} file MTA-STS policy
 * @param {Object} [opts]
 * @param {Boolean} [opts.strict=false] If true, then the policy must match the RFC 8461 syntax exactly
 * @returns {Object} parsed policy
 */
const parsePolicy = (file, opts) => parsePolicyFile(file, !!opts?.strict, null);

/**
 * Validate mx hostname against MTA-STS policy
 * @param {String} mx MX hostname
 * @param {Object} policy Policy structure from `parsePolicy`
 * @param {Object} [_opts]
 * @param {Boolean} [_opts.strict=false] Accepted for API consistency, matching rules are the same in both modes
 * @returns {Object} validation result
 */
const validateMx = (mx, policy, _opts) => {
    policy = policy || { mode: 'none' };
    if (policy.mode === 'none' || !policy.mode) {
        // nothing to check for
        return {
            valid: true,
            mode: policy.mode || 'none',
            testing: policy.mode === 'testing'
        };
    }

    mx = toALabel((mx || '').toString().trim().toLowerCase().replace(/\.$/, ''));

    // a hostname never contains a wildcard character
    let patterns = mx && !mx.includes('*') && Array.isArray(policy.mx) ? policy.mx : [];

    for (let allowed of patterns) {
        allowed = (allowed || '').toString().trim().toLowerCase().replace(/\.$/, '');
        if (!allowed) {
            continue;
        }
        if (/^\*\./.test(allowed)) {
            // the wildcard matches exactly one complete left-most label
            let suffix = allowed.substr(1);
            let label = mx.substr(0, mx.length - suffix.length);
            if (mx.length > suffix.length && mx.substr(-suffix.length) === suffix && !label.includes('.')) {
                return {
                    valid: true,
                    mode: policy.mode,
                    match: suffix,
                    testing: policy.mode === 'testing'
                };
            }
        } else if (allowed === mx) {
            return {
                valid: true,
                mode: policy.mode,
                match: allowed,
                testing: policy.mode === 'testing'
            };
        }
    }

    // no match found
    return {
        valid: false,
        mode: policy.mode,
        testing: policy.mode === 'testing'
    };
};

/**
 * Checks the Policy Host certificate identity the way RFC 8461 3.3 requires: only DNS-ID
 * subjectAltName entries are used (no CN fallback) and a wildcard may only be the complete left-most label.
 * @param {String} hostname Policy Host name
 * @param {Object} cert Peer certificate object
 * @returns {Boolean} true if the certificate is valid for the hostname
 */
const checkPolicyHostIdentity = (hostname, cert) => {
    try {
        let x509 = new X509Certificate(cert.raw);
        return !!x509.checkHost(hostname, {
            subject: 'never',
            wildcards: true,
            partialWildcards: false,
            multiLabelWildcards: false,
            singleLabelSubdomains: false
        });
    } catch (err) {
        return false;
    }
};

/**
 * Fetches and parses MTA-STS policy file for a domain
 * @param {String} domain
 * @param {Object} opts
 * @param {Array} warnings Lax acceptance markers are added here
 * @returns {Object|Boolean} false if the policy host has no address or structured policy
 */
const fetchPolicyFile = async (domain, opts, warnings) => {
    const strict = !!opts.strict;
    const resolver = opts.resolver || dns.promises.resolve;
    const timeout = typeof opts.timeout === 'number' && opts.timeout > 0 ? opts.timeout : HTTP_REQUEST_TIMEOUT;
    const maxPolicySize = typeof opts.maxPolicySize === 'number' && opts.maxPolicySize > 0 ? opts.maxPolicySize : MAX_POLICY_SIZE;

    domain = normalizeDomain(domain);

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

    let fetchWarnings = [];

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
        checkServerIdentity: (hostname, cert) => {
            let err = tls.checkServerIdentity(hostname, cert);
            if (err) {
                return err;
            }
            if (!checkPolicyHostIdentity(hostname, cert)) {
                if (strict) {
                    err = createError(
                        `Certificate is not valid for ${hostname}: a DNS-ID subjectAltName must match and a wildcard must be the complete left-most label`,
                        'ERR_TLS_CERT_ALTNAME_INVALID',
                        { host: hostname, cert }
                    );
                    return err;
                }
                fetchWarnings.push('cert-identity');
            }
        },
        // use a fresh connection, so that a connection verified with other options is never reused
        agent: false,
        timeout: Math.min(HTTP_IDLE_TIMEOUT, timeout)
    };

    let data = await new Promise((resolve, reject) => {
        let finished = false;
        let req;
        let timer;

        const done = (err, data) => {
            if (finished) {
                return;
            }
            finished = true;
            clearTimeout(timer);
            if (err) {
                if (req) {
                    req.destroy();
                }
                return reject(err);
            }
            resolve(data);
        };

        const tooLarge = () => createError(`Policy file is larger than ${maxPolicySize} bytes`, 'policy_too_large');

        const handleResponse = res => {
            let statusCode = res.statusCode;
            if (statusCode !== 200) {
                if (strict || !statusCode || statusCode < 200 || statusCode >= 300) {
                    // only HTTP 200 is a valid policy response, redirects are not followed
                    return done(createError(`Invalid response code ${statusCode || '-'}`, 'http_status_' + (statusCode || 'na')));
                }
                fetchWarnings.push('http-status');
            }

            let mediaType = (res.headers['content-type'] || '').split(';').shift().trim().toLowerCase();
            if (mediaType !== 'text/plain') {
                if (strict) {
                    return done(createError(`Invalid Content-Type ${JSON.stringify(res.headers['content-type'] || '')}`, 'invalid_content_type'));
                }
                fetchWarnings.push('content-type');
            }

            if (Number(res.headers['content-length']) > maxPolicySize) {
                return done(tooLarge());
            }

            let chunks = [],
                chunklen = 0;
            res.on('data', chunk => {
                if (finished) {
                    return;
                }
                chunks.push(chunk);
                chunklen += chunk.length;
                if (chunklen > maxPolicySize) {
                    done(tooLarge());
                }
            });
            res.on('end', () => done(null, Buffer.concat(chunks, chunklen)));
            res.on('error', err => done(err));
            res.on('close', () => {
                if (!res.complete) {
                    done(createError(`Incomplete response for https://${servername}${path}`, 'http_incomplete_response'));
                }
            });
        };

        try {
            req = https.request(options, handleResponse);
        } catch (err) {
            return done(err);
        }

        req.on('timeout', () => {
            done(createError(`Request timeout for https://${servername}${path}`, 'HTTP_SOCKET_TIMEOUT'));
        });
        req.on('error', err => done(err));

        // overall time limit, the socket timeout only covers idle periods
        timer = setTimeout(() => {
            done(createError(`Request timeout for https://${servername}${path}`, 'HTTP_REQUEST_TIMEOUT'));
        }, timeout);

        req.end();
    });

    let policy = parsePolicyFile(data, strict, fetchWarnings);
    warnings.push(...fetchWarnings);
    return policy;
};

/**
 * Fetches and parses MTA-STS policy file for a domain
 * @param {String} domain
 * @param {Object} opts
 * @param {Function} [opts.resolver] Optional async DNS resolver function
 * @param {Boolean} [opts.strict=false] If true, then apply the RFC 8461 rules exactly
 * @param {Number} [opts.timeout=60000] Overall time limit for the HTTPS request in milliseconds
 * @param {Number} [opts.maxPolicySize=65536] Maximum size of the policy file in bytes
 * @returns {Object|Boolean} false if policy file was not found or structured policy
 */
const fetchPolicy = async (domain, opts) => fetchPolicyFile(domain, opts || {}, []);

/**
 * Checks if a cached policy exists and has not expired yet
 * @param {Object} knownPolicy
 * @returns {Boolean}
 */
const isPolicyValid = knownPolicy => {
    if (!knownPolicy || typeof knownPolicy !== 'object' || !knownPolicy.id || !knownPolicy.expires) {
        return false;
    }
    let expires = new Date(knownPolicy.expires).getTime();
    return !isNaN(expires) && expires > Date.now();
};

const formatResult = (policy, status, warnings) => {
    let result = { policy, status };
    if (warnings.length) {
        result.warnings = Array.from(new Set(warnings));
    }
    return result;
};

/**
 * Resolves and fetches MTA-STS policy for a domain name
 * @param {String} domain Domain name to fetch the policy for
 * @param {Object} [knownPolicy] currently known MTA-STS policy
 * @param {Object} [opts]
 * @param {Function} [opts.resolver] Optional async DNS resolver function
 * @param {Boolean} [opts.strict=false] If true, then apply the RFC 8461 rules exactly
 * @param {Number} [opts.timeout=60000] Overall time limit for the HTTPS request in milliseconds
 * @param {Number} [opts.maxPolicySize=65536] Maximum size of the policy file in bytes
 * @returns {Object} Policy information
 */
const getPolicy = async (domain, knownPolicy, opts) => {
    opts = opts || {};
    const strict = !!opts.strict;
    const warnings = [];

    domain = normalizeDomain(domain);

    // RFC 8461 3.3, 5.1: a valid (non-expired) cached policy must be applied if no live policy can be discovered or fetched
    const cacheValid = isPolicyValid(knownPolicy);
    const useCached = err => formatResult(Object.assign({}, knownPolicy, { error: err }), 'errored', warnings);

    let discovery;
    try {
        discovery = await discoverPolicyId(domain, opts, warnings);
    } catch (err) {
        if (cacheValid) {
            return useCached(err);
        }
        return formatResult({ id: false, mode: 'none', error: err }, 'errored', warnings);
    }

    const policyId = discovery.id;
    if (!policyId) {
        if (cacheValid) {
            return useCached(createError(`No usable MTA-STS TXT record found for ${domain}`, discovery.reason));
        }
        return formatResult({ id: false, mode: 'none' }, 'not_found', warnings);
    }

    if (cacheValid && knownPolicy.id === policyId) {
        // no changes, not expired, no need to fetch the policy file
        return formatResult(Object.assign({}, knownPolicy), 'renewed', warnings);
    }

    try {
        let policy = await fetchPolicyFile(domain, opts, warnings);
        if (!policy) {
            if (cacheValid) {
                return useCached(createError(`Policy host mta-sts.${domain} has no address records`, 'policy_host_not_found'));
            }
            return formatResult({ id: false, mode: 'none' }, 'not_found', warnings);
        }

        return formatResult(
            Object.assign({ id: policyId }, policy, {
                expires: new Date(Date.now() + policy.maxAge * 1000).toISOString()
            }),
            'found',
            warnings
        );
    } catch (err) {
        // A valid cached "none" policy (or an earlier retry placeholder) enforces nothing, so it is
        // replaced with a retry placeholder for the new policy ID below instead of being reused
        if (cacheValid && knownPolicy.mode !== 'none') {
            // re-use existing policy on error
            return useCached(err);
        }

        if (!strict && knownPolicy?.id && ['enforce', 'testing'].includes(knownPolicy.mode)) {
            // lax mode keeps applying an expired policy instead of falling back to no policy
            warnings.push('expired-cache');
            return useCached(err);
        }

        // continue as if the domain had no policy, and do not retry fetching this policy ID for a while
        return formatResult(
            {
                id: policyId,
                mode: 'none',
                expires: new Date(Date.now() + ERROR_RETRY_DELAY).toISOString(),
                error: err
            },
            'errored',
            warnings
        );
    }
};

module.exports = {
    resolvePolicy,
    fetchPolicy,
    parsePolicy,
    validateMx,
    getPolicy
};
