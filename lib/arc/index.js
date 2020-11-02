'use strict';

const { parseDkimHeaders, formatRelaxedLine, getPublicKey, formatAuthHeaderRow } = require('../../lib/tools');
const crypto = require('crypto');

const verifyAS = async (chain, opts) => {
    const { resolver } = opts || {};

    let chunks = [];
    let signatureHeader;

    for (let i = 0; i < chain.length; i++) {
        let isLast = i === chain.length - 1;
        let link = chain[i];

        chunks.push(formatRelaxedLine(link['arc-authentication-results'].original, '\r\n'));
        chunks.push(formatRelaxedLine(link['arc-message-signature'].original, '\r\n'));

        if (!isLast) {
            chunks.push(formatRelaxedLine(link['arc-seal'].original, '\r\n'));
        } else {
            signatureHeader = link['arc-seal'];
            if (!signatureHeader.parsed?.s?.value || !signatureHeader.parsed?.d?.value) {
                let err = new Error(`Invalid ARC-Seal header`);
                err.code = 'invalid_arc_seal';
                throw err;
            }

            chunks.push(
                Buffer.from(
                    formatRelaxedLine(link['arc-seal'].original)
                        .toString('binary')
                        // remove value from b= key
                        .replace(/([;:\s]+b=)[^;]+/, '$1'),
                    'binary'
                )
            );
        }
    }

    let canonicalizedHeader = Buffer.concat(chunks);

    let publicKey;
    let queryDomain = `${signatureHeader.parsed?.s?.value}._domainkey.${signatureHeader.parsed?.d?.value}`;
    try {
        publicKey = await getPublicKey('AS', queryDomain, resolver);
    } catch (err) {
        err.queryDomain = queryDomain;
    }

    let pass = crypto.verify(
        signatureHeader.signAlgo === 'rsa' ? signatureHeader.algorithm : null,
        canonicalizedHeader,
        publicKey,
        Buffer.from(signatureHeader.parsed?.b?.value, 'base64')
    );

    if (!pass) {
        let err = new Error(`ARC Seal validation failed (i=${chain.length + 1})`);
        err.code = 'failing_arc_seal';
        throw err;
    }

    return true;
};

const verifyASChain = async (data, opts) => {
    if (!data?.chain?.length) {
        return false;
    }

    for (let i = data.chain.length - 1; i >= 0; i--) {
        if (!['none', 'pass'].includes(data.chain[i]?.['arc-seal']?.parsed?.cv?.value)) {
            // no need to look further
            // validate this header set only
            // TODO: what should we report as the result?
            await verifyAS([data.chain[i]], opts);
            break;
        }

        // throws if validation fails
        await verifyAS(data.chain.slice(0, i + 1));
    }

    return true;
};

const getARChain = headers => {
    let headerRows = (headers && headers.parsed) || [];

    let arcChain = new Map();
    for (let row of headerRows) {
        if (['arc-seal', 'arc-message-signature', 'arc-authentication-results'].includes(row.key)) {
            let value = parseDkimHeaders(row.line);
            let instance = value?.parsed?.i?.value;
            if (instance) {
                if (!arcChain.has(instance)) {
                    arcChain.set(instance, {
                        i: instance
                    });
                } else if (arcChain.get(instance)[row.key]) {
                    // value for this header is already set
                    let err = new Error(`Multiple "${row.key}" values for the same instance "${instance}"`);
                    err.code = 'multiple_arc_keys';
                    throw err;
                }
                arcChain.get(instance)[row.key] = value;
            }
        }
    }

    arcChain = Array.from(arcChain.values()).sort((a, b) => a.i - b.i);
    if (!arcChain.length) {
        // empty chain
        return false;
    }

    if (arcChain.length > 50) {
        let err = new Error(`Too many ARC instances found: "${arcChain.length}"`);
        err.code = 'invalid_arc_count';
        throw err;
    }

    for (let i = 0; i < arcChain.length; i++) {
        const arcInstance = arcChain[i];

        if (arcInstance.i !== i + 1) {
            // not a complete sequence
            let err = new Error(`Invalid instance number "${arcInstance.i}". Expecting "${i + 1}"`);
            err.code = 'invalid_arc_instance';
            throw err;
        }

        for (let headerKey of ['arc-seal', 'arc-message-signature', 'arc-authentication-results']) {
            if (!arcInstance[headerKey]) {
                // missing required header
                let err = new Error(`Missing header ${headerKey} from ARC instance ${arcInstance.i}`);
                err.code = 'missing_arc_header';
                throw err;
            }
        }

        if (i === 0 && arcInstance['arc-seal']?.parsed?.cv?.value?.toLowerCase() !== 'none') {
            let err = new Error(`Unexpected cv value for first ARC instance: "${arcInstance['arc-seal']?.parsed?.cv?.value}". Expecting "none"`);
            err.code = 'invalid_cv_value';
            throw err;
        }

        if (i > 0 && arcInstance['arc-seal']?.parsed?.cv?.value?.toLowerCase() !== 'pass') {
            let err = new Error(`Unexpected cv value ARC instance ${arcInstance.i}: "${arcInstance['arc-seal']?.parsed?.cv?.value}". Expecting "pass"`);
            err.code = 'invalid_cv_value';
            throw err;
        }

        if (arcInstance['arc-seal']?.parsed?.h) {
            let err = new Error(`Unexpected h value found from ARC-Seal i=${arcInstance.i}: "${arcInstance['arc-seal']?.parsed?.h?.value}"`);
            err.code = 'unexpected_h_value';
            throw err;
        }
    }

    return arcChain;
};

// {chain, last}
const arc = async (data, opts) => {
    const status = {
        result: 'none'
    };

    const result = { status };

    try {
        if (data.error) {
            // raise error from `getARChain`
            throw data.error;
        }

        let hasChain = await verifyASChain(data, opts);
        if (hasChain) {
            result.i = data?.lastEntry?.i || false;
            result.signature = data?.lastEntry?.messageSignature || false;

            result.authenticationResults = data?.lastEntry?.['arc-authentication-results']?.parsed;
            if (result.authenticationResults) {
                delete result.authenticationResults.i;
                delete result.authenticationResults.header;

                result.authenticationResults.host = result.authenticationResults.value;
                delete result.authenticationResults.value;

                ['arc', 'spf', 'dmarc'].forEach(key => {
                    if (result.authenticationResults[key]) {
                        result.authenticationResults[key].result = result.authenticationResults[key].value;
                        delete result.authenticationResults[key].value;
                    }
                });

                if (result.authenticationResults.dkim && result.authenticationResults.dkim.length) {
                    result.authenticationResults.dkim.forEach(entry => {
                        entry.result = entry.value;
                        delete entry.value;
                    });
                }
            }
            status.result = 'pass';
        } else {
            result.i = 0;
            status.result = 'none';
        }

        if (status.result !== 'none') {
            if (status.result === 'pass' && result.authenticationResults) {
                let comment = [`i=${result.i}`, result.authenticationResults.spf ? `spf=${result.authenticationResults.spf.result}` : false];

                if (result.authenticationResults.dkim && result.authenticationResults.dkim.length) {
                    for (let entry of result.authenticationResults.dkim) {
                        comment.push(`dkim=${entry.result}`);
                        if (entry?.header?.i) {
                            comment.push(`dkdomain=${entry.header.i.replace(/^@/, '')}`);
                        }
                    }
                }

                if (result.authenticationResults.dmarc) {
                    comment.push(`dmarc=${result.authenticationResults.dmarc.result}`);
                    if (result.authenticationResults.dmarc?.header?.from) {
                        comment.push(`fromdomain=${result.authenticationResults.dmarc?.header?.from}`);
                    }
                }

                status.comment = comment.filter(v => v).join(' ');
            }

            result.info = formatAuthHeaderRow('arc', status);
        }
    } catch (err) {
        // all failures are permanent in the scope of ARC
        status.result = 'fail';

        switch (err.code) {
            case 'invalid_arc_seal':
            case 'failing_arc_seal':
            case 'multiple_arc_keys':
            case 'invalid_arc_count':
            case 'invalid_arc_instance':
            case 'missing_arc_header':
            case 'invalid_cv_value':
            case 'unexpected_h_value':
                status.comment = err.message
                    .toLowerCase()
                    .replace(/["'()]/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim()
                    .substr(0, 128);
                break;

            case 'ENOTFOUND':
                if (err.queryDomain) {
                    status.comment = `no key for ${err.queryDomain}`;
                }
                break;

            case 'EINVALIDVER':
                if (err.queryDomain) {
                    status.comment = `unknown key version for ${err.queryDomain}`;
                }
                break;

            case 'EINVALIDTYPE':
                if (err.queryDomain) {
                    status.comment = `unknown key type for ${err.queryDomain}`;
                }
                break;

            case 'EINVALIDVAL':
                if (err.queryDomain) {
                    status.comment = `invalid public key for ${err.queryDomain}`;
                }
                break;

            case 'ESHORTKEY':
                status.policy['dkim-rules'] = `weak-key`;
                if (err.queryDomain) {
                    status.comment = `weak key for ${err.queryDomain}`;
                }
                break;
        }
    }

    return result;
};

module.exports = { getARChain, arc };
