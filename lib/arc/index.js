'use strict';

const { Buffer } = require('node:buffer');
const {
    parseDkimHeaders,
    formatRelaxedLine,
    getPublicKey,
    formatAuthHeaderRow,
    formatSignatureHeaderLine,
    writeToStream,
    validateAlgorithm
} = require('../../lib/tools');
const crypto = require('node:crypto');
const { DkimSigner } = require('../dkim/dkim-signer');

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
        let res = await getPublicKey('AS', queryDomain, opts.minBitLength, resolver);
        publicKey = res?.publicKey;
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
        let err = new Error(`i=${chain.length} seal signature validation failed`);
        err.code = 'failing_arc_seal';
        throw err;
    }

    return true;
};

const signAS = async (chain, entry, signatureData) => {
    let { instance, algorithm, selector, signingDomain, bodyHash, cv, signTime, privateKey } = signatureData;

    const signAlgo = algorithm?.split('-').shift();

    signTime = signTime || new Date();

    let chunks = [];

    if (signatureData.cv === 'pass') {
        // sign existing only chain for passing validation
        for (let i = 0; i < chain.length; i++) {
            let link = chain[i];

            chunks.push(formatRelaxedLine(link['arc-authentication-results'].original, '\r\n'));
            chunks.push(formatRelaxedLine(link['arc-message-signature'].original, '\r\n'));
            chunks.push(formatRelaxedLine(link['arc-seal'].original, '\r\n'));
        }
    }

    chunks.push(formatRelaxedLine(entry['arc-authentication-results'], '\r\n'));
    chunks.push(formatRelaxedLine(entry['arc-message-signature'], '\r\n'));

    let headerOpts = {
        i: instance,
        a: algorithm,
        s: selector,
        d: signingDomain,
        cv,
        bh: bodyHash
    };

    if (signTime) {
        if (typeof signTime === 'string' || typeof signTime === 'number') {
            signTime = new Date(signTime);
        }

        if (Object.prototype.toString.call(signTime) === '[object Date]' && signTime.toString() !== 'Invalid Date') {
            // we need a unix timestamp value
            signTime = Math.round(signTime.getTime() / 1000);
            headerOpts.t = signTime;
        }
    }

    let canonSignatureHeaderLine = formatSignatureHeaderLine(
        'AS',
        Object.assign(
            {
                // make sure that b= always has a value, otherwise folding would be different
                b: 'a'.repeat(73)
            },
            headerOpts
        ),
        true
    );

    chunks.push(
        Buffer.from(
            formatRelaxedLine(canonSignatureHeaderLine)
                .toString('binary')
                // remove value from b= key
                .replace(/([;:\s]+b=)[^;]+/, '$1'),
            'binary'
        )
    );

    let canonicalizedHeader = Buffer.concat(chunks);

    let signature = crypto
        .sign(
            // use `null` as algorithm to detect it from the key file
            signAlgo === 'rsa' ? algorithm : null,
            signAlgo === 'rsa' ? canonicalizedHeader : crypto.createHash('sha256').update(canonicalizedHeader).digest(),
            privateKey
        )
        .toString('base64');

    headerOpts.b = signature;

    return formatSignatureHeaderLine('AS', headerOpts, true);
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
        await verifyAS(data.chain.slice(0, i + 1), opts);
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
                    let err = new Error(`i=${instance} multiple ${row.key} values`);
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
        let err = new Error(`chain-length=${arcChain.length}`);
        err.code = 'invalid_arc_count';
        throw err;
    }

    for (let i = 0; i < arcChain.length; i++) {
        const arcInstance = arcChain[i];

        if (arcInstance.i !== i + 1) {
            // not a complete sequence
            let err = new Error(`i=${arcInstance.i} expected=${i + 1}`);
            err.code = 'invalid_arc_instance';
            throw err;
        }

        for (let headerKey of ['arc-seal', 'arc-message-signature', 'arc-authentication-results']) {
            if (!arcInstance[headerKey]) {
                // missing required header
                let err = new Error(`i=${arcInstance.i} no ${headerKey} set`);
                err.code = 'missing_arc_header';
                throw err;
            }
        }

        if (i === 0 && arcInstance['arc-seal']?.parsed?.cv?.value?.toLowerCase() !== 'none') {
            let err = new Error(`i=1 cv="${arcInstance['arc-seal']?.parsed?.cv?.value}`);
            err.code = 'invalid_cv_value';
            throw err;
        }

        let asC = arcInstance['arc-seal']?.parsed?.c?.value?.toLowerCase().trim();
        if (asC && asC !== 'relaxed/relaxed') {
            let err = new Error(`i=${arcInstance.i} invalid as c`);
            err.code = 'unexpected_as_c_value';
            throw err;
        }

        // add missing c value
        if (arcInstance['arc-message-signature']?.parsed && !arcInstance['arc-message-signature']?.parsed?.c) {
            arcInstance['arc-message-signature'].parsed.c = { value: 'relaxed/relaxed' };
        }

        if (arcInstance['arc-seal']?.parsed?.a && !arcInstance['arc-seal']?.parsed?.a?.value) {
            let err = new Error(`i=${arcInstance.i} empty a`);
            err.code = 'invalid_a_value';
            throw err;
        }

        if (!arcInstance['arc-seal']?.parsed?.a?.value) {
            let err = new Error(`i=${arcInstance.i} missing a`);
            err.code = 'missing_a_value';
            throw err;
        }

        // throws if using non-supported algorithm
        validateAlgorithm(arcInstance['arc-seal']?.parsed?.a?.value, true);
        validateAlgorithm(arcInstance['arc-message-signature']?.parsed?.a?.value, true);

        if (i > 0 && arcInstance['arc-seal']?.parsed?.cv?.value?.toLowerCase() !== 'pass') {
            let err = new Error(`i=${arcInstance.i} cv=${arcInstance['arc-seal']?.parsed?.cv?.value}`);
            err.code = 'invalid_cv_value';
            throw err;
        }

        if (arcInstance['arc-seal']?.parsed?.h) {
            let err = new Error(`i=${arcInstance.i} unexpected as h`);
            err.code = 'unexpected_as_h_value';
            throw err;
        }

        let amsH = arcInstance['arc-message-signature']?.parsed?.h?.value
            ?.trim()
            .toLowerCase()
            .split(':')
            .map(v => v.trim())
            .filter(v => v);

        if (amsH?.some(v => v === 'arc-seal')) {
            let err = new Error(`i=${arcInstance.i} invalid ams h`);
            err.code = 'invalid_ams_h_value';
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

    Object.defineProperty(result, 'chain', {
        enumerable: false,
        configurable: false,
        writable: false,
        value: data.chain
    });

    try {
        if (data.error) {
            // raise error from `getARChain`
            throw data.error;
        }

        let hasChain = await verifyASChain(data, opts);
        if (hasChain) {
            result.i = data?.lastEntry?.i || false;
            result.signature = data?.lastEntry?.messageSignature || false;

            if (result?.signature?.status?.result !== 'pass') {
                // no valid ARC-Message-Signature found
                let err = new Error(`i=${result.i} no valid signature`);
                err.code = 'missing_valid_ams';
                throw err;
            }

            result.authenticationResults = data?.lastEntry?.['arc-authentication-results']?.parsed;

            if (result.authenticationResults) {
                delete result.authenticationResults.i;
                delete result.authenticationResults.header;

                if (result.authenticationResults.value) {
                    let mta = result.authenticationResults.value;
                    delete result.authenticationResults.value;
                    result.authenticationResults = Object.assign({ mta }, result.authenticationResults);
                }

                ['arc', 'spf', 'dmarc'].forEach(key => {
                    if (result.authenticationResults[key]) {
                        let res = result.authenticationResults[key].value;
                        delete result.authenticationResults[key].value;
                        result.authenticationResults[key] = Object.assign({ result: res }, result.authenticationResults[key]);
                    }
                });

                if (result.authenticationResults.dkim && result.authenticationResults.dkim.length) {
                    result.authenticationResults.dkim = result.authenticationResults.dkim.map(entry => {
                        let result = entry.value;
                        delete entry.value;
                        return Object.assign({ result }, entry);
                    });
                }
            }

            status.result = 'pass';
        } else {
            result.i = 0;
            status.result = 'none';
        }
    } catch (err) {
        // all failures are permanent in the scope of ARC
        result.i = data?.lastEntry?.i || false;
        status.result = 'fail';
        // if last entry was listed as passing then add our seal even if the validation failed
        status.shouldSeal = ['pass', 'none'].includes(data?.lastEntry?.['arc-seal']?.parsed?.cv?.value);

        switch (err.code) {
            case 'invalid_arc_seal':
            case 'failing_arc_seal':
            case 'multiple_arc_keys':
            case 'invalid_arc_count':
            case 'invalid_arc_instance':
            case 'missing_arc_header':
            case 'invalid_cv_value':
            case 'unexpected_as_h_value':
            case 'invalid_ams_h_value':
            case 'missing_valid_ams':
            case 'unexpected_as_c_value':
            case 'unexpected_ams_c_value':
                status.comment = err.message
                    .toLowerCase()
                    .replace(/["'()]/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim()
                    .substr(0, 128);
                break;

            case 'ENOTFOUND':
            case 'ENODATA':
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

    return result;
};

const createSeal = async (input, data) => {
    let { headers, arc, seal } = data;
    let bodyHash = seal?.bodyHash;

    // Step 1. Calculate ARC-Message-Signature
    let dkimSigner = new DkimSigner({
        // headers and bodyHash are prepared values if we do not have the source message anymore
        headers,
        bodyHash: seal.bodyHash,

        signTime: seal.signTime,

        // which headers to sign
        headerList: seal.headerList,

        arc: {
            instance: seal.i, // overriden if not set
            algorithm: seal.algorithm,
            signingDomain: seal.signingDomain,
            selector: seal.selector,
            privateKey: seal.privateKey
        },

        getARChain // pass as a property so we do not have to use circular require()
    });

    if (input) {
        await writeToStream(dkimSigner, input);

        let { hashAlgo } = dkimSigner.getAlgorithm(seal);
        let { bodyCanon } = dkimSigner.getCanonicalization(seal);

        let hashKey = `${bodyCanon}:${hashAlgo}:`;

        bodyHash = dkimSigner.bodyHashes.get(hashKey)?.hash;

        arc = arc || dkimSigner.arc;
        seal.i = arc.instance;
    } else {
        // this gives us dkimSigner.arc.messageSignature
        await dkimSigner.finalize();
    }

    const authResults = `ARC-Authentication-Results: i=${seal.i}; ${seal.authResults}`;

    // Step 2. Calculate ARC-Seal
    const arcSeal = await signAS(
        arc.chain,
        {
            'arc-authentication-results': authResults,
            'arc-message-signature': dkimSigner.arc?.messageSignature
        },
        {
            instance: seal.i,
            algorithm: seal.algorithm || 'rsa-sha256',
            signingDomain: seal.signingDomain,
            selector: seal.selector,
            bodyHash,
            cv: seal.cv,
            signTime: seal.signTime,
            privateKey: seal.privateKey
        }
    );

    return {
        headers: [arcSeal, dkimSigner?.arc?.messageSignature, authResults].map(v => v)
    };
};

const sealMessage = async (input, seal) => {
    const { headers } = await createSeal(input, { seal });
    return headers.length ? Buffer.from(headers.join('\r\n') + '\r\n') : Buffer.from('');
};

module.exports = { getARChain, arc, createSeal, sealMessage };
