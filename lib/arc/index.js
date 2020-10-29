'use strict';

const util = require('util');
const { parseDkimHeaders } = require('../../lib/tools');

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
        let err = new Error(`Too many ARC instances found ("${arcChain.length}")`);
        err.code = 'invalid_arc_count';
        throw err;
    }

    for (let i = 0; i < arcChain.length; i++) {
        const arcInstance = arcChain[i];

        if (arcInstance.i !== i + 1) {
            // not a complete sequence
            let err = new Error(`Invalid instance number "${arcInstance.i}" (expecting "${i + 1}")`);
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
            let err = new Error(`Unexpected cv value for first ARC instance: "${arcInstance['arc-seal']?.parsed?.cv?.value}" (expecting "none")`);
            err.code = 'invalid_cv_value';
            throw err;
        }

        if (i > 0 && arcInstance['arc-seal']?.parsed?.cv?.value?.toLowerCase() !== 'pass') {
            let err = new Error(`Unexpected cv value ARC instance ${arcInstance.i}: "${arcInstance['arc-seal']?.parsed?.cv?.value}" (expecting "pass")`);
            err.code = 'invalid_cv_value';
            throw err;
        }
    }

    return arcChain;
};

const arc = async headers => {
    let arcChain = getARChain(headers);

    console.log(util.inspect(arcChain, false, 22));

    return 'future feature';
};

module.exports = { getARChain, arc };
