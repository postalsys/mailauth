'use strict';

const util = require('util');
const { parseDkimHeaders } = require('../../lib/tools');

const arc = async headers => {
    let headerRows = (headers && headers.parsed) || [];

    let arcChain = new Map();
    for (let row of headerRows) {
        if (['arc-seal', 'arc-message-signature', 'arc-authentication-results'].includes(row.key)) {
            let value = parseDkimHeaders(row.line);
            if (value?.parsed?.i?.value) {
                if (!arcChain.has(value?.parsed?.i?.value)) {
                    arcChain.set(value?.parsed?.i?.value, {
                        i: value?.parsed?.i?.value
                    });
                }
                arcChain.get(value?.parsed?.i?.value)[row.key] = value;
            }
        }
    }

    arcChain = Array.from(arcChain.values()).sort((a, b) => a.i - b.i);
    if (!arcChain.length) {
        // nothing to validate
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

    /*
    const latestInstance = arcChain[arcChain.length - 1];
    // TODO: validate AMS

    for (let i = arcChain.length - 1; i >= 0; i--) {
        const arcInstance = arcChain[i];
        // TODO: validate AS
    }
    */

    console.log(util.inspect(arcChain, false, 22));

    return 'future feature';
};

module.exports = { arc };
