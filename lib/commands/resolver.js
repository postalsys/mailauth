'use strict';

const fs = require('node:fs');
const { resolve } = require('node:dns').promises;

/**
 * The DNS resolver for a command: answers from the --dns-cache file, or real DNS queries that are
 * logged with --verbose. Undefined when neither is set, so the library uses its default resolver
 *
 * @param {Object} argv Command options
 * @returns {Function|undefined} async (name, rrtype) resolver
 */
const createResolver = async argv => {
    if (argv.dnsCache) {
        let dnsCache = JSON.parse(await fs.promises.readFile(argv.dnsCache, 'utf-8'));

        return async (name, rr) => {
            let match = dnsCache?.[name]?.[rr];

            if (argv.verbose) {
                console.error(`DNS query for ${rr} ${name}: ${match ? JSON.stringify(match) : 'not found'} (using cache)`);
            }

            if (!match) {
                let err = new Error('Error');
                err.code = 'ENOTFOUND';
                throw err;
            }

            return match;
        };
    }

    if (argv.verbose) {
        return async (name, rr) => {
            let match;
            try {
                match = await resolve(name, rr);
                console.error(`DNS query for ${rr} ${name}: ${match ? JSON.stringify(match) : 'not found'}`);
                return match;
            } catch (err) {
                console.error(`DNS query for ${rr} ${name}: ${err.message}${err.code ? ` [${err.code}]` : ''}`);
                throw err;
            }
        };
    }

    return undefined;
};

module.exports = { createResolver };
