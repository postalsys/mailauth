import fs from 'node:fs';
import { promises as _promises_node_dns } from 'node:dns';
const { resolve } = _promises_node_dns;

/**
 * The command options createResolver() reads
 */
export interface ResolverArgv {
    dnsCache?: string | undefined;
    verbose?: boolean | undefined;
}

/**
 * A DNS resolver with the signature of dns.promises.resolve
 */
export type CommandResolver = (name: string, rr: string) => Promise<any>;

/**
 * The DNS resolver for a command: answers from the --dns-cache file, or real DNS queries that are
 * logged with --verbose. Undefined when neither is set, so the library uses its default resolver
 *
 * @param {Object} argv Command options
 * @returns {Function|undefined} async (name, rrtype) resolver
 */
const createResolver = async (argv: ResolverArgv): Promise<CommandResolver | undefined> => {
    if (argv.dnsCache) {
        let dnsCache = JSON.parse(await fs.promises.readFile(argv.dnsCache, 'utf-8'));

        return async (name: string, rr: string) => {
            let match = dnsCache?.[name]?.[rr];

            if (argv.verbose) {
                console.error(`DNS query for ${rr} ${name}: ${match ? JSON.stringify(match) : 'not found'} (using cache)`);
            }

            if (!match) {
                let err: Error & { code?: string } = new Error('Error');
                err.code = 'ENOTFOUND';
                throw err;
            }

            return match;
        };
    }

    if (argv.verbose) {
        return async (name: string, rr: string) => {
            let match;
            try {
                match = await resolve(name, rr);
                console.error(`DNS query for ${rr} ${name}: ${match ? JSON.stringify(match) : 'not found'}`);
                return match;
            } catch (err: any) {
                console.error(`DNS query for ${rr} ${name}: ${err.message}${err.code ? ` [${err.code}]` : ''}`);
                throw err;
            }
        };
    }

    return undefined;
};

export { createResolver };
