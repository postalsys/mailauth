import { spf } from '../spf/index.js';
import { createResolver } from './resolver.js';
import type { SPFOptions } from '../spf/index.js';

// the options of the spf command
interface SpfArgv {
    verbose?: boolean | undefined;
    sender?: string | undefined;
    clientIp?: string | undefined;
    helo?: string | undefined;
    mta?: string | undefined;
    dnsCache?: string | undefined;
    headersOnly?: boolean | undefined;
    maxLookups?: number | undefined;
    maxVoidLookups?: number | undefined;
    maxElapsedTime?: number | undefined;
    strict?: boolean | undefined;
}

const cmd = async (argv: SpfArgv): Promise<void> => {
    let address = argv.sender;

    if (argv.verbose) {
        console.error(`Checking SPF for ${address}`);
        if (argv.maxLookups) {
            console.error(`Maximum DNS lookups: ${argv.maxLookups}`);
        }
        if (argv.dnsCache) {
            console.error(`Using DNS cache:      ${argv.dnsCache}`);
        }
        console.error('--------');
    }

    let opts: Partial<SPFOptions> = {};

    if (argv.clientIp) {
        opts.ip = argv.clientIp;
    }

    if (typeof argv.maxLookups === 'number') {
        opts.maxResolveCount = argv.maxLookups;
    }

    if (typeof argv.maxVoidLookups === 'number') {
        opts.maxVoidCount = argv.maxVoidLookups;
    }

    if (argv.strict) {
        opts.strict = true;
    }

    if (argv.maxElapsedTime) {
        opts.maxElapsedTime = Number(argv.maxElapsedTime);
    }

    for (let key of ['sender', 'helo', 'mta'] as const) {
        if (argv[key]) {
            opts[key] = argv[key];
        }
    }

    opts.resolver = await createResolver(argv);

    let result;
    try {
        // --client-ip is a required option
        result = await spf(opts as SPFOptions);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }

    if (argv.headersOnly) {
        process.stdout.write(result.header + '\r\n');
        return;
    }

    process.stdout.write(JSON.stringify(result, false as unknown as null, 2) + '\n');
};

export default cmd;
