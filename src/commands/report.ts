import { authenticate } from '../mailauth.js';
import fs from 'node:fs';
import { createResolver } from './resolver.js';
import type { AuthenticateOptions, SPFOptions } from '../types.js';

// the options of the report command
interface ReportArgv {
    email?: string | undefined;
    verbose?: boolean | undefined;
    clientIp?: string | undefined;
    mta?: string | undefined;
    helo?: string | undefined;
    sender?: string | undefined;
    dnsCache?: string | undefined;
    maxLookups?: number | undefined;
    maxVoidLookups?: number | undefined;
    strict?: boolean | undefined;
    rejectRsaSha1?: boolean | undefined;
    dkim2?: boolean | undefined;
    rcptTo?: string[] | undefined;
}

const cmd = async (argv: ReportArgv): Promise<void> => {
    let source = argv.email;
    let useStdin = false;
    let stream;

    if (!source) {
        useStdin = true;
        source = 'standard input';
    }

    if (argv.verbose) {
        console.error(`Reading email message from ${source}`);
    }

    if (useStdin) {
        stream = process.stdin;
    } else {
        stream = fs.createReadStream(source);
    }

    // authenticate() passes the SPF lookup limits on to spf()
    const opts: AuthenticateOptions & Pick<SPFOptions, 'maxResolveCount' | 'maxVoidCount'> = {
        trustReceived: true,
        strict: !!argv.strict,
        rejectRsaSha1: !!argv.rejectRsaSha1,
        dkim2: !!argv.dkim2
    };

    if (argv.rcptTo) {
        opts.rcptTo = argv.rcptTo;
    }

    if (argv.clientIp) {
        opts.ip = argv.clientIp;
    }

    if (typeof argv.maxLookups === 'number') {
        opts.maxResolveCount = argv.maxLookups;
    }

    if (typeof argv.maxVoidLookups === 'number') {
        opts.maxVoidCount = argv.maxVoidLookups;
    }

    for (let key of ['mta', 'helo', 'sender'] as const) {
        if (argv[key]) {
            opts[key] = argv[key];
        }
    }

    opts.resolver = await createResolver(argv);

    let result = await authenticate(stream, opts);
    process.stdout.write(JSON.stringify(result, false as unknown as null, 2) + '\n');
};

export default cmd;
