import { dkim2Verify } from '../dkim2/verify.js';
import { createResolver } from './resolver.js';
import fs from 'node:fs';
import type { DKIM2VerifyOptions } from '../types.js';

// the options of the dkim2-verify command
interface Dkim2VerifyArgv {
    email?: string | undefined;
    verbose?: boolean | undefined;
    mailFrom?: string | undefined;
    rcptTo?: string[] | undefined;
    dnsCache?: string | undefined;
    time?: number | undefined;
    maxAge?: number | undefined;
    maxFuture?: number | undefined;
    maxInstances?: number | undefined;
    headersOnly?: boolean | undefined;
}

const cmd = async (argv: Dkim2VerifyArgv): Promise<void> => {
    let source = argv.email;

    if (argv.verbose) {
        console.error(`Reading email message from ${source || 'standard input'}`);
    }

    let stream = source ? fs.createReadStream(source) : process.stdin;

    let opts: DKIM2VerifyOptions = {
        resolver: await createResolver(argv),
        rcptTo: argv.rcptTo
    };

    if (typeof argv.mailFrom === 'string') {
        opts.mailFrom = argv.mailFrom;
    }

    if (typeof argv.time === 'number') {
        opts.curTime = new Date(argv.time * 1000);
    }

    if (typeof argv.maxAge === 'number') {
        // 0 turns the expiration check off
        opts.maxSignatureAge = argv.maxAge || false;
    }

    if (typeof argv.maxFuture === 'number') {
        // 0 turns the check off, like --max-age
        opts.maxFutureTime = argv.maxFuture || false;
    }

    if (typeof argv.maxInstances === 'number') {
        opts.maxInstances = argv.maxInstances;
    }

    let result = await dkim2Verify(stream, opts);

    if (argv.verbose) {
        for (let warning of result.status.warnings || []) {
            console.error(`Warning: ${warning}`);
        }
    }

    if (argv.headersOnly) {
        process.stdout.write(result.info + '\n');
        return;
    }

    process.stdout.write(JSON.stringify(result, false as unknown as null, 2) + '\n');
};

export default cmd;
