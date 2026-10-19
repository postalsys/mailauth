import { Buffer } from 'node:buffer';
import { authenticate } from '../mailauth.js';
import { createSeal } from '../arc/index.js';
import fs from 'node:fs';
import { GathererStream } from '../gatherer-stream.js';
import { createResolver } from './resolver.js';
import type { Readable } from 'node:stream';
import type { ARCResult, ARCSealOptions, AuthenticateOptions } from '../types.js';

// the options of the seal command
interface SealArgv {
    email?: string | undefined;
    verbose?: boolean | undefined;
    privateKey: string;
    domain: string;
    selector: string;
    algo?: string | undefined;
    time?: number | undefined;
    headerFields?: string | undefined;
    clientIp?: string | undefined;
    mta?: string | undefined;
    helo?: string | undefined;
    sender?: string | undefined;
    dnsCache?: string | undefined;
    headersOnly?: boolean | undefined;
    strict?: boolean | undefined;
    authResults?: string | undefined;
    authResultsFile?: string | undefined;
    cv?: string | undefined;
    instance?: number | undefined;
}

// the seal options, with the signing time set
interface SealSignatureOptions extends ARCSealOptions {
    signTime: Date;
}

const writeMessageBody = async (gatherer: GathererStream): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        let msgStream = gatherer.replay();

        msgStream.pipe(process.stdout, { end: false });
        msgStream.on('end', () => {
            resolve();
        });

        msgStream.on('error', err => {
            reject(err);
        });
    });

const printSignatureInfo = (opts: SealSignatureOptions): void => {
    if (opts.signingDomain) {
        console.error(`Signing domain:             ${opts.signingDomain}`);
    }
    if (opts.selector) {
        console.error(`Key selector:               ${opts.selector}`);
    }
    if (opts.algorithm) {
        console.error(`Hashing algorithm:          ${opts.algorithm}`);
    }
    if (opts.signTime) {
        console.error(`Signing time:               ${opts.signTime.toISOString()}`);
    }
};

const cmd = async (argv: SealArgv): Promise<void> => {
    let source = argv.email;
    let useStdin = false;
    let stream: Readable;

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

    let gatherer = new GathererStream({ gather: !argv.headersOnly });
    stream.pipe(gatherer);
    stream.on('error', err => gatherer.emit('error', err));

    let privateKey = await fs.promises.readFile(argv.privateKey, 'utf-8');

    let signatureOpts: SealSignatureOptions = {
        signingDomain: argv.domain,
        selector: argv.selector,
        privateKey,
        algorithm: argv.algo,
        headerList: argv.headerFields,
        signTime: argv.time ? new Date(argv.time * 1000) : new Date(),
        strict: !!argv.strict
    };

    if (argv.authResults || argv.authResultsFile) {
        // Seal-only mode: embed the caller-provided Authentication-Results value without authenticating the message
        let authResults = argv.authResultsFile ? (await fs.promises.readFile(argv.authResultsFile, 'utf-8')).trim() : argv.authResults;
        // a folded value from a file usually has LF line endings, header folding needs CRLF.
        // createSeal refuses any line break that does not continue the header with whitespace
        // set, either --auth-results or --auth-results-file was given
        authResults = authResults!.replace(/\r?\n/g, '\r\n');

        let sealOpts: SealSignatureOptions = Object.assign({}, signatureOpts, {
            authResults,
            cv: argv.cv || 'none'
        });

        if (argv.instance) {
            sealOpts.i = argv.instance;
        }

        if (argv.verbose) {
            console.error('Seal-only mode: sealing with provided authentication results, skipping authentication');
            printSignatureInfo(sealOpts);
            console.error(`Chain validation status:    ${sealOpts.cv}`);
            if (sealOpts.i) {
                console.error(`ARC instance:               ${sealOpts.i}`);
            }
            console.error('--------');
        }

        let { headers, errors, warnings, instance } = await createSeal(gatherer, { seal: sealOpts });

        if (!headers.length) {
            // nothing was sealed, say why instead of printing the message as if it had been
            let err = errors?.[0]?.err || new Error('The message could not be sealed');
            throw err;
        }

        // the instance is set when a set was created
        if (instance! > 1 && !argv.cv) {
            console.error(`warning: sealed with i=${instance} and cv=none; a chain with i>1 only validates when cv=pass (use --cv pass)`);
        }

        for (let warning of warnings || []) {
            switch (warning) {
                case 'arc-instance-gap':
                    console.error(`warning: sealed with i=${instance}, which does not follow the existing ARC chain`);
                    break;
                case 'arc-cv-instance':
                    // covered by the message above for the default cv
                    if (argv.cv) {
                        console.error(`warning: cv=${argv.cv} is not valid for i=${instance} (i=1 takes cv=none, later sets take cv=pass or cv=fail)`);
                    }
                    break;
                default:
                    console.error(`warning: ${warning}`);
            }
        }

        process.stdout.write(Buffer.from(headers.join('\r\n') + '\r\n'));
        if (!argv.headersOnly) {
            // print full message as well
            await writeMessageBody(gatherer);
        }
        return;
    }

    if (argv.verbose) {
        printSignatureInfo(signatureOpts);
        if (signatureOpts.headerList) {
            console.error(`Header fields to seal:      ${signatureOpts.headerList}`);
        }
        if (argv.dnsCache) {
            console.error(`Using DNS cache:             ${argv.dnsCache}`);
        }
        console.error('--------');
    }

    const opts: AuthenticateOptions = {
        trustReceived: true,
        seal: signatureOpts,
        strict: !!argv.strict
    };

    if (argv.clientIp) {
        opts.ip = argv.clientIp;
    }

    for (let key of ['mta', 'helo', 'sender'] as const) {
        if (argv[key]) {
            opts[key] = argv[key];
        }
    }

    opts.resolver = await createResolver(argv);

    let result = await authenticate(gatherer, opts);

    // a false arc result has no sealErrors either
    for (let sealError of (result.arc as ARCResult | undefined)?.sealErrors || []) {
        // the message is printed without a seal
        console.error(`warning: the message was not sealed: ${sealError?.err?.message || sealError?.err}`);
    }

    process.stdout.write(result.headers);
    if (!argv.headersOnly) {
        // print full message as well
        await writeMessageBody(gatherer);
    }
};

export default cmd;
