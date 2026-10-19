import { dkim2Sign } from '../dkim2/sign.js';
import { GathererStream } from '../gatherer-stream.js';
import fs from 'node:fs';
import type { Readable } from 'node:stream';
import type { DKIM2SignOptions, DKIM2SignatureKey } from '../types.js';

// the options of the dkim2-sign command
interface Dkim2SignArgv {
    email?: string | undefined;
    verbose?: boolean | undefined;
    privateKey?: string[] | undefined;
    selector?: string[] | undefined;
    domain: string;
    mailFrom?: string | undefined;
    rcptTo?: string[] | undefined;
    nextDomain?: string | undefined;
    nonce?: string | undefined;
    flag?: string[] | undefined;
    // not validated here, the signer rejects unsupported algorithms
    hash?: string[] | undefined;
    recipe?: string | undefined;
    time?: number | undefined;
    headersOnly?: boolean | undefined;
}

const cmd = async (argv: Dkim2SignArgv): Promise<void> => {
    let source = argv.email;
    let stream: Readable;

    if (argv.verbose) {
        console.error(`Reading email message from ${source || 'standard input'}`);
    }

    stream = source ? fs.createReadStream(source) : process.stdin;

    let privateKeys = argv.privateKey || [];
    let selectors = argv.selector || [];
    if (privateKeys.length !== selectors.length) {
        let err = new Error('Every --private-key needs a --selector, in the same order');
        throw err;
    }

    let gatherer = new GathererStream({ gather: !argv.headersOnly });
    stream.pipe(gatherer);
    stream.on('error', err => gatherer.emit('error', err));

    let signatureData: DKIM2SignatureKey[] = [];
    for (let i = 0; i < privateKeys.length; i++) {
        signatureData.push({ selector: selectors[i], privateKey: await fs.promises.readFile(privateKeys[i], 'utf-8') });
    }

    let options: DKIM2SignOptions & { signTime: Date } = {
        signingDomain: argv.domain,
        signatureData,
        signTime: argv.time ? new Date(argv.time * 1000) : new Date(),
        flags: argv.flag,
        nonce: argv.nonce
    };

    if (argv.hash?.length) {
        options.hashAlgorithms = argv.hash as DKIM2SignOptions['hashAlgorithms'];
    }

    if (argv.nextDomain) {
        options.nextDomain = argv.nextDomain;
    } else {
        options.mailFrom = argv.mailFrom;
        options.rcptTo = argv.rcptTo;
    }

    if (argv.recipe) {
        options.recipe = JSON.parse(await fs.promises.readFile(argv.recipe, 'utf-8'));
    }

    if (argv.verbose) {
        console.error(`Signing domain: ${options.signingDomain}`);
        console.error(`Selectors:      ${selectors.join(', ')}`);
        console.error(`Signing time:   ${options.signTime.toISOString()}`);
        console.error('--------');
    }

    let signResult = await dkim2Sign(gatherer, options);

    process.stdout.write(signResult.signatures);
    if (!argv.headersOnly) {
        // print the full message as well
        await new Promise<void>((resolve, reject) => {
            let msgStream = gatherer.replay();
            msgStream.pipe(process.stdout, { end: false });
            msgStream.on('end', resolve);
            msgStream.on('error', reject);
        });
    }
};

export default cmd;
