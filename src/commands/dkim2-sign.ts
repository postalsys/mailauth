import { dkim2Sign } from '../dkim2/sign.js';
import { GathererStream } from '../gatherer-stream.js';
import { createResolver } from './resolver.js';
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
    group?: string[] | undefined;
    // not validated here, the signer rejects unsupported algorithms
    hash?: string[] | undefined;
    recipe?: string | undefined;
    time?: number | undefined;
    headersOnly?: boolean | undefined;
    receivedMailFrom?: string | undefined;
    receivedRcptTo?: string[] | undefined;
    outOfBand?: boolean | undefined;
    dnsCache?: string | undefined;
}

// Splits the keys into the groups of --group, lists of key positions counted from 1. Every key
// is in exactly one group
const groupKeys = (keys: DKIM2SignatureKey[], groups: string[]): DKIM2SignatureKey[][] => {
    let used = new Set<number>();
    let result = groups.map(group =>
        group.split(',').map(value => {
            let position = Number(value.trim());
            if (!Number.isSafeInteger(position) || position < 1 || position > keys.length || used.has(position)) {
                throw new Error(`Invalid key position "${value.trim()}" in --group ${group}`);
            }
            used.add(position);
            return keys[position - 1];
        })
    );
    if (used.size !== keys.length) {
        throw new Error('Every key has to be in one --group');
    }
    return result;
};

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

    let keys: DKIM2SignatureKey[] = [];
    for (let i = 0; i < privateKeys.length; i++) {
        keys.push({ selector: selectors[i], privateKey: await fs.promises.readFile(privateKeys[i], 'utf-8') });
    }
    let signatureData = argv.group?.length ? groupKeys(keys, argv.group) : keys;

    let options: DKIM2SignOptions & { signTime: Date } = {
        signingDomain: argv.domain,
        signatureData,
        signTime: argv.time ? new Date(argv.time * 1000) : new Date(),
        flags: argv.flag,
        nonce: argv.nonce,
        resolver: await createResolver(argv),
        outOfBand: !!argv.outOfBand
    };

    if (argv.receivedMailFrom !== undefined || argv.receivedRcptTo) {
        // the envelope the message arrived with, for verifying a message that is already signed
        options.received = { mailFrom: argv.receivedMailFrom, rcptTo: argv.receivedRcptTo };
    }

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
