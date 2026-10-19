import { dkim2Hash } from '../dkim2/hash.js';
import fs from 'node:fs';
import type { DKIM2HashOptions } from '../types.js';

// the options of the dkim2-hash command
interface Dkim2HashArgv {
    email?: string | undefined;
    verbose?: boolean | undefined;
    // the values as given, dkim2Hash() rejects unsupported algorithms
    algo?: DKIM2HashOptions['algorithms'];
}

const cmd = async (argv: Dkim2HashArgv): Promise<void> => {
    let source = argv.email;
    if (argv.verbose) {
        console.error(`Reading email message from ${source || 'standard input'}`);
    }

    let { headers, hashes } = await dkim2Hash(source ? fs.createReadStream(source) : process.stdin, { algorithms: argv.algo });

    if (argv.verbose) {
        console.error(`Hashed header fields: ${headers.join(', ') || '(none)'}`);
        console.error('--------');
    }

    // the hash-sets of the h= tag of a Message-Instance (section 7.3)
    for (let { algorithm, headerHash, bodyHash } of hashes) {
        process.stdout.write(`${algorithm}:${headerHash}:${bodyHash}\n`);
    }
};

export default cmd;
