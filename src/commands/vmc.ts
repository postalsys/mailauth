import { validateVMC } from '../bimi/index.js';

import { promises as fs } from 'node:fs';
import type { BIMIData, VMCValidationOptions, VMCValidationResult } from '../types.js';

// the options of the vmc command
interface VmcArgv {
    verbose?: boolean | undefined;
    authorityPath?: string | undefined;
    authority?: string | undefined;
    domain?: string | undefined;
    date?: string | undefined;
}

// the parts of the BIMI data validateVMC() reads
interface VMCInput {
    authorityPath?: Buffer | undefined;
    authority?: string | undefined;
    status?: { header: { d: string } } | undefined;
}

const cmd = async (argv: VmcArgv): Promise<void> => {
    let bimiData: VMCInput = {};
    if (argv.authorityPath) {
        bimiData.authorityPath = await fs.readFile(argv.authorityPath);
    }

    if (argv.authority) {
        bimiData.authority = argv.authority;
    }

    if (argv.domain) {
        bimiData.status = { header: { d: argv.domain } };
    }

    let opts: VMCValidationOptions = {};
    if (argv.date) {
        let date = new Date(argv.date);
        if (date.toString() !== 'Invalid Date') {
            opts.now = date;
            if (argv.verbose) {
                console.error(`Setting date to: ${argv.date}`);
            }
        } else if (argv.verbose) {
            console.error(`Invalid date argument: ${argv.date}`);
        }
    }

    const result = await validateVMC(bimiData as unknown as BIMIData, opts);
    // validateVMC() only returns false for empty input
    process.stdout.write(JSON.stringify((result as VMCValidationResult).authority, false as unknown as null, 2) + '\n');
};

export default cmd;
