import { DkimSigner } from '../dkim/dkim-signer.js';
import { writeToStream } from '../tools.js';
import fs from 'node:fs';
import type { DkimSignerSignatureData } from '../dkim/dkim-signer.js';

// the options of the bodyhash command
interface BodyhashArgv {
    email?: string | undefined;
    verbose?: boolean | undefined;
    algo?: string | undefined;
    canonicalization?: string | undefined;
    bodyLength?: number | null | undefined;
}

const cmd = async (argv: BodyhashArgv): Promise<void> => {
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

    // isNaN() converts a missing value to NaN
    if (isNaN(argv.bodyLength as number) || (argv.bodyLength as number) < 0) {
        argv.bodyLength = null;
    }

    let signatureOpts = {
        type: 'DKIM' as const,
        privateKey: true, // force hash calculation
        canonicalization: argv.canonicalization && (argv.canonicalization.includes('/') ? argv.canonicalization : `/${argv.canonicalization}`),
        algorithm: argv.algo,
        maxBodyLength: argv.bodyLength
    };

    // privateKey is only checked to be set, the signer does not sign without signingDomain and selector
    let dkimSigner = new DkimSigner({ signatureData: [signatureOpts as unknown as DkimSignerSignatureData] });

    let { hashAlgo } = dkimSigner.getAlgorithm(signatureOpts);
    let { bodyCanon } = dkimSigner.getCanonicalization(signatureOpts);

    if (argv.verbose) {
        if (hashAlgo) {
            console.error(`Hashing algorithm:               ${hashAlgo}`);
        }
        if (bodyCanon) {
            console.error(`Body canonicalization algorithm: ${bodyCanon}`);
        }
        if (signatureOpts.maxBodyLength) {
            console.error(`Maximum body length:             ${signatureOpts.maxBodyLength}`);
        }
        console.error('--------');
    }

    await writeToStream(dkimSigner, stream);

    let hashKey = `${bodyCanon}:${hashAlgo}:${typeof argv.bodyLength === 'number' ? argv.bodyLength : ''}`;
    const bodyHash = dkimSigner.bodyHashes.get(hashKey)?.hash;
    if (bodyHash) {
        process.stdout.write(bodyHash);
    }
};

export default cmd;
