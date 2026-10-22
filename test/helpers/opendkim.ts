// Runs OpenDKIM (http://www.opendkim.org/) as an independent DKIM implementation to compare
// mailauth with. The filter is run in its test mode (`opendkim -t <file>`), which processes a
// message file without an MTA and prints the header fields it would add, so a signature or an
// Authentication-Results field can be read from the output. Public keys come from a
// `TestPublicKeys` file instead of DNS, so no network access is needed.
//
// The binary is `opendkim` from PATH or /usr/sbin, or the command in the OPENDKIM environment
// variable. On a system without OpenDKIM, `test/helpers/opendkim-docker.sh` runs it in a
// container: `OPENDKIM=test/helpers/opendkim-docker.sh npm test`. The wrapper mounts the working
// directory of the call, so every file is written to one temporary directory that is also the
// working directory.
//
// The test mode reads the file line by line the way an MTA would hand the message over, which
// changes some input before libopendkim sees it, so a test message has to avoid these:
// - every line ends with CRLF: a bare LF becomes CRLF and a missing final line break is added
// - the whitespace after the colon of a header field becomes a single space (the milter
//   protocol drops it and the filter adds one back), as does a fold right after the colon
// - a NUL byte ends the line

import { Buffer } from 'node:buffer';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

interface OpendkimSignOptions {
    domain: string;
    selector: string;
    // PEM encoded private key
    privateKey: string | Buffer;
    canonicalization?: string | undefined;
    algorithm?: string | undefined;
    // SignHeaders, a list of field names
    signHeaders?: string[] | undefined;
    // OversignHeaders, a list of field names
    oversignHeaders?: string[] | undefined;
    // adds l= with the length of the body
    bodyLength?: boolean | undefined;
    // adds z= with a copy of the signed header fields
    diagnostics?: boolean | undefined;
}

interface OpendkimVerifyOptions {
    // { 'sel._domainkey.example.com': 'v=DKIM1; k=rsa; p=...' }
    keys: Record<string, string>;
}

const findOpendkim = (): string | null => {
    if (process.env.OPENDKIM) {
        return path.resolve(process.env.OPENDKIM);
    }
    let dirs = (process.env.PATH || '').split(path.delimiter).concat(['/usr/sbin', '/usr/local/sbin']);
    for (let dir of dirs) {
        let candidate = path.join(dir, 'opendkim');
        try {
            fs.accessSync(candidate, fs.constants.X_OK);
            return candidate;
        } catch {
            // not here
        }
    }
    return null;
};

const opendkimBin = findOpendkim();

// realpath, the macOS temporary directory is a symlink the container would not see the same way
const tmpDir = fs.realpathSync(os.tmpdir());

// Runs the filter on message.eml, resolves with the exit code and everything it printed. The
// test mode exits with a non-zero code when the filter returns early, before the end of the message
const run = async (files: Record<string, string | Buffer>, config: string[]): Promise<{ code: number; output: string }> => {
    if (!opendkimBin) {
        throw new Error('OpenDKIM not found');
    }
    let dir = fs.mkdtempSync(path.join(tmpDir, 'mailauth-opendkim-'));
    try {
        for (let [name, content] of Object.entries(files)) {
            // the message is a Buffer, only the tables refer to %DIR%
            fs.writeFileSync(path.join(dir, name), typeof content === 'string' ? content.replace(/%DIR%/g, dir) : content, { mode: 0o600 });
        }
        fs.writeFileSync(path.join(dir, 'opendkim.conf'), config.map(line => line.replace(/%DIR%/g, dir)).join('\n') + '\n');
        return await new Promise((resolve, reject) => {
            execFile(opendkimBin, ['-x', path.join(dir, 'opendkim.conf'), '-t', path.join(dir, 'message.eml'), '-vv'], { cwd: dir }, (err, stdout, stderr) => {
                if (err && typeof err.code !== 'number') {
                    // not started, or killed
                    return reject(err);
                }
                resolve({ code: err ? (err.code as number) : 0, output: stdout + stderr });
            });
        });
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
};

// Header fields the filter adds in test mode, as `### INSHEADER: idx=0 hname='Name' hvalue='...'`.
// The folded value uses LF line breaks, these are returned as CRLF
const addedHeaders = (output: string): Array<{ name: string; value: string }> => {
    let list: Array<{ name: string; value: string }> = [];
    let re = /^### (?:INS|ADD)HEADER: (?:idx=\d+ )?hname='([^']*)' hvalue='([^']*)'/gm;
    let match;
    while ((match = re.exec(output))) {
        list.push({ name: match[1], value: match[2].replace(/\r?\n/g, '\r\n') });
    }
    return list;
};

// Signs a message, returns the DKIM-Signature header field (without a trailing line break)
const opendkimSign = async (message: Buffer, opts: OpendkimSignOptions): Promise<string> => {
    let config = [
        'Mode s',
        // the key is used for every message, whatever its From domain
        'KeyTable %DIR%/keytable',
        'SigningTable refile:%DIR%/signingtable',
        'RequireSafeKeys false',
        `Canonicalization ${opts.canonicalization || 'relaxed/relaxed'}`,
        `SignatureAlgorithm ${opts.algorithm || 'rsa-sha256'}`
    ];
    if (opts.signHeaders) {
        config.push(`SignHeaders ${opts.signHeaders.join(',')}`);
    }
    if (opts.oversignHeaders) {
        config.push(`OversignHeaders ${opts.oversignHeaders.join(',')}`);
    }
    if (opts.bodyLength) {
        // matched against the recipients, the test mode uses a fixed one
        config.push('BodyLengthDB refile:%DIR%/bodylength');
    }
    if (opts.diagnostics) {
        config.push('Diagnostics yes');
    }
    let files = {
        'message.eml': message,
        'private.pem': opts.privateKey,
        keytable: `key ${opts.domain}:${opts.selector}:%DIR%/private.pem\n`,
        signingtable: '* key\n',
        bodylength: '*\n'
    };
    let { output } = await run(files, config);
    let header = addedHeaders(output).find(h => h.name.toLowerCase() === 'dkim-signature');
    if (!header) {
        throw new Error(`OpenDKIM did not sign the message\n${output}`);
    }
    return `DKIM-Signature: ${header.value}`;
};

// Verifies the signatures of a message, public keys come from `keys`. Resolves with the dkim=
// results of the Authentication-Results field, one per signature, or an empty list when the
// filter accepted the message without a verdict
const opendkimVerify = async (message: Buffer, opts: OpendkimVerifyOptions): Promise<string[]> => {
    let keys = Object.entries(opts.keys)
        .map(([name, record]) => `${name} ${record}`)
        .join('\n');
    let config = ['Mode v', 'AuthservID opendkim.test', 'AlwaysAddARHeader yes', 'TestPublicKeys %DIR%/keys.txt'];
    let { code, output } = await run({ 'message.eml': message, 'keys.txt': keys + '\n' }, config);
    let header = addedHeaders(output).find(h => h.name.toLowerCase() === 'authentication-results');
    if (!header) {
        if (code && /mlfi_eoh\(\) returned SMFIS_ACCEPT/.test(output)) {
            // libopendkim refused the signature header as a syntax error, the filter accepts the
            // message at the end of the header without a verdict
            return [];
        }
        throw new Error(`OpenDKIM added no Authentication-Results\n${output}`);
    }
    // not the RFC 8601 reader of auth-results-reference.ts: OpenDKIM writes an empty header.b=
    // for a signature with an empty b=, which that grammar does not allow
    return header.value
        .split(';')
        .slice(1)
        .map(resinfo => resinfo.trim().match(/^dkim=([a-z]+)/)?.[1])
        .filter((result): result is string => !!result);
};

export type { OpendkimSignOptions };
export { opendkimBin, opendkimSign, opendkimVerify };
