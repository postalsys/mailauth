import { describe, it } from 'node:test';
import { expect } from 'chai';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

// The suite runs through tsx, which strips the types instead of checking them. These tests
// type-check consumers against the built declarations in dist/ the way an installed copy is
// resolved: the package is linked into a temporary project so that the specifiers go through
// the package.json exports map (or main and typesVersions for the node10 resolution).
const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..', '..');
const tsc = require.resolve('typescript/bin/tsc');

// The hand-written declarations that shipped with 7.x, kept as the compatibility contract
const oldTypes = path.join(root, 'test', 'fixtures', 'types-v7');

// Deliberate changes to that contract, applied to a copy of the old declarations before the
// check. Each one corrects a declaration that did not match what the code returns, and
// widens a result type, which an exhaustive switch in a consumer would notice.
const intendedChanges: { file: string; from: string; to: string; reason: string }[] = [
    {
        file: 'index.d.ts',
        from: "    | 'key-ed25519-spki';",
        to: "    | 'key-ed25519-spki'\n    | 'ams-c-default';",
        reason: 'ARC-Message-Signature results, typed DKIMResult, carry this warning when c= is missing'
    }
];

// Every function and class the old declarations announced must stay assignable to its old
// declared type: the parameters accept at least what they accepted, the results carry at
// least what they carried. Every type name they exported must still be exported.
const compatConsumer = (): string => {
    const lines: string[] = [];
    const modules: [string, string][] = [['index', 'mailauth']];
    for (const file of fs.readdirSync(path.join(oldTypes, 'lib'), { recursive: true }) as string[]) {
        if (file.endsWith('.d.ts')) {
            const name = file.slice(0, -'.d.ts'.length).split(path.sep).join('/');
            modules.push(['lib/' + name, 'mailauth/lib/' + name.replace(/\/index$/, '')]);
        }
    }
    let checked = 0;
    modules.forEach(([oldPath, specifier], i) => {
        const source = fs.readFileSync(path.join(oldTypes, oldPath + '.d.ts'), 'utf8');
        lines.push(`import type * as Old${i} from './old/${oldPath}';`);
        lines.push(`import * as New${i} from '${specifier}';`);
        for (const [, kind, name] of source.matchAll(/^export (function|class|interface|type) (\w+)/gm)) {
            if (kind === 'function' || kind === 'class') {
                lines.push(`export const _${kind}${i}_${name}: typeof Old${i}.${name} = New${i}.${name};`);
            } else {
                lines.push(`export type _${kind}${i}_${name} = New${i}.${name};`);
            }
            checked++;
        }
        // re-exports such as `export { dkim2Sign, Dkim2SignStream } from '../../index'`
        for (const [, names] of source.matchAll(/^export \{([^}]+)\} from /gm)) {
            for (const name of names.split(',').map(n => n.trim())) {
                lines.push(`export const _reexport${i}_${name}: typeof Old${i}.${name} = New${i}.${name};`);
                checked++;
            }
        }
    });
    expect(checked).to.be.greaterThan(80);
    return lines.join('\n') + '\n';
};

// The documented idioms of the README and docs/
const consumer = `
import { authenticate, dkimSign, DkimSignStream, dkimVerify, spf, dmarc, arc, sealMessage, bimi, validateBimiSvg } from 'mailauth';
import mailauth from 'mailauth';
import type { AuthenticateOptions, AuthenticateResult, DKIMVerifyResult, SPFResult, DNSResolver } from 'mailauth';
import { spf as spfDeep } from 'mailauth/lib/spf';
import { dkimVerify as dkimVerifyDeep } from 'mailauth/lib/dkim/verify';
import { dkimSign as dkimSignDeep } from 'mailauth/lib/dkim/sign';
import { getPolicy, validateMx } from 'mailauth/lib/mta-sts';
import { parseReceived } from 'mailauth/lib/parse-received';
import { bimi as bimiDeep, validateVMC } from 'mailauth/lib/bimi';
import { dmarc as dmarcDeep } from 'mailauth/lib/dmarc';
import { arc as arcDeep } from 'mailauth/lib/arc';
import { dkim2Sign } from 'mailauth/lib/dkim2/sign';
import { dkim2Verify } from 'mailauth/lib/dkim2/verify';
import { Readable } from 'node:stream';

declare const message: Buffer;
const resolver: DNSResolver = async (name, rr) => [[name + rr]];

export async function run(): Promise<void> {
    const opts: AuthenticateOptions = { ip: '192.0.2.1', helo: 'mx.example.com', sender: 'a@example.com', mta: 'mx.example.net', resolver };
    const result: AuthenticateResult = await authenticate(message, opts);
    const fromStream = await mailauth.authenticate(Readable.from(message), { trustReceived: true });
    result.headers.length;
    fromStream.dkim.results.forEach(r => r.status.result);
    result.spf && result.spf.status.result;
    result.dmarc && result.dmarc.status.result;

    const signed = await dkimSign(message, {
        signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: '-----BEGIN PRIVATE KEY-----' }]
    });
    signed.signatures.length;
    const stream = new DkimSignStream({ signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: 'key' }] });
    Readable.from(message).pipe(stream);

    const verified: DKIMVerifyResult = await dkimVerify(message, { resolver });
    verified.results.length;
    const spfResult: SPFResult = await spf({ sender: 'a@example.com', ip: '192.0.2.1', helo: 'mx.example.com', resolver });
    spfResult.header.length;
    await spfDeep({ sender: 'a@example.com', ip: '192.0.2.1', maxElapsedTime: 1000, strict: true });
    await dkimVerifyDeep(message);
    await dkimSignDeep(message, { signatureData: [] });
    await dmarc({ headerFrom: 'a@example.com', spfDomains: [], dkimDomains: [], resolver });
    await dmarcDeep({ headerFrom: 'a@example.com', strict: true });
    await arc({ chain: false }, { resolver });
    await arcDeep({ chain: false });
    await sealMessage(message, { signingDomain: 'example.com', selector: 's', privateKey: 'k', authResults: 'x', cv: 'none' });
    await bimi({ dmarc: false, headers: { parsed: [] }, resolver });
    await bimiDeep({ dmarc: false, headers: { parsed: [] } });
    await validateVMC(null);
    validateBimiSvg('<svg/>');
    const policy = await getPolicy('example.com', null, { resolver });
    policy.policy && validateMx('mx.example.com', policy.policy);
    validateMx('mx.example.com', null);
    await authenticate(message, { resolver, maxResolveCount: 5, maxVoidCount: 1, maxElapsedTime: 2000 });
    parseReceived('from a by b');
    await dkim2Sign(message, { signingDomain: 'example.com', mailFrom: 'a@example.com', rcptTo: ['b@example.net'], signatureData: [{ selector: 's', privateKey: 'k' }] });
    await dkim2Verify(message, { resolver });
}
`;

// Every optional property is declared as \`T | undefined\` so that an explicit undefined is
// still accepted under exactOptionalPropertyTypes. OptionalKeys picks the keys that may be
// left out, and MissingUndefined keeps the ones that do not accept undefined
const exactOptionalConsumer = (typeNames: string[]): string => `
import type * as T from 'mailauth';

type OptionalKeys<T> = Extract<{ [K in keyof T]-?: object extends Pick<T, K> ? K : never }[keyof T], string>;
type MissingUndefined<T> = { [K in OptionalKeys<T>]-?: { [P in K]: undefined } extends Pick<T, K> ? never : K }[OptionalKeys<T>];
type NoneMissing<T extends never> = T;

${typeNames.map(name => `type _${name} = NoneMissing<MissingUndefined<T.${name}>>;`).join('\n')}

declare const maybeString: string | undefined;
declare const maybeBoolean: boolean | undefined;
export const options: T.AuthenticateOptions = { ip: maybeString, helo: maybeString, sender: maybeString, mta: maybeString, trustReceived: maybeBoolean };
`;

// node16 is what an installed copy resolves through the exports map, bundler is what the
// common front end tool chains use, and node10 is the default of a plain CommonJS project on
// older TypeScript, which resolves through main and typesVersions instead of the exports map
const node16 = { module: 'node16', moduleResolution: 'node16' };
const node10 = { module: 'commonjs', moduleResolution: 'node10', ignoreDeprecations: '6.0' };
const resolutions = [node16, { module: 'esnext', moduleResolution: 'bundler' }, node10];

const typeCheckConsumer = (sources: { [file: string]: string }, compilerOptions: { [key: string]: unknown }, include?: string[]): void => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mailauth-types-'));
    try {
        fs.mkdirSync(path.join(dir, 'node_modules'));
        // link the package itself and the node typings a real consumer has
        fs.symlinkSync(root, path.join(dir, 'node_modules', 'mailauth'), 'dir');
        fs.symlinkSync(path.join(root, 'node_modules', '@types'), path.join(dir, 'node_modules', '@types'), 'dir');
        fs.cpSync(oldTypes, path.join(dir, 'old'), { recursive: true });
        for (const change of intendedChanges) {
            const file = path.join(dir, 'old', change.file);
            const source = fs.readFileSync(file, 'utf8');
            expect(source, change.reason).to.include(change.from);
            fs.writeFileSync(file, source.replace(change.from, change.to));
        }
        for (const [file, text] of Object.entries(sources)) {
            fs.writeFileSync(path.join(dir, file), text);
        }
        fs.writeFileSync(
            path.join(dir, 'tsconfig.json'),
            JSON.stringify({
                compilerOptions: {
                    target: 'ES2022',
                    lib: ['ES2023'],
                    types: ['node'],
                    strict: true,
                    noEmit: true,
                    skipLibCheck: true,
                    esModuleInterop: true,
                    noErrorTruncation: true,
                    ...compilerOptions
                },
                include: include || Object.keys(sources)
            })
        );
        const result = spawnSync(process.execPath, [tsc, '-p', path.join(dir, 'tsconfig.json')], { encoding: 'utf8' });
        expect(result.status, 'tsc reported\n' + result.stdout + result.stderr).to.equal(0);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
};

describe('Built package types', { timeout: 180 * 1000 }, () => {
    for (const resolution of resolutions) {
        it('type-checks the documented idioms with moduleResolution ' + resolution.moduleResolution, () => {
            typeCheckConsumer({ 'consumer.ts': consumer }, resolution);
        });
    }

    it('keeps every function, class and type of the 7.x declarations assignable', () => {
        typeCheckConsumer({ 'compat.ts': compatConsumer() }, node16);
    });

    it('accepts an explicit undefined for optional properties with exactOptionalPropertyTypes', () => {
        const declarations = fs.readFileSync(path.join(root, 'dist', 'cjs', 'types.d.ts'), 'utf8');
        const names = [...declarations.matchAll(/^export interface (\w+)/gm)].map(match => match[1]);
        expect(names.length).to.be.greaterThan(40);
        typeCheckConsumer({ 'consumer.ts': exactOptionalConsumer(names) }, { ...node16, exactOptionalPropertyTypes: true });
    });

    // The consumer checks above run with skipLibCheck, which hides a broken reference inside
    // the declarations. This type-checks every built declaration file itself
    it('type-checks the built declarations themselves', () => {
        typeCheckConsumer({ 'empty.ts': 'export {};\n' }, { ...node16, skipLibCheck: false }, ['empty.ts', path.join(root, 'dist', '**', '*.d.ts')]);
    });
});
