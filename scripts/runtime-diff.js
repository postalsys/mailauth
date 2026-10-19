// Compares the JavaScript that src/ compiles to with a baseline copy of the sources, to
// show every runtime change a refactor or a typing pass made. Types and comments are
// erased from both sides the same way and both are formatted with Prettier, so only
// changes to emitted code are reported.
//
// Usage: node scripts/runtime-diff.js <baseline-dir> [src/file.ts ...]
// Without files every .ts file under src/ is compared. Exits with 1 when a file differs.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import prettier from 'prettier';
import ts from 'typescript';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const [baselineDir, ...files] = process.argv.slice(2);

if (!baselineDir) {
    console.error('Usage: node scripts/runtime-diff.js <baseline-dir> [src/file.ts ...]');
    process.exit(2);
}

const prettierOptions = { ...(await prettier.resolveConfig(path.join(root, 'src', 'x.ts'))), parser: 'babel' };

async function erase(source, fileName) {
    const { outputText } = ts.transpileModule(source, {
        fileName,
        compilerOptions: {
            target: ts.ScriptTarget.ES2022,
            module: ts.ModuleKind.ESNext,
            removeComments: true,
            verbatimModuleSyntax: false,
            useDefineForClassFields: false
        }
    });
    return prettier.format(outputText, prettierOptions);
}

const targets = files.length
    ? files.map(file => path.relative(path.join(root, 'src'), path.resolve(file)))
    : fs.readdirSync(path.join(root, 'src'), { recursive: true }).filter(name => name.endsWith('.ts') && !name.endsWith('.d.ts') && name !== 'package-info.ts');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-diff-'));
let changed = 0;

for (const name of targets.sort()) {
    const current = path.join(root, 'src', name);
    const baseline = path.join(path.resolve(baselineDir), name);
    const a = fs.existsSync(baseline) ? await erase(fs.readFileSync(baseline, 'utf8'), baseline) : '';
    const b = fs.existsSync(current) ? await erase(fs.readFileSync(current, 'utf8'), current) : '';
    if (a === b) {
        continue;
    }
    changed++;
    const aFile = path.join(tmp, 'a.js');
    const bFile = path.join(tmp, 'b.js');
    fs.writeFileSync(aFile, a);
    fs.writeFileSync(bFile, b);
    const diff = spawnSync('diff', ['-u', '--label', 'baseline/' + name, '--label', 'src/' + name, aFile, bFile], { encoding: 'utf8' });
    process.stdout.write(diff.stdout);
}

fs.rmSync(tmp, { recursive: true, force: true });
console.error(changed ? `${changed} file(s) with runtime changes` : 'No runtime changes');
process.exit(changed ? 1 : 0);
