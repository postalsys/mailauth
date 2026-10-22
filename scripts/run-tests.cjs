'use strict';

// Runs every test/**/*-test.ts file with the Node.js test runner through tsx.
//
// The files are listed here rather than handed to the runner as a glob: Node.js expands
// a glob in a --test argument from version 21 on, so on Node 20, the oldest version
// supported, `node --test "test/**/*-test.ts"` finds nothing, and a shell expansion is no
// option for the Windows runners of the CI. Extra arguments are passed on to the runner,
// so `node scripts/run-tests.cjs --test-name-pattern=dkim` works as before.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const testDir = path.join(root, 'test');

const files = fs
    .readdirSync(testDir, { recursive: true })
    .filter(name => name.endsWith('-test.ts'))
    .sort()
    .map(name => path.join('test', name));

if (!files.length) {
    console.error('No test files found under ' + testDir);
    process.exit(1);
}

const result = spawnSync(process.execPath, ['--import', 'tsx', '--test', '--test-concurrency=1', ...process.argv.slice(2), ...files], {
    cwd: root,
    stdio: 'inherit'
});

if (result.error) {
    throw result.error;
}
process.exit(result.status ?? 1);
