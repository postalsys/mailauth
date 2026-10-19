// Runs the command line interface from src/ the way bin/mailauth.cjs runs the built one. The
// CLI tests start it in a child process through tsx, so coverage maps to the sources directly;
// the built entry itself is run by test/package/cjs-smoke.cjs and test/package/pkg-smoke.cjs
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { run } from '../../src/cli.js';

run(process.argv, { root: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..') });
