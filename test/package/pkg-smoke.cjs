'use strict';

// Builds single-file executables with @yao-pkg/pkg the way EmailEngine and the mailauth
// release binaries are built, and runs them. `npm run test:pkg` (slow: pkg downloads a
// prebuilt Node.js binary on first use, so it is not part of `npm test`).
//
// 1. The package is packed with `npm pack` (dist/ is built by the pretest:pkg script) and installed into a scratch application, so
//    only the published files take part and the `exports` map is resolved the way an
//    installed copy resolves it. The application requires mailauth, deep imports included,
//    and runs authenticate() inside the binary.
// 2. The mailauth CLI itself is packaged from bin/mailauth.cjs and run.
//
// pkg snapshots a CommonJS require() graph and can not load ES modules, so either binary
// fails at startup when an ES module creeps into the graph.

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '..', '..');
const pkg = require(path.join(root, 'package.json'));
const pkgBin = require.resolve('@yao-pkg/pkg/lib-es5/bin.js');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

const target = `node${process.versions.node.split('.')[0]}-${{ darwin: 'macos', win32: 'win' }[process.platform] || process.platform}-${process.arch}`;
const exe = name => (process.platform === 'win32' ? name + '.exe' : name);

const run = (cmd, args, opts) =>
    execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], shell: process.platform === 'win32', ...opts });

const app = `'use strict';
const crypto = require('node:crypto');
const { authenticate, dkimSign } = require('mailauth');
const { spf } = require('mailauth/lib/spf');
const { parseReceived } = require('mailauth/lib/parse-received');
const getDmarcRecord = require('mailauth/lib/dmarc/get-dmarc-record');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const zone = {
    'test._domainkey.example.com:TXT': [['v=DKIM1; k=rsa; p=' + publicKey.export({ type: 'spki', format: 'der' }).toString('base64')]],
    'example.com:TXT': [['v=spf1 ip4:192.0.2.1 -all']],
    '_dmarc.example.com:TXT': [['v=DMARC1; p=reject']]
};
const resolver = async (name, type) => {
    const answer = zone[name.toLowerCase() + ':' + type];
    if (!answer) {
        const err = new Error('ENOTFOUND ' + name);
        err.code = 'ENOTFOUND';
        throw err;
    }
    return answer;
};

(async () => {
    const message = Buffer.from('From: sender@example.com\\r\\nTo: rcpt@example.net\\r\\nSubject: pkg\\r\\n\\r\\nHello\\r\\n');
    const signed = await dkimSign(message, { signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: privateKey.export({ type: 'pkcs1', format: 'pem' }) }] });
    const result = await authenticate(Buffer.concat([Buffer.from(signed.signatures), message]), { ip: '192.0.2.1', helo: 'mx.example.com', sender: 'sender@example.com', mta: 'mx.example.net', resolver });
    const spfResult = await spf({ sender: 'sender@example.com', ip: '192.0.2.1', helo: 'mx.example.com', resolver });
    console.log(JSON.stringify({
        dkim: result.dkim.results[0].status.result,
        spf: result.spf.status.result,
        dmarc: result.dmarc.status.result,
        deepSpf: spfResult.status.result,
        received: !!parseReceived('from a.example (a.example [192.0.2.1]) by b.example; Mon, 19 Oct 2026 10:00:00 +0000'),
        dmarcRecord: typeof getDmarcRecord.parseDmarcRecord
    }));
})().catch(err => {
    console.error(err);
    process.exit(1);
});
`;

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mailauth-pkg-'));
try {
    // 1. An application that depends on the packed package
    const tarball = run(npm, ['pack', '--ignore-scripts', '--pack-destination', dir, '--silent'], { cwd: root }).trim().split('\n').pop();
    const appDir = path.join(dir, 'app');
    fs.mkdirSync(appDir);
    fs.writeFileSync(path.join(appDir, 'package.json'), JSON.stringify({ name: 'pkg-smoke', version: '1.0.0', private: true, bin: 'app.js' }, null, 2));
    fs.writeFileSync(path.join(appDir, 'app.js'), app);
    run(npm, ['install', '--omit=dev', '--no-audit', '--no-fund', '--silent', path.join(dir, tarball)], { cwd: appDir });

    run(process.execPath, [pkgBin, 'app.js', '--targets', target, '--output', exe('app-bin')], { cwd: appDir });
    const output = JSON.parse(run(path.join(appDir, exe('app-bin')), [], { cwd: os.tmpdir() }));
    assert.deepStrictEqual(output, { dkim: 'pass', spf: 'pass', dmarc: 'pass', deepSpf: 'pass', received: true, dmarcRecord: 'function' });
    console.log('pkg: application binary ok', output);

    // 2. The mailauth CLI, packaged from the repository the way build-dist does it
    const cliOut = path.join(dir, exe('mailauth'));
    run(process.execPath, [pkgBin, path.join(root, 'package.json'), '--targets', target, '--output', cliOut], { cwd: root });
    assert.strictEqual(run(cliOut, ['--version']).trim(), pkg.version);
    const help = run(cliOut, ['--help']);
    assert.match(help, /dkim2-verify/);
    console.log('pkg: CLI binary ok');
} finally {
    fs.rmSync(dir, { recursive: true, force: true });
}
