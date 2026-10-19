'use strict';

// CommonJS smoke test for the built package, run by `npm run test:cjs` as plain Node with
// --no-experimental-require-module. EmailEngine bundles mailauth into a @yao-pkg/pkg binary,
// and the mailauth CLI is shipped as one too. pkg can only load a CommonJS module graph, and
// Node 22+ enables require(esm) by default, which would hide an ES module reached through
// require(). With the flag set, such a module throws ERR_REQUIRE_ESM here instead of in the
// binary. Kept as plain JavaScript on purpose: running it through tsx would let its loader
// transpile an ES module to CommonJS and mask exactly the failure this guards against.

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '..', '..');
const pkg = require(path.join(root, 'package.json'));

if (!process.execArgv.includes('--no-experimental-require-module') && !/--no-experimental-require-module/.test(process.env.NODE_OPTIONS || '')) {
    throw new Error('Run with --no-experimental-require-module (npm run test:cjs)');
}

// A resolver over a fixed zone, the way consumers plug in their own DNS
const zone = new Map();
const resolver = async (name, type) => {
    let key = `${name.toLowerCase().replace(/\.$/, '')}:${type}`;
    if (!zone.has(key)) {
        let err = new Error(`No ${type} record for ${name}`);
        err.code = 'ENOTFOUND';
        throw err;
    }
    return zone.get(key);
};

async function run() {
    const mailauth = require(path.join(root, pkg.exports['.'].require));
    assert.strictEqual(require('mailauth'), mailauth);
    assert.strictEqual(typeof mailauth.authenticate, 'function');

    // Every module of the CommonJS build, the way deep imports load them
    let cjsRoot = path.join(root, 'dist', 'cjs');
    let modules = fs.readdirSync(cjsRoot, { recursive: true }).filter(name => name.endsWith('.js'));
    assert.ok(modules.length > 50, 'expected the compiled modules under dist/cjs');
    for (let name of modules) {
        require('mailauth/lib/' + name.split(path.sep).join('/'));
    }
    for (let name of Object.keys(pkg.exports)) {
        if (/^\.\/lib\/[^*]+$/.test(name)) {
            require('mailauth' + name.slice(1));
        }
    }

    // DKIM signing and verification, and the whole authenticate() pipeline
    let { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    let publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    zone.set('test._domainkey.example.com:TXT', [[`v=DKIM1; k=rsa; p=${publicKeyB64}`]]);
    zone.set('example.com:TXT', [['v=spf1 ip4:192.0.2.1 -all']]);
    zone.set('_dmarc.example.com:TXT', [['v=DMARC1; p=reject']]);

    let message = Buffer.from(
        [
            'From: Sender <sender@example.com>',
            'To: recipient@example.net',
            'Subject: CommonJS smoke test',
            'Date: Mon, 19 Oct 2026 10:00:00 +0000',
            'Message-ID: <smoke@example.com>',
            '',
            'Hello from the CommonJS build',
            ''
        ].join('\r\n')
    );

    let signed = await mailauth.dkimSign(message, {
        signatureData: [{ signingDomain: 'example.com', selector: 'test', privateKey: privateKey.export({ type: 'pkcs1', format: 'pem' }) }]
    });
    assert.deepStrictEqual(signed.errors, []);
    let signedMessage = Buffer.concat([Buffer.from(signed.signatures), message]);

    let verified = await require('mailauth/lib/dkim/verify').dkimVerify(signedMessage, { resolver });
    assert.strictEqual(verified.results[0].status.result, 'pass');

    let result = await mailauth.authenticate(signedMessage, {
        ip: '192.0.2.1',
        helo: 'mx.example.com',
        sender: 'sender@example.com',
        mta: 'mx.example.net',
        resolver
    });
    assert.strictEqual(result.dkim.results[0].status.result, 'pass');
    assert.strictEqual(result.spf.status.result, 'pass');
    assert.strictEqual(result.dmarc.status.result, 'pass');
    assert.match(result.headers, /^Authentication-Results: mx\.example\.net;/m);

    // ARC sealing
    let sealed = await mailauth.sealMessage(signedMessage, {
        signingDomain: 'example.com',
        selector: 'test',
        privateKey: privateKey.export({ type: 'pkcs1', format: 'pem' }),
        authResults: result.arc.authResults,
        cv: result.arc.status.result
    });
    assert.match(sealed.toString(), /^ARC-Seal: i=1;/m);

    // Default-export deep modules load as the function itself
    let getDmarcRecord = require('mailauth/lib/dmarc/get-dmarc-record');
    assert.strictEqual(typeof getDmarcRecord, 'function');
    assert.strictEqual(typeof getDmarcRecord.parseDmarcRecord, 'function');
    assert.strictEqual(typeof require('mailauth/lib/parse-dkim-headers').parseTagList, 'function');

    // Received parsing and MTA-STS policy parsing through their deep imports
    let { parseReceived } = require('mailauth/lib/parse-received');
    assert.ok(parseReceived('from mx.example.com (mx.example.com [192.0.2.1]) by mx.example.net with ESMTPS id abc; Mon, 19 Oct 2026 10:00:00 +0000'));
    let { parsePolicy } = require('mailauth/lib/mta-sts');
    assert.strictEqual(parsePolicy('version: STSv1\r\nmode: enforce\r\nmx: mx.example.com\r\nmax_age: 86400\r\n').mode, 'enforce');

    // The command line entry, loaded the way the pkg binary loads it
    let dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mailauth-cjs-'));
    try {
        let keyFile = path.join(dir, 'key.pem');
        let emlFile = path.join(dir, 'message.eml');
        fs.writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }));
        fs.writeFileSync(emlFile, message);
        let cli = path.join(root, pkg.bin.mailauth);
        let execArgv = ['--no-experimental-require-module'];
        assert.strictEqual(execFileSync(process.execPath, execArgv.concat([cli, '--version']), { encoding: 'utf8' }).trim(), pkg.version);
        let output = execFileSync(process.execPath, execArgv.concat([cli, 'sign', emlFile, '-k', keyFile, '-d', 'example.com', '-s', 'test', '-o']), {
            encoding: 'utf8'
        });
        assert.match(output, /^DKIM-Signature: v=1; a=rsa-sha256; c=relaxed\/relaxed; d=example\.com;/);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

run()
    .then(() => {
        console.log('CommonJS smoke test passed');
    })
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
