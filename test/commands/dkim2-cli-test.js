/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const util = require('node:util');
const execFile = util.promisify(require('node:child_process').execFile);

const { keyRecord, rsaKey, ed25519Key, generated } = require('../helpers/dkim2');

const CLI_PATH = path.join(__dirname, '..', '..', 'bin', 'mailauth.js');
const DENY_DNS_PATH = path.join(__dirname, '..', 'fixtures', 'deny-dns.js');
const FIXTURES_PATH = path.join(__dirname, '..', 'fixtures');
const MESSAGE = path.join(FIXTURES_PATH, 'message1.eml');

const runCli = async args =>
    execFile('node', ['-r', DENY_DNS_PATH, CLI_PATH].concat(args), {
        env: Object.assign({}, process.env, { DENY_DNS: '1' }),
        maxBuffer: 10 * 1024 * 1024
    });

const keyArgs = [
    '-k',
    path.join(FIXTURES_PATH, 'private-rsa.pem'),
    '-s',
    'rsa',
    '-k',
    path.join(FIXTURES_PATH, 'private-ed25519.pem'),
    '-s',
    'ed',
    '-d',
    'example.com'
];

describe('CLI dkim2-sign and report --dkim2', function () {
    this.timeout(15000);

    let dir;
    before(async () => {
        dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'mailauth-dkim2-'));
        await fs.promises.writeFile(
            path.join(dir, 'dns.json'),
            JSON.stringify({
                'rsa._domainkey.example.com': { TXT: [[keyRecord(rsaKey)]] },
                'ed._domainkey.example.com': { TXT: [[keyRecord(ed25519Key)]] },
                'list._domainkey.list.example.org': { TXT: [[keyRecord(generated.rsa)]] }
            })
        );
        await fs.promises.writeFile(path.join(dir, 'list.key'), generated.rsa);
    });

    after(async () => {
        await fs.promises.rm(dir, { recursive: true, force: true });
    });

    it('signs a message that report --dkim2 verifies with the envelope', async () => {
        let { stdout } = await runCli([
            'dkim2-sign',
            ...keyArgs,
            '-f',
            'sender@example.com',
            '-r',
            'rcpt@example.net',
            '-r',
            'two@example.org',
            '--flag',
            'feedback',
            MESSAGE
        ]);
        expect(stdout).to.match(/^DKIM2-Signature: i=1;/);
        let signedPath = path.join(dir, 'signed.eml');
        await fs.promises.writeFile(signedPath, stdout);

        let report = await runCli([
            'report',
            '--dkim2',
            '-f',
            'sender@example.com',
            '-r',
            'two@example.org',
            '-i',
            '192.0.2.1',
            '-n',
            path.join(dir, 'dns.json'),
            signedPath
        ]);
        let result = JSON.parse(report.stdout);
        expect(result.dkim2.status.result).to.equal('pass');
        expect(result.dkim2.signatures[0].flags).to.deep.equal(['feedback']);
        expect(result.headers).to.include('dkim2=pass');

        let mismatch = await runCli([
            'report',
            '--dkim2',
            '-f',
            'sender@example.com',
            '-r',
            'nobody@example.org',
            '-i',
            '192.0.2.1',
            '-n',
            path.join(dir, 'dns.json'),
            signedPath
        ]);
        expect(JSON.parse(mismatch.stdout).dkim2.status.comment).to.equal('DKIM2-Signature i=1 RCPT TO nobody@example.org did not match');
    });

    it('prints only the header fields with --headers-only', async () => {
        let { stdout } = await runCli(['dkim2-sign', ...keyArgs, '-f', 'sender@example.com', '-r', 'rcpt@example.net', '-o', '-t', '1791626400', MESSAGE]);
        expect(stdout).to.match(/^DKIM2-Signature: i=1; m=1; t=1791626400;/);
        expect(stdout).to.match(/Message-Instance: m=1;[^]*\r\n$/);
        expect(stdout).to.not.include('Subject:');
    });

    describe('dkim2-verify', () => {
        let signedPath;
        const dnsArgs = () => ['-n', path.join(dir, 'dns.json')];

        before(async () => {
            let { stdout } = await runCli(['dkim2-sign', ...keyArgs, '-f', 'sender@example.com', '-r', 'rcpt@example.net', '-t', '1791626400', MESSAGE]);
            signedPath = path.join(dir, 'verify.eml');
            await fs.promises.writeFile(signedPath, stdout);
        });

        it('prints a JSON report and checks the envelope', async () => {
            let { stdout } = await runCli(['dkim2-verify', ...dnsArgs(), '-f', 'sender@example.com', '-r', 'rcpt@example.net', '-t', '1791630000', signedPath]);
            let result = JSON.parse(stdout);
            expect(result.status.result).to.equal('pass');
            expect(result.status).to.not.have.property('warnings');
            expect(result.signatures[0].values.map(entry => entry.result)).to.deep.equal(['pass', 'pass']);

            let nullSender = JSON.parse((await runCli(['dkim2-verify', ...dnsArgs(), '-f', '<>', '-t', '1791630000', signedPath])).stdout);
            expect(nullSender.status.comment).to.equal('DKIM2-Signature i=1 MAIL FROM <> did not match');
        });

        it('prints only the Authentication-Results entry with --headers-only, and the envelope warnings with --verbose', async () => {
            let { stdout, stderr } = await runCli(['dkim2-verify', '-v', ...dnsArgs(), '-o', '-t', '1791630000', signedPath]);
            expect(stdout).to.equal('dkim2=pass (i=1 example.com pass) header.d=example.com\n');
            expect(stderr).to.include('Warning: mail-from-not-checked');
            expect(stderr).to.include('Warning: rcpt-to-not-checked');
        });

        it('expires signatures by --time and --max-age', async () => {
            // 14 days and one second after t=
            let expired = await runCli(['dkim2-verify', ...dnsArgs(), '-o', '-t', String(1791626400 + 1209601), signedPath]);
            expect(expired.stdout).to.match(/^dkim2=permerror .*signature expired/);

            let unlimited = await runCli(['dkim2-verify', ...dnsArgs(), '-o', '-t', String(1791626400 + 1209601), '--max-age', '0', signedPath]);
            expect(unlimited.stdout).to.match(/^dkim2=pass/);

            let short = await runCli(['dkim2-verify', ...dnsArgs(), '-o', '-t', '1791630000', '--max-age', '60', signedPath]);
            expect(short.stdout).to.match(/^dkim2=permerror .*signature expired/);
        });

        it('limits the DKIM2 header fields with --max-instances', async () => {
            let { stdout } = await runCli(['dkim2-verify', ...dnsArgs(), '-o', '-t', '1791630000', '--max-instances', '0.5', signedPath]);
            expect(stdout).to.include('Message has more than 0.5 Message-Instance or DKIM2-Signature header fields');
        });

        it('reports none for a message without DKIM2', async () => {
            let { stdout } = await runCli(['dkim2-verify', '-o', MESSAGE]);
            expect(stdout).to.equal('dkim2=none\n');
        });
    });

    describe('dkim2-sign as a forwarder', () => {
        const listArgs = () => ['-k', path.join(dir, 'list.key'), '-s', 'list', '-d', 'list.example.org'];

        it('signs a revision with --recipe that dkim2-verify accepts', async () => {
            let { stdout: original } = await runCli(['dkim2-sign', ...keyArgs, '-f', 'sender@example.com', '-r', 'list@list.example.org', MESSAGE]);
            let revised = original.replace(/^Subject: /m, 'Subject: [list] ');
            let revisedPath = path.join(dir, 'revised.eml');
            await fs.promises.writeFile(revisedPath, revised);

            let subject = original.match(/^Subject: (.*)$/m)[1].replace(/\r$/, '');
            let recipePath = path.join(dir, 'recipe.json');
            await fs.promises.writeFile(recipePath, JSON.stringify({ h: { subject: [{ d: [subject] }] } }));

            let { stdout: forwarded } = await runCli([
                'dkim2-sign',
                ...listArgs(),
                '-f',
                'bounce@list.example.org',
                '-r',
                'member@example.net',
                '--recipe',
                recipePath,
                revisedPath
            ]);
            expect(forwarded).to.match(/^DKIM2-Signature: i=2; m=2;/);
            let forwardedPath = path.join(dir, 'forwarded.eml');
            await fs.promises.writeFile(forwardedPath, forwarded);

            let { stdout } = await runCli([
                'dkim2-verify',
                '-n',
                path.join(dir, 'dns.json'),
                '-f',
                'bounce@list.example.org',
                '-r',
                'member@example.net',
                '-o',
                forwardedPath
            ]);
            expect(stdout).to.equal('dkim2=pass (i=1 example.com pass, i=2 list.example.org pass) header.d=example.com\n');

            // without the recipe the changed message can not be signed
            let err = await runCli(['dkim2-sign', ...listArgs(), '-f', 'bounce@list.example.org', '-r', 'member@example.net', revisedPath]).then(
                () => null,
                err => err
            );
            expect(err.code).to.equal(1);
            expect(err.stderr).to.include('a recipe is required');
        });

        it('signs an imaginary hop with --next-domain', async () => {
            let { stdout: original } = await runCli(['dkim2-sign', ...keyArgs, '-f', 'sender@example.com', '-r', 'list@list.example.org', MESSAGE]);
            let originalPath = path.join(dir, 'nd.eml');
            await fs.promises.writeFile(originalPath, original);

            let { stdout } = await runCli([
                'dkim2-sign',
                ...listArgs(),
                '--next-domain',
                'fwd.example.net',
                '--flag',
                'feedhere',
                '--nonce',
                'abc',
                '-o',
                originalPath
            ]);
            // unfolded, the long header field is folded where it needs to be
            expect(stdout.replace(/\r\n /g, ' ')).to.match(/^DKIM2-Signature: i=2; m=1;[^]* d=list\.example\.org; nd=fwd\.example\.net; n=abc; f=feedhere;/);
            expect(stdout).to.not.include('Message-Instance');
        });
    });

    describe('dkim2-hash', () => {
        it('prints the h= hash-sets that dkim2-sign writes', async () => {
            let { stdout: signed } = await runCli([
                'dkim2-sign',
                ...keyArgs,
                '-f',
                'sender@example.com',
                '-r',
                'rcpt@example.net',
                '--hash',
                'sha256',
                '--hash',
                'sha512',
                MESSAGE
            ]);
            let instance = signed.match(/^Message-Instance:[^]*?(?=\r\n[^ \t])/m)[0].replace(/\s/g, '');
            let hashSets = instance.match(/h=([^;]+)/)[1].split(',');

            let { stdout } = await runCli(['dkim2-hash', '-a', 'sha256', '-a', 'SHA512', MESSAGE]);
            expect(stdout.trim().split('\n')).to.deep.equal(hashSets);

            // DKIM2 header fields on the message are not part of the hashes
            let signedPath = path.join(dir, 'hash.eml');
            await fs.promises.writeFile(signedPath, signed);
            let again = await runCli(['dkim2-hash', '-a', 'sha256', '-a', 'sha512', signedPath]);
            expect(again.stdout).to.equal(stdout);
        });

        it('defaults to sha256, lists the hashed header fields with --verbose, and rejects other algorithms', async () => {
            let { stdout, stderr } = await runCli(['dkim2-hash', '-v', MESSAGE]);
            expect(stdout).to.match(/^sha256:[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*\n$/);
            expect(stderr).to.include('Hashed header fields: content-type, date, from, message-id, mime-version, subject, to');

            let err = await runCli(['dkim2-hash', '-a', 'sha1', MESSAGE]).then(
                () => null,
                err => err
            );
            expect(err.code).to.equal(1);
            expect(err.stderr).to.include('Unsupported hash algorithm sha1');
        });
    });

    it('requires either an envelope or --next-domain, and a selector for every key', async () => {
        for (let args of [
            ['dkim2-sign', ...keyArgs, MESSAGE],
            ['dkim2-sign', ...keyArgs, '-f', 'sender@example.com', '-r', 'a@example.net', '--next-domain', 'example.net', MESSAGE],
            [
                'dkim2-sign',
                '-k',
                path.join(FIXTURES_PATH, 'private-rsa.pem'),
                '-k',
                path.join(FIXTURES_PATH, 'private-ed25519.pem'),
                '-s',
                'rsa',
                '-d',
                'example.com',
                '-f',
                'sender@example.com',
                '-r',
                'a@example.net',
                MESSAGE
            ]
        ]) {
            let err = await runCli(args).then(
                () => null,
                err => err
            );
            expect(err).to.be.an('error');
            expect(err.code).to.equal(1);
        }
    });
});
