/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const util = require('node:util');
const execFile = util.promisify(require('node:child_process').execFile);

const { keyRecord, rsaKey, ed25519Key } = require('../helpers/dkim2');

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
                'ed._domainkey.example.com': { TXT: [[keyRecord(ed25519Key)]] }
            })
        );
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
