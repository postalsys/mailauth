/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;
const path = require('node:path');
const util = require('node:util');
const execFile = util.promisify(require('node:child_process').execFile);

const packageData = require('../../package.json');

const CLI_PATH = path.join(__dirname, '..', '..', 'bin', 'mailauth.js');
const DENY_DNS_PATH = path.join(__dirname, '..', 'fixtures', 'deny-dns.js');
const FIXTURES_PATH = path.join(__dirname, '..', 'fixtures');

const MESSAGE = path.join(FIXTURES_PATH, 'message1.eml');
const signArgs = ['-k', path.join(FIXTURES_PATH, 'private-rsa.pem'), '-d', 'tahvel.info', '-s', 'test.rsa'];

// run the CLI in a child process where every DNS lookup is reported and rejected
const runCli = async args =>
    execFile('node', ['-r', DENY_DNS_PATH, CLI_PATH].concat(args), {
        env: Object.assign({}, process.env, { DENY_DNS: '1' })
    });

const runCliExpectingError = async args =>
    runCli(args).then(
        () => null,
        e => e
    );

describe('CLI argument handling', function () {
    this.timeout(15000);

    describe('--version', () => {
        it('should print the package version', async () => {
            let { stdout } = await runCli(['--version']);
            expect(stdout.trim()).to.equal(packageData.version);
        });
    });

    describe('numeric options', () => {
        // a non-numeric value used to be silently passed on: --max-lookups turned
        // the SPF lookup limit into a comparison against a string, which is never
        // true, and --time produced an empty t= tag
        let cases = [
            ['report --max-lookups', ['report', '--max-lookups', 'abc', MESSAGE]],
            ['report --max-void-lookups', ['report', '--max-void-lookups', 'abc', MESSAGE]],
            ['spf --max-lookups', ['spf', '-f', 'user@example.com', '-i', '192.0.2.1', '-x', 'abc']],
            ['spf --max-void-lookups', ['spf', '-f', 'user@example.com', '-i', '192.0.2.1', '-z', 'abc']],
            ['sign --time', ['sign'].concat(signArgs, ['-t', 'abc', MESSAGE])],
            ['sign --body-length', ['sign'].concat(signArgs, ['-l', 'abc', MESSAGE])],
            ['seal --instance', ['seal'].concat(signArgs, ['--auth-results', 'mx.test; spf=pass', '--instance', 'abc', MESSAGE])],
            ['bodyhash --body-length', ['bodyhash', '-l', 'abc', MESSAGE]]
        ];

        for (let [label, args] of cases) {
            it(`should reject a non-numeric value for ${label}`, async () => {
                let err = await runCliExpectingError(args);
                expect(err, args.join(' ')).to.be.an('error');
                expect(err.code, args.join(' ')).to.equal(1);
                expect(err.stderr, args.join(' ')).to.include('Not a number.');
            });
        }

        it('should not sign a message when --time is not a number', async () => {
            let err = await runCliExpectingError(['sign'].concat(signArgs, ['-t', 'abc', '-o', MESSAGE]));
            expect(err).to.be.an('error');
            expect(err.stdout).to.not.include('DKIM-Signature');
        });

        it('should still accept valid numeric values', async () => {
            let { stdout } = await runCli(['sign'].concat(signArgs, ['-t', '1700000000', '-l', '10', '-o', MESSAGE]));
            expect(stdout).to.include('t=1700000000;');
            expect(stdout).to.include('l=10;');
        });

        it('should still accept a valid bodyhash --body-length value', async () => {
            let { stdout } = await runCli(['bodyhash', '-l', '10', MESSAGE]);
            expect(stdout.trim()).to.not.be.empty;
        });
    });
});
