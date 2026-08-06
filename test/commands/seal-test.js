/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const util = require('node:util');
const execFile = util.promisify(require('node:child_process').execFile);

const { authenticate } = require('../../lib/mailauth');
const { dkimTxtRecord } = require('../helpers/keys');
const { zoneResolver } = require('../helpers/dns-zone');

const CLI_PATH = path.join(__dirname, '..', '..', 'bin', 'mailauth.js');
const DENY_DNS_PATH = path.join(__dirname, '..', 'fixtures', 'deny-dns.js');
const FIXTURES_PATH = path.join(__dirname, '..', 'fixtures');

const AUTH_RESULTS = 'mx.shield.test; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass header.from=example.com';

// run the CLI in a child process where every DNS lookup is reported and rejected
const runSeal = async args =>
    execFile('node', ['-r', DENY_DNS_PATH, CLI_PATH, 'seal'].concat(args), {
        env: Object.assign({}, process.env, { DENY_DNS: '1' })
    });

const keyArgs = ['-k', path.join(FIXTURES_PATH, 'private-rsa.pem'), '-d', 'tahvel.info', '-s', 'test.rsa'];

// resolver that only knows the public key for the sealing selector
const resolver = zoneResolver({ 'test.rsa._domainkey.tahvel.info': { TXT: [[dkimTxtRecord('public-rsa.pem')]] } });

describe('CLI seal command', function () {
    this.timeout(15000);

    let tmpDir;

    before(async () => {
        tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'mailauth-seal-test-'));
    });

    after(async () => {
        await fs.promises.rm(tmpDir, { recursive: true, force: true });
    });

    describe('seal-only mode (--auth-results)', () => {
        it('should seal with the provided Authentication-Results without performing DNS lookups', async () => {
            let { stdout, stderr } = await runSeal(keyArgs.concat(['--auth-results', AUTH_RESULTS, '-o', path.join(FIXTURES_PATH, 'message1.eml')]));

            expect(stderr).to.not.include('DNS_LOOKUP_ATTEMPTED');

            expect(stdout).to.match(/^ARC-Seal: i=1;/m);
            expect(stdout).to.match(/^ARC-Message-Signature: i=1;/m);
            expect(stdout).to.include('cv=none');
            expect(stdout).to.include(`ARC-Authentication-Results: i=1; ${AUTH_RESULTS}`);
        });

        it('should read the Authentication-Results value from a file', async () => {
            let authResultsFile = path.join(tmpDir, 'auth-results.txt');
            let multiLineValue =
                'mx.shield.test;\r\n spf=pass smtp.mailfrom=example.com;\r\n dkim=pass header.i=@example.com;\r\n dmarc=pass header.from=example.com';
            await fs.promises.writeFile(authResultsFile, multiLineValue + '\r\n');

            let { stdout, stderr } = await runSeal(
                keyArgs.concat(['--auth-results-file', authResultsFile, '--cv', 'none', '-o', path.join(FIXTURES_PATH, 'message1.eml')])
            );

            expect(stderr).to.not.include('DNS_LOOKUP_ATTEMPTED');
            expect(stdout).to.include(`ARC-Authentication-Results: i=1; ${multiLineValue}`);
        });

        it('should produce a seal that validates against the original message', async () => {
            let { stdout } = await runSeal(keyArgs.concat(['--auth-results', AUTH_RESULTS, path.join(FIXTURES_PATH, 'message1.eml')]));

            // without --headers-only the output is the sealed headers followed by the full message
            let res = await authenticate(Buffer.from(stdout, 'binary'), {
                ip: '127.0.0.1',
                helo: 'example.com',
                mta: 'example.com',
                disableDmarc: true,
                resolver
            });

            expect(res.arc.status.result).to.equal('pass');
        });

        it('should extend an existing ARC chain with the provided cv value', async () => {
            let { stdout, stderr } = await runSeal(
                keyArgs.concat(['--auth-results', AUTH_RESULTS, '--cv', 'pass', '-o', path.join(FIXTURES_PATH, 'arc-pass.eml')])
            );

            expect(stderr).to.not.include('DNS_LOOKUP_ATTEMPTED');

            // arc-pass.eml already carries an ARC chain with instances 1 and 2
            expect(stdout).to.match(/^ARC-Seal: i=3;/m);
            expect(stdout).to.match(/^ARC-Message-Signature: i=3;/m);
            expect(stdout).to.include('cv=pass');
            expect(stdout).to.include(`ARC-Authentication-Results: i=3; ${AUTH_RESULTS}`);
        });

        it('should use an explicitly provided instance number', async () => {
            let { stdout } = await runSeal(keyArgs.concat(['--auth-results', AUTH_RESULTS, '--instance', '5', '-o', path.join(FIXTURES_PATH, 'message1.eml')]));

            expect(stdout).to.match(/^ARC-Seal: i=5;/m);
            expect(stdout).to.include(`ARC-Authentication-Results: i=5; ${AUTH_RESULTS}`);
        });

        it('should reject using --auth-results and --auth-results-file together', async () => {
            let err = await runSeal(
                keyArgs.concat(['--auth-results', AUTH_RESULTS, '--auth-results-file', 'whatever.txt', '-o', path.join(FIXTURES_PATH, 'message1.eml')])
            ).then(
                () => null,
                e => e
            );
            expect(err).to.be.an('error');
        });

        it('should reject an empty --auth-results value instead of silently authenticating', async () => {
            let err = await runSeal(keyArgs.concat(['--auth-results', '', '-o', path.join(FIXTURES_PATH, 'message1.eml')])).then(
                () => null,
                e => e
            );
            expect(err).to.be.an('error');
            expect(err.stderr).to.include('--auth-results must not be empty');
        });

        it('should reject --cv and --instance without --auth-results', async () => {
            for (let extra of [
                ['--cv', 'pass'],
                ['--instance', '2']
            ]) {
                let err = await runSeal(keyArgs.concat(extra, ['-o', path.join(FIXTURES_PATH, 'message1.eml')])).then(
                    () => null,
                    e => e
                );
                expect(err, extra.join(' ')).to.be.an('error');
                expect(err.stderr, extra.join(' ')).to.include('can only be used together with');
            }
        });

        it('should warn when sealing an existing chain with the default cv=none', async () => {
            let { stderr } = await runSeal(keyArgs.concat(['--auth-results', AUTH_RESULTS, '-o', path.join(FIXTURES_PATH, 'arc-pass.eml')]));
            expect(stderr).to.include('only validates when cv=pass');
        });
    });

    describe('default mode (backward compatibility)', () => {
        it('should authenticate and seal when no auth-results option is provided', async () => {
            let dnsCacheFile = path.join(tmpDir, 'dns-cache.json');
            await fs.promises.writeFile(dnsCacheFile, '{}');

            let { stdout } = await runSeal(keyArgs.concat(['--dns-cache', dnsCacheFile, path.join(FIXTURES_PATH, 'message1.eml')]));

            // the authenticate() path computes its own Authentication-Results header
            expect(stdout).to.match(/^Authentication-Results:/m);
            expect(stdout).to.match(/^ARC-Seal: i=1;/m);
            expect(stdout).to.match(/^ARC-Authentication-Results: i=1;/m);
        });
    });
});
