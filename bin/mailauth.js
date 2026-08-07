#!/usr/bin/env node

'use strict';

const { Command, InvalidArgumentError, Option } = require('commander');
const os = require('node:os');

const commandReport = require('../lib/commands/report');
const commandSign = require('../lib/commands/sign');
const commandSeal = require('../lib/commands/seal');
const commandSpf = require('../lib/commands/spf');
const commandVmc = require('../lib/commands/vmc');
const commandBodyhash = require('../lib/commands/bodyhash');

const fs = require('node:fs');
const pathlib = require('node:path');

const packageData = require('../package.json');

// Commander hands every option value over as a string, so numeric options have
// to be coerced. A value that is not a number is rejected instead of being
// passed on: a non-numeric --max-lookups would disable the SPF lookup limit
// entirely, and a non-numeric --time would produce an empty t= tag.
const numberArg = value => {
    let num = Number(value);
    if (isNaN(num)) {
        throw new InvalidArgumentError('Not a number.');
    }
    return num;
};

// Repeating a single-value option is a mistake worth reporting instead of
// silently keeping the last occurrence. Wraps whatever parser the option
// already has (`.choices()` installs one) so its validation still runs.
const rejectRepeated = option => {
    let parseArg = option.parseArg;
    return option.argParser((value, previous) => {
        if (previous !== undefined) {
            throw new InvalidArgumentError(`--${option.name()} can only be provided once`);
        }
        return parseArg ? parseArg(value, previous) : value;
    });
};

// Wrap an async command implementation with the shared promise handling used by
// every subcommand: merge the positional `email` argument with the parsed
// options (including the global --verbose flag) into a single `argv` object.
const runCommand = (fn, failMessage) =>
    function () {
        let command = arguments[arguments.length - 1];
        let positional = Array.prototype.slice.call(arguments, 0, arguments.length - 2);

        let argv = Object.assign({}, command.optsWithGlobals());
        if (command.registeredArguments && command.registeredArguments.length) {
            command.registeredArguments.forEach((arg, i) => {
                argv[arg.name()] = positional[i];
            });
        }

        fn(argv)
            .then(() => {
                process.exit();
            })
            .catch(err => {
                if (!err || !err.suppress) {
                    console.error(failMessage);
                    console.error(err);
                }
                process.exit(1);
            });
    };

const emailArgDescription = 'Path to the email message file in EML format. If not specified, the content is read from standard input.';

const program = new Command();

program
    .name('mailauth')
    .description('Email authentication tools for Node.js')
    // yargs registered --version automatically, commander does not
    .version(packageData.version, '--version', 'Show version number.')
    .option('-v, --verbose', 'Enable verbose logging for debugging purposes.')
    // sign/seal use -h as an alias for --header-fields, so free it up from the
    // built-in help option and expose help via --help only.
    .helpOption('--help', 'Show help.');

program
    .command('report', { isDefault: true })
    .description('Validate an email message and return a detailed JSON report')
    .argument('[email]', emailArgDescription)
    .helpOption('--help', 'Show help.')
    .option('-i, --client-ip <ip>', 'IP address of the remote client (used for SPF checks). If not provided, it is parsed from the latest Received header.')
    .option(
        '-m, --mta <hostname>',
        'Hostname of the server performing the validation (used in the Authentication-Results header). Defaults to the local hostname.',
        os.hostname()
    )
    .option('-e, --helo <hostname>', 'Client hostname from the HELO/EHLO command (used in some SPF checks).')
    .option('-f, --sender <address>', 'Email address from the MAIL FROM command. If not provided, the address from the latest Return-Path header is used.')
    .option(
        '-n, --dns-cache <file>',
        'Path to a JSON file with cached DNS responses. When provided, DNS queries use these cached responses instead of performing actual DNS lookups.'
    )
    .option('-x, --max-lookups <number>', 'Maximum allowed DNS lookups during SPF checks. Defaults to 10.', numberArg, 10)
    .option('-z, --max-void-lookups <number>', 'Maximum allowed DNS lookups that return no data (void lookups) during SPF checks. Defaults to 2.', numberArg, 2)
    .action(runCommand(commandReport, 'Failed to generate report for the input message.'));

program
    .command('sign')
    .description('Sign an email with a DKIM digital signature')
    .argument('[email]', emailArgDescription)
    .helpOption('--help', 'Show help.')
    .requiredOption('-k, --private-key <file>', 'Path to the private key file used for signing.')
    .requiredOption('-d, --domain <domain>', 'Domain name to use in the DKIM signature (d= tag).')
    .requiredOption('-s, --selector <selector>', 'Selector to use in the DKIM signature (s= tag).')
    .option('-a, --algo <algorithm>', 'Signing algorithm. Defaults to "rsa-sha256" or "ed25519-sha256" depending on the private key type.', 'rsa-sha256')
    .option('-c, --canonicalization <method>', 'Canonicalization method (c= tag). Defaults to "relaxed/relaxed".', 'relaxed/relaxed')
    .option('-t, --time <timestamp>', 'Signing time as a UNIX timestamp (t= tag). Defaults to the current time.', numberArg)
    .option(
        '-l, --body-length <number>',
        'Maximum length of the canonicalized body to include in the signature (l= tag). Not recommended for general use.',
        numberArg
    )
    .option('-h, --header-fields <fields>', 'Colon-separated list of header field names to include in the signature (h= tag).')
    .option('-o, --headers-only', 'If set, outputs only the DKIM signature headers without the message body.')
    .action(runCommand(commandSign, 'Failed to sign the input message.'));

program
    .command('seal')
    .description('Authenticate and seal an email with an ARC digital signature')
    .argument('[email]', emailArgDescription)
    .helpOption('--help', 'Show help.')
    .requiredOption('-k, --private-key <file>', 'Path to the private key file used for sealing.')
    .requiredOption('-d, --domain <domain>', 'Domain name to use in the ARC seal (d= tag).')
    .requiredOption('-s, --selector <selector>', 'Selector to use in the ARC seal (s= tag).')
    .option(
        '-a, --algo <algorithm>',
        'Sealing algorithm. Defaults to "rsa-sha256" or "ed25519-sha256" depending on the private key type. Note: RFC8617 only allows "rsa-sha256" (a= tag).',
        'rsa-sha256'
    )
    .option('-c, --canonicalization <method>', 'Canonicalization method. Note: RFC8617 only allows "relaxed/relaxed" (c= tag).', 'relaxed/relaxed')
    .option('-t, --time <timestamp>', 'Sealing time as a UNIX timestamp (t= tag). Defaults to the current time.', numberArg)
    .option('-h, --header-fields <fields>', 'Colon-separated list of header field names to include in the seal (h= tag).')
    .option('-i, --client-ip <ip>', 'IP address of the remote client (used for SPF checks). If not provided, it is parsed from the latest Received header.')
    .option(
        '-m, --mta <hostname>',
        'Hostname of the server performing the validation (used in the Authentication-Results header). Defaults to the local hostname.',
        os.hostname()
    )
    .option('-e, --helo <hostname>', 'Client hostname from the HELO/EHLO command (used in some SPF checks).')
    .option('-f, --sender <address>', 'Email address from the MAIL FROM command. If not provided, the address from the latest Return-Path header is used.')
    .option(
        '-n, --dns-cache <file>',
        'Path to a JSON file with cached DNS responses. When provided, DNS queries use these cached responses instead of performing actual DNS lookups.'
    )
    .option('-o, --headers-only', 'If set, outputs only the ARC seal headers without the message body.')
    .addOption(
        rejectRepeated(
            new Option(
                '--auth-results <value>',
                'Authentication-Results value to embed in the ARC-Authentication-Results header (the part after "i=N;"). When set, the message is sealed using this value as is and no authentication checks are performed.'
            ).conflicts('authResultsFile')
        )
    )
    .addOption(
        rejectRepeated(
            new Option(
                '--auth-results-file <file>',
                'Path to a file containing the Authentication-Results value. Same as --auth-results, but read from a file.'
            )
        )
    )
    .addOption(
        rejectRepeated(
            new Option(
                '--cv <status>',
                'Chain validation status for the ARC-Seal header (cv= tag). Only used together with --auth-results or --auth-results-file. Defaults to "none".'
            ).choices(['none', 'pass', 'fail'])
        )
    )
    .addOption(
        rejectRepeated(
            new Option(
                '--instance <number>',
                'ARC instance number (i= tag). Only used together with --auth-results or --auth-results-file. Defaults to the next instance number based on the existing ARC chain, or 1.'
            ).argParser(numberArg)
        )
    )
    .hook('preAction', command => {
        let opts = command.opts();
        let fromCli = key => command.getOptionValueSource(key) === 'cli';

        // a missing value would silently flip the command back into full
        // authentication mode, the opposite of what the caller asked for
        for (let [key, flag] of [
            ['authResults', '--auth-results'],
            ['authResultsFile', '--auth-results-file']
        ]) {
            if (fromCli(key) && (typeof opts[key] !== 'string' || !opts[key].trim())) {
                command.error(`error: ${flag} must not be empty`);
            }
        }

        // .implies() cannot express "requires one of", so enforce it here
        if (!opts.authResults && !opts.authResultsFile) {
            for (let key of ['cv', 'instance']) {
                if (fromCli(key)) {
                    command.error(`error: --${key} can only be used together with --auth-results or --auth-results-file`);
                }
            }
        }
    })
    .action(runCommand(commandSeal, 'Failed to seal the input message.'));

program
    .command('spf')
    .description('Validate SPF for an email address and MTA IP address')
    .helpOption('--help', 'Show help.')
    .requiredOption('-f, --sender <address>', 'Email address from the MAIL FROM command.')
    .requiredOption('-i, --client-ip <ip>', 'IP address of the remote client (used for SPF checks).')
    .option('-e, --helo <hostname>', 'Client hostname from the HELO/EHLO command (used in some SPF checks).')
    .option(
        '-m, --mta <hostname>',
        'Hostname of the server performing the SPF check (used in the Authentication-Results header). Defaults to the local hostname.',
        os.hostname()
    )
    .option(
        '-n, --dns-cache <file>',
        'Path to a JSON file with cached DNS responses. When provided, DNS queries use these cached responses instead of performing actual DNS lookups.'
    )
    .option('-o, --headers-only', 'If set, outputs only the SPF authentication header.')
    .option('-x, --max-lookups <number>', 'Maximum allowed DNS lookups during SPF checks. Defaults to 10.', numberArg, 10)
    .option('-z, --max-void-lookups <number>', 'Maximum allowed DNS lookups that return no data (void lookups) during SPF checks. Defaults to 2.', numberArg, 2)
    .action(runCommand(commandSpf, 'Failed to verify SPF for the email address.'));

program
    .command('vmc')
    .description('Validate a Verified Mark Certificate (VMC) logo file')
    .helpOption('--help', 'Show help.')
    .option('-p, --authorityPath <file>', 'Path to a local VMC file.')
    .option('-a, --authority <url>', 'URL of the VMC file.')
    .option('-d, --domain <domain>', 'Sending domain to validate against the VMC.')
    .option('-t, --date <timestamp>', 'ISO-formatted timestamp to use for certificate expiration checks.')
    .action(runCommand(commandVmc, 'Failed to verify the VMC file.'));

program
    .command('bodyhash')
    .description('Generate a DKIM body hash for an email message')
    .argument('[email]', emailArgDescription)
    .helpOption('--help', 'Show help.')
    .option('-a, --algo <algorithm>', 'Hashing algorithm to use. Defaults to "sha256". Can also use DKIM-style algorithms like "rsa-sha256".', 'sha256')
    .option(
        '-c, --canonicalization <method>',
        'Body canonicalization method (c= tag). Defaults to "relaxed". Can use DKIM-style formats like "relaxed/relaxed".',
        'relaxed'
    )
    .option('-l, --body-length <number>', 'Maximum length of the canonicalized body to include in the hash (l= tag).', numberArg)
    .action(runCommand(commandBodyhash, 'Failed to calculate the body hash for the input message.'));

program
    .command('license')
    .description('Display license information for mailauth and included modules')
    .helpOption('--help', 'Show help.')
    .action(() => {
        fs.readFile(pathlib.join(__dirname, '..', 'LICENSE.txt'), (err, license) => {
            if (err) {
                console.error('Failed to load license information.');
                console.error(err);
                return process.exit(1);
            }

            console.error('mailauth License');
            console.error('================');

            console.error(license.toString().trim());

            console.error('');

            fs.readFile(pathlib.join(__dirname, '..', 'licenses.txt'), (err, data) => {
                if (err) {
                    console.error('Failed to load included modules license information.');
                    console.error(err);
                    return process.exit(1);
                }

                console.error('Included Modules');
                console.error('================');

                console.error(data.toString().trim());
                process.exit();
            });
        });
    });

program.parse(process.argv);
