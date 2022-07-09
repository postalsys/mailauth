#!/usr/bin/env node

'use strict';

const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const os = require('os');
const assert = require('assert');

const commandReport = require('../lib/commands/report');
const commandSign = require('../lib/commands/sign');
const commandSeal = require('../lib/commands/seal');
const commandSpf = require('../lib/commands/spf');
const commandVmc = require('../lib/commands/vmc');

const fs = require('fs');
const pathlib = require('path');

const argv = yargs(hideBin(process.argv))
    .command(
        ['report [email]', '$0 [email]'],
        'Validate email message and return a report in JSON format',
        yargs => {
            yargs
                .option('client-ip', {
                    alias: 'i',
                    type: 'string',
                    description: 'Client IP used for SPF checks. If not set then parsed from the latest Received header'
                })
                .option('mta', {
                    alias: 'm',
                    type: 'string',
                    description: 'Hostname of this machine, used in the Authentication-Results header',
                    default: os.hostname()
                })
                .option('helo', {
                    alias: 'e',
                    type: 'string',
                    description: 'Client hostname from the EHLO/HELO command, used in some specific SPF checks'
                })
                .option('sender', {
                    alias: 'f',
                    type: 'string',
                    description: 'Email address from the MAIL FROM command. If not set then the address from the latest Return-Path header is used instead'
                })
                .option('dns-cache', {
                    alias: 'n',
                    type: 'string',
                    description: 'Path to a JSON file with cached DNS responses. If this file is given then no actual DNS requests are performed'
                })
                .option('max-lookups', {
                    alias: 'x',
                    type: 'number',
                    description: 'Maximum allowed DNS lookups',
                    default: 50
                });
            yargs.positional('email', {
                describe: 'Path to the email message file in EML format. If not specified then content is read from stdin'
            });
        },
        argv => {
            commandReport(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    console.error('Failed to generate report for input message');
                    console.error(err);
                    process.exit(1);
                });
        }
    )
    .command(
        ['sign [email]'],
        'Sign an email with a DKIM digital signature',
        yargs => {
            yargs

                .option('private-key', {
                    alias: 'k',
                    type: 'string',
                    description: 'Path to a private key for signing',
                    demandOption: true
                })
                .option('domain', {
                    alias: 'd',
                    type: 'string',
                    description: 'Domain name for signing (d= tag)',
                    demandOption: true
                })
                .option('selector', {
                    alias: 's',
                    type: 'string',
                    description: 'Key selector for signing  (s= tag)',
                    demandOption: true
                })
                .option('canonicalization', {
                    alias: 'c',
                    type: 'string',
                    description: 'Canonicalization algorithm  (c= tag)',
                    default: 'relaxed/relaxed'
                })
                .option('time', {
                    alias: 't',
                    type: 'number',
                    description: 'Signing time as a unix timestamp (t= tag)'
                })
                .option('body-length', {
                    alias: 'l',
                    type: 'number',
                    description: 'Maximum length of canonicalizated body to sign (l= tag)'
                })
                .option('header-fields', {
                    alias: 'h',
                    type: 'string',
                    description: 'Colon separated list of header field names to sign (h= tag)'
                })
                .option('headers-only', {
                    alias: 'o',
                    type: 'boolean',
                    description: 'Return signing headers only'
                });
            yargs.positional('email', {
                describe: 'Path to the email message file in EML format. If not specified then content is read from stdin'
            });
        },
        argv => {
            commandSign(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    if (!err.suppress) {
                        console.error('Failed to sign input message');
                        console.error(err);
                    }
                    process.exit(1);
                });
        }
    )
    .command(
        ['seal [email]'],
        'Authenticates an email and seals it with an ARC digital signature',
        yargs => {
            yargs
                .option('private-key', {
                    alias: 'k',
                    type: 'string',
                    description: 'Path to a private key for sealing',
                    demandOption: true
                })
                .option('domain', {
                    alias: 'd',
                    type: 'string',
                    description: 'Domain name for sealing (d= tag)',
                    demandOption: true
                })
                .option('selector', {
                    alias: 's',
                    type: 'string',
                    description: 'Key selector for sealing  (s= tag)',
                    demandOption: true
                })
                .option('algo', {
                    alias: 'a',
                    type: 'string',
                    description:
                        'Sealing algorithm. Defaults either to rsa-sha256 or ed25519-sha256 depending on the private key format. NB! Only rsa-sha256 is allowed by RFC8617 (a= tag)',
                    default: 'rsa-sha256'
                })
                .option('canonicalization', {
                    alias: 'c',
                    type: 'string',
                    description: 'Canonicalization algorithm. NB! Only relaxed/relaxed is allowed by RFC8617 (c= tag)',
                    default: 'relaxed/relaxed'
                })
                .option('time', {
                    alias: 't',
                    type: 'number',
                    description: 'Signing time as a unix timestamp (t= tag)'
                })
                .option('header-fields', {
                    alias: 'h',
                    type: 'string',
                    description: 'Colon separated list of header field names to sign (h= tag)'
                })
                .option('client-ip', {
                    alias: 'i',
                    type: 'string',
                    description: 'Client IP used for SPF checks. If not set then parsed from the latest Received header'
                })
                .option('mta', {
                    alias: 'm',
                    type: 'string',
                    description: 'Hostname of this machine, used in the Authentication-Results header',
                    default: os.hostname()
                })
                .option('helo', {
                    alias: 'e',
                    type: 'string',
                    description: 'Client hostname from the EHLO/HELO command, used in some specific SPF checks'
                })
                .option('sender', {
                    alias: 'f',
                    type: 'string',
                    description: 'Email address from the MAIL FROM command. If not set then the address from the latest Return-Path header is used instead'
                })
                .option('dns-cache', {
                    alias: 'n',
                    type: 'string',
                    description: 'Path to a JSON file with cached DNS responses. If this file is given then no actual DNS requests are performed'
                })
                .option('headers-only', {
                    alias: 'o',
                    type: 'boolean',
                    description: 'Return signing headers only'
                });
            yargs.positional('email', {
                describe: 'Path to the email message file in EML format. If not specified then content is read from stdin'
            });
        },
        argv => {
            commandSeal(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    if (!err.suppress) {
                        console.error('Failed to sign input message');
                        console.error(err);
                    }
                    process.exit(1);
                });
        }
    )
    .command(
        ['spf'],
        'Validate SPF for an email address and MTA IP address',
        yargs => {
            yargs
                .option('sender', {
                    alias: 'f',
                    type: 'string',
                    description: 'Email address from the MAIL FROM command',
                    demandOption: true
                })
                .option('client-ip', {
                    alias: 'i',
                    type: 'string',
                    description: 'Client IP used for SPF checks. If not set then parsed from the latest Received header',
                    demandOption: true
                })
                .option('helo', {
                    alias: 'e',
                    type: 'string',
                    description: 'Client hostname from the EHLO/HELO command, used in some specific SPF checks'
                })
                .option('mta', {
                    alias: 'm',
                    type: 'string',
                    description: 'Hostname of this machine, used in the Authentication-Results header',
                    default: os.hostname()
                })
                .option('dns-cache', {
                    alias: 'n',
                    type: 'string',
                    description: 'Path to a JSON file with cached DNS responses. If this file is given then no actual DNS requests are performed'
                })
                .option('headers-only', {
                    alias: 'o',
                    type: 'boolean',
                    description: 'Return signing headers only'
                })
                .option('max-lookups', {
                    alias: 'x',
                    type: 'number',
                    description: 'Maximum allowed DNS lookups',
                    default: 50
                });
        },
        argv => {
            commandSpf(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    console.error('Failed to verify SPF for an email address');
                    console.error(err);
                    process.exit(1);
                });
        }
    )
    .command(
        ['vmc'],
        'Validate VMC logo',
        yargs => {
            yargs.option('authorityFile', {
                alias: 'f',
                type: 'string',
                description: 'Path to a VMC file',
                demandOption: false
            });
            yargs.option('authority', {
                alias: 'a',
                type: 'string',
                description: 'URL to a VMC file',
                demandOption: false
            });
        },
        argv => {
            commandVmc(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    console.error('Failed to verify VMC file');
                    console.error(err);
                    process.exit(1);
                });
        }
    )
    .command(
        ['license'],
        'Show license information',
        () => false,
        () => {
            fs.readFile(pathlib.join(__dirname, '..', 'LICENSE.txt'), (err, license) => {
                if (err) {
                    console.error('Failed to load license information');
                    console.error(err);
                    return process.exit(1);
                }

                console.error('Mailauth License');
                console.error('================');

                console.error(license.toString().trim());

                console.error('');

                fs.readFile(pathlib.join(__dirname, '..', 'licenses.txt'), (err, data) => {
                    if (err) {
                        console.error('Failed to load license information');
                        console.error(err);
                        return process.exit(1);
                    }

                    console.error('Included Modules');
                    console.error('================');

                    console.error(data.toString().trim());
                    process.exit();
                });
            });
        }
    )
    .option('verbose', {
        alias: 'v',
        type: 'boolean',
        description: 'Run with verbose logging'
    }).argv;

assert.ok(argv);
