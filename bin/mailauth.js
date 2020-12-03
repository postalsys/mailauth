#!/usr/bin/env node

'use strict';

const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const os = require('os');
const assert = require('assert');
const commandReport = require('../lib/commands/report');
const commandSign = require('../lib/commands/sign');
const commandSeal = require('../lib/commands/seal');

const argv = yargs(hideBin(process.argv))
    .command(
        ['report [email]', '$0 [email]'],
        'Validate email message and return a report in JSON format',
        yargs => {
            yargs
                .option('client-ip', {
                    alias: 'i',
                    type: 'string',
                    description: 'Client IP used for SPF checks. If not set then parsed from latest Received header'
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
                .option('headers-only', {
                    alias: 'h',
                    type: 'boolean',
                    description: 'Return signing headers only'
                })
                .option('domain', {
                    alias: 'd',
                    type: 'string',
                    description: 'Domain name for signing',
                    demandOption: true
                })
                .option('selector', {
                    alias: 's',
                    type: 'string',
                    description: 'Key selector for signing',
                    demandOption: true
                })
                .option('private-key', {
                    alias: 'k',
                    type: 'string',
                    description: 'Path to a private key for signing',
                    demandOption: true
                })
                .option('algo', {
                    alias: 'a',
                    type: 'string',
                    description: 'Signing algorithm. Defaults either to rsa-sha256 or ed25519-sha256 depending on the private key format',
                    default: 'rsa-sha256'
                })
                .option('canonicalization', {
                    alias: 'c',
                    type: 'string',
                    description: 'Canonicalization algorithm',
                    default: 'relaxed/relaxed'
                })
                .option('time', {
                    alias: 't',
                    type: 'number',
                    description: 'Signing time as a unix timestamp'
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
                .option('headers-only', {
                    alias: 'h',
                    type: 'boolean',
                    description: 'Return sealing headers only'
                })
                .option('domain', {
                    alias: 'd',
                    type: 'string',
                    description: 'Domain name for sealing',
                    demandOption: true
                })
                .option('selector', {
                    alias: 's',
                    type: 'string',
                    description: 'Key selector for sealing',
                    demandOption: true
                })
                .option('private-key', {
                    alias: 'k',
                    type: 'string',
                    description: 'Path to a private key for sealing',
                    demandOption: true
                })
                .option('algo', {
                    alias: 'a',
                    type: 'string',
                    description: 'Sealing algorithm. Defaults either to rsa-sha256 or ed25519-sha256 depending on the private key format',
                    default: 'rsa-sha256'
                })
                .option('canonicalization', {
                    alias: 'c',
                    type: 'string',
                    description: 'Canonicalization algorithm',
                    default: 'relaxed/relaxed'
                })
                .option('time', {
                    alias: 't',
                    type: 'number',
                    description: 'Sealing time as a unix timestamp'
                })
                .option('client-ip', {
                    alias: 'i',
                    type: 'string',
                    description: 'Client IP used for SPF checks. If not set then parsed from latest Received header'
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
    .option('verbose', {
        alias: 'v',
        type: 'boolean',
        description: 'Run with verbose logging'
    }).argv;

assert.ok(argv);
