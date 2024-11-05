#!/usr/bin/env node

'use strict';

const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const os = require('node:os');
const assert = require('node:assert');

const commandReport = require('../lib/commands/report');
const commandSign = require('../lib/commands/sign');
const commandSeal = require('../lib/commands/seal');
const commandSpf = require('../lib/commands/spf');
const commandVmc = require('../lib/commands/vmc');
const commandBodyhash = require('../lib/commands/bodyhash');

const fs = require('node:fs');
const pathlib = require('node:path');

const argv = yargs(hideBin(process.argv))
    .command(
        ['report [email]', '$0 [email]'],
        'Validate an email message and return a detailed JSON report',
        yargs => {
            yargs
                .option('client-ip', {
                    alias: 'i',
                    type: 'string',
                    description: 'IP address of the remote client (used for SPF checks). If not provided, it is parsed from the latest Received header.'
                })
                .option('mta', {
                    alias: 'm',
                    type: 'string',
                    description:
                        'Hostname of the server performing the validation (used in the Authentication-Results header). Defaults to the local hostname.',
                    default: os.hostname()
                })
                .option('helo', {
                    alias: 'e',
                    type: 'string',
                    description: 'Client hostname from the HELO/EHLO command (used in some SPF checks).'
                })
                .option('sender', {
                    alias: 'f',
                    type: 'string',
                    description: 'Email address from the MAIL FROM command. If not provided, the address from the latest Return-Path header is used.'
                })
                .option('dns-cache', {
                    alias: 'n',
                    type: 'string',
                    description:
                        'Path to a JSON file with cached DNS responses. When provided, DNS queries use these cached responses instead of performing actual DNS lookups.'
                })
                .option('max-lookups', {
                    alias: 'x',
                    type: 'number',
                    description: 'Maximum allowed DNS lookups during SPF checks. Defaults to 10.',
                    default: 10
                })
                .option('max-void-lookups', {
                    alias: 'z',
                    type: 'number',
                    description: 'Maximum allowed DNS lookups that return no data (void lookups) during SPF checks. Defaults to 2.',
                    default: 2
                });
            yargs.positional('email', {
                describe: 'Path to the email message file in EML format. If not specified, the content is read from standard input.'
            });
        },
        argv => {
            commandReport(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    console.error('Failed to generate report for the input message.');
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
                    description: 'Path to the private key file used for signing.',
                    demandOption: true
                })
                .option('domain', {
                    alias: 'd',
                    type: 'string',
                    description: 'Domain name to use in the DKIM signature (d= tag).',
                    demandOption: true
                })
                .option('selector', {
                    alias: 's',
                    type: 'string',
                    description: 'Selector to use in the DKIM signature (s= tag).',
                    demandOption: true
                })
                .option('algo', {
                    alias: 'a',
                    type: 'string',
                    description: 'Signing algorithm. Defaults to "rsa-sha256" or "ed25519-sha256" depending on the private key type.',
                    default: 'rsa-sha256'
                })
                .option('canonicalization', {
                    alias: 'c',
                    type: 'string',
                    description: 'Canonicalization method (c= tag). Defaults to "relaxed/relaxed".',
                    default: 'relaxed/relaxed'
                })
                .option('time', {
                    alias: 't',
                    type: 'number',
                    description: 'Signing time as a UNIX timestamp (t= tag). Defaults to the current time.'
                })
                .option('body-length', {
                    alias: 'l',
                    type: 'number',
                    description: 'Maximum length of the canonicalized body to include in the signature (l= tag). Not recommended for general use.'
                })
                .option('header-fields', {
                    alias: 'h',
                    type: 'string',
                    description: 'Colon-separated list of header field names to include in the signature (h= tag).'
                })
                .option('headers-only', {
                    alias: 'o',
                    type: 'boolean',
                    description: 'If set, outputs only the DKIM signature headers without the message body.'
                });
            yargs.positional('email', {
                describe: 'Path to the email message file in EML format. If not specified, the content is read from standard input.'
            });
        },
        argv => {
            commandSign(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    if (!err.suppress) {
                        console.error('Failed to sign the input message.');
                        console.error(err);
                    }
                    process.exit(1);
                });
        }
    )
    .command(
        ['seal [email]'],
        'Authenticate and seal an email with an ARC digital signature',
        yargs => {
            yargs
                .option('private-key', {
                    alias: 'k',
                    type: 'string',
                    description: 'Path to the private key file used for sealing.',
                    demandOption: true
                })
                .option('domain', {
                    alias: 'd',
                    type: 'string',
                    description: 'Domain name to use in the ARC seal (d= tag).',
                    demandOption: true
                })
                .option('selector', {
                    alias: 's',
                    type: 'string',
                    description: 'Selector to use in the ARC seal (s= tag).',
                    demandOption: true
                })
                .option('algo', {
                    alias: 'a',
                    type: 'string',
                    description:
                        'Sealing algorithm. Defaults to "rsa-sha256" or "ed25519-sha256" depending on the private key type. Note: RFC8617 only allows "rsa-sha256" (a= tag).',
                    default: 'rsa-sha256'
                })
                .option('canonicalization', {
                    alias: 'c',
                    type: 'string',
                    description: 'Canonicalization method. Note: RFC8617 only allows "relaxed/relaxed" (c= tag).',
                    default: 'relaxed/relaxed'
                })
                .option('time', {
                    alias: 't',
                    type: 'number',
                    description: 'Sealing time as a UNIX timestamp (t= tag). Defaults to the current time.'
                })
                .option('header-fields', {
                    alias: 'h',
                    type: 'string',
                    description: 'Colon-separated list of header field names to include in the seal (h= tag).'
                })
                .option('client-ip', {
                    alias: 'i',
                    type: 'string',
                    description: 'IP address of the remote client (used for SPF checks). If not provided, it is parsed from the latest Received header.'
                })
                .option('mta', {
                    alias: 'm',
                    type: 'string',
                    description:
                        'Hostname of the server performing the validation (used in the Authentication-Results header). Defaults to the local hostname.',
                    default: os.hostname()
                })
                .option('helo', {
                    alias: 'e',
                    type: 'string',
                    description: 'Client hostname from the HELO/EHLO command (used in some SPF checks).'
                })
                .option('sender', {
                    alias: 'f',
                    type: 'string',
                    description: 'Email address from the MAIL FROM command. If not provided, the address from the latest Return-Path header is used.'
                })
                .option('dns-cache', {
                    alias: 'n',
                    type: 'string',
                    description:
                        'Path to a JSON file with cached DNS responses. When provided, DNS queries use these cached responses instead of performing actual DNS lookups.'
                })
                .option('headers-only', {
                    alias: 'o',
                    type: 'boolean',
                    description: 'If set, outputs only the ARC seal headers without the message body.'
                });
            yargs.positional('email', {
                describe: 'Path to the email message file in EML format. If not specified, the content is read from standard input.'
            });
        },
        argv => {
            commandSeal(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    if (!err.suppress) {
                        console.error('Failed to seal the input message.');
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
                    description: 'Email address from the MAIL FROM command.',
                    demandOption: true
                })
                .option('client-ip', {
                    alias: 'i',
                    type: 'string',
                    description: 'IP address of the remote client (used for SPF checks).',
                    demandOption: true
                })
                .option('helo', {
                    alias: 'e',
                    type: 'string',
                    description: 'Client hostname from the HELO/EHLO command (used in some SPF checks).'
                })
                .option('mta', {
                    alias: 'm',
                    type: 'string',
                    description: 'Hostname of the server performing the SPF check (used in the Authentication-Results header). Defaults to the local hostname.',
                    default: os.hostname()
                })
                .option('dns-cache', {
                    alias: 'n',
                    type: 'string',
                    description:
                        'Path to a JSON file with cached DNS responses. When provided, DNS queries use these cached responses instead of performing actual DNS lookups.'
                })
                .option('headers-only', {
                    alias: 'o',
                    type: 'boolean',
                    description: 'If set, outputs only the SPF authentication header.'
                })
                .option('max-lookups', {
                    alias: 'x',
                    type: 'number',
                    description: 'Maximum allowed DNS lookups during SPF checks. Defaults to 10.',
                    default: 10
                })
                .option('max-void-lookups', {
                    alias: 'z',
                    type: 'number',
                    description: 'Maximum allowed DNS lookups that return no data (void lookups) during SPF checks. Defaults to 2.',
                    default: 2
                });
        },
        argv => {
            commandSpf(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    console.error('Failed to verify SPF for the email address.');
                    console.error(err);
                    process.exit(1);
                });
        }
    )
    .command(
        ['vmc'],
        'Validate a Verified Mark Certificate (VMC) logo file',
        yargs => {
            yargs
                .option('authorityPath', {
                    alias: 'p',
                    type: 'string',
                    description: 'Path to a local VMC file.'
                })
                .option('authority', {
                    alias: 'a',
                    type: 'string',
                    description: 'URL of the VMC file.'
                })
                .option('domain', {
                    alias: 'd',
                    type: 'string',
                    description: 'Sending domain to validate against the VMC.'
                })
                .option('date', {
                    alias: 't',
                    type: 'string',
                    description: 'ISO-formatted timestamp to use for certificate expiration checks.'
                });
        },
        argv => {
            commandVmc(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    console.error('Failed to verify the VMC file.');
                    console.error(err);
                    process.exit(1);
                });
        }
    )
    .command(
        ['bodyhash [email]'],
        'Generate a DKIM body hash for an email message',
        yargs => {
            yargs
                .option('algo', {
                    alias: 'a',
                    type: 'string',
                    description: 'Hashing algorithm to use. Defaults to "sha256". Can also use DKIM-style algorithms like "rsa-sha256".',
                    default: 'sha256'
                })
                .option('canonicalization', {
                    alias: 'c',
                    type: 'string',
                    description: 'Body canonicalization method (c= tag). Defaults to "relaxed". Can use DKIM-style formats like "relaxed/relaxed".',
                    default: 'relaxed'
                })
                .option('body-length', {
                    alias: 'l',
                    type: 'number',
                    description: 'Maximum length of the canonicalized body to include in the hash (l= tag).'
                });
            yargs.positional('email', {
                describe: 'Path to the email message file in EML format. If not specified, the content is read from standard input.'
            });
        },
        argv => {
            commandBodyhash(argv)
                .then(() => {
                    process.exit();
                })
                .catch(err => {
                    if (!err.suppress) {
                        console.error('Failed to calculate the body hash for the input message.');
                        console.error(err);
                    }
                    process.exit(1);
                });
        }
    )
    .command(
        ['license'],
        'Display license information for mailauth and included modules',
        () => false,
        () => {
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
        }
    )
    .option('verbose', {
        alias: 'v',
        type: 'boolean',
        description: 'Enable verbose logging for debugging purposes.'
    }).argv;

assert.ok(argv);
