#!/usr/bin/env node

'use strict';

const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const os = require('os');
const assert = require('assert');
const runReport = require('../lib/run-report');

const argv = yargs(hideBin(process.argv))
    .command(
        ['report [email]', '$0 [email]'],
        'Validate email message and return a report in JSON format',
        yargs => {
            yargs.positional('email', {
                describe: 'Path to the email message file in EML format. If not specified then content is read from stdin'
            });
        },
        argv => {
            runReport(argv)
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
    .option('verbose', {
        alias: 'v',
        type: 'boolean',
        description: 'Run with verbose logging'
    })
    .option('client-ip', {
        alias: 'c',
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
        alias: 's',
        type: 'string',
        description: 'Email address from the MAIL FROM command. If not set then the address from the latest Return-Path header is used instead'
    })
    .option('dns-cache', {
        alias: 'd',
        type: 'string',
        description: 'Path to a JSON file with cached DNS responses. If this file is given then no actual DNS requests are performed'
    }).argv;

assert.ok(argv);
