'use strict';

const net = require('net');
const ipaddr = require('ipaddr.js');
const os = require('node:os');

/**
 * Renders macro into an output string.
 * @param {String} input Macro to evaluate
 * @param {Object} values Macro variables
 * @param {String} values.sender Sender email address
 * @param {String} values.ip Sender IP address
 * @param {String} values.helo Client's HELO/EHLO domain
 * @param {String} [values.mta] Hostname of the MTA or MX server that processes the message
 */
const macro = (input, values) => {
    input = (input || '').toString();

    let { sender, ip, helo, mta } = values || {};

    sender = (sender || '').toString();
    ip = (ip || '').toString();
    helo = (helo || '').toString();

    let atPos = sender.indexOf('@');
    let senderLocal = atPos >= 0 ? sender.substr(0, atPos) : '';
    let senderDomain = atPos >= 0 ? sender.substr(atPos + 1) : sender;
    let vStr = net.isIPv4(ip) ? 'in-addr' : net.isIPv6(ip) ? 'ip6' : '';

    return input.replace(/%%|%_|%-|%\{([^}]+)\}|%/gi, (m, c) => {
        if (m === '%') {
            // Lone % found
            let err = new Error('Syntax error on parsing macro');
            err.spfResult = { error: 'permerror', message: `Unexpected % in macro` };
            throw err;
        }

        if (m === '%%') {
            return '%';
        }

        if (m === '%_') {
            return ' ';
        }

        if (m === '%-') {
            return '%20';
        }

        // macro letters
        let curval = '';
        let chars = c.split('');
        let macroChar = chars.shift();

        let delimiters = '';

        switch (macroChar.toLowerCase()) {
            case 's':
                curval = sender;
                break;

            case 'l':
                curval = senderLocal;
                break;

            case 'o':
            case 'd':
            case 'p': // validated domain name is unsupported, instead we use the unvalidated sender domain
                curval = senderDomain;
                break;

            case 'i':
                curval = ipaddr.parse(ip).toNormalizedString();
                if (net.isIPv6(ip)) {
                    curval = curval
                        .split(':')
                        .flatMap(p => {
                            if (p.length < 4) {
                                p = '0'.repeat(4 - p.length) + p;
                            }
                            return p.split('');
                        })
                        .join('.');
                }
                break;

            case 'v':
                curval = vStr;
                break;

            case 'h':
                curval = helo || `[${ipaddr.parse(ip).toString()}]`;
                break;

            case 'c':
                curval = ipaddr.parse(ip).toString();
                break;

            case 'r':
                curval = mta || os.hostname();
                break;

            case 't':
                curval = Math.round(Date.now() / 1000).toString();
                break;

            default: {
                let err = new Error('Syntax error on parsing macro');
                err.spfResult = { error: 'permerror', message: `Unknown macro letter "${macroChar}"` };
                throw err;
            }
        }

        let nr = '';
        let reversed = false;

        // find the nr transformer
        while (chars.length) {
            let char = chars[0];
            if (char >= '0' && char <= '9') {
                chars.shift();
                nr += char;
            } else {
                break;
            }
        }

        if (nr) {
            nr = parseInt(nr, 10);
        }

        // find the reverse transformer
        if (chars.length && chars[0] === 'r') {
            chars.shift();
            reversed = true;
        }

        // find the delimiter chars
        for (let char of chars) {
            // ABNF
            // delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="
            if (['.', '-', '+', ',', '/', '_', '='].includes(char) && delimiters.indexOf(char) < 0) {
                delimiters += char;
            }
        }
        // default delimiter is the dot
        delimiters = delimiters || '.';

        if (reversed || nr || delimiters !== '.') {
            curval = curval.split(new RegExp(`[${delimiters.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}]`));

            if (reversed) {
                curval = curval.reverse();
            }

            if (nr && nr > 0) {
                curval = curval.slice(-nr);
            }

            // no matter the expansion delimiter, values are joined with dots
            return curval.join('.');
        }

        return curval;
    });
};

module.exports = macro;
