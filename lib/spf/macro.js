'use strict';

const net = require('net');
const ipaddr = require('ipaddr.js');

/**
 * Renders macro into an output string.
 * @param {String} input Macro to evaluate
 * @param {Object} values Macto variables
 * @param {String} values.sender Sender email address
 * @param {String} values.ip Sender IP address
 * @param {String} values.helo Client's HELO/EHLO domain
 */
const macro = (input, values) => {
    input = (input || '').toString();

    let { sender, ip, helo } = values || {};

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
            throw new Error('Syntax error on parsing macro');
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

        let splitter = '.';

        switch (macroChar) {
            case 's':
                curval = sender;
                break;
            case 'l':
                curval = senderLocal;
                break;
            case 'o':
                curval = senderDomain;
                break;
            case 'd':
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
            // validated domain name is unsupported
            case 'p':
                break;
            case 'v':
                curval = vStr;
                break;
            case 'h':
                curval = helo;
                break;
            // exp flags are not supported
            case 'c':
            case 'r':
            case 't':
                break;
            default:
                throw new Error(`Unknown macro letter "${macroChar}"`);
        }

        let nr = '';
        let reversed = false;

        for (let char of chars) {
            if (char === 'r') {
                reversed = true;
                continue;
            }
            if (char >= '0' && char <= '9' && nr.length < 5) {
                nr += char;
                continue;
            }
            splitter = char;
        }

        if (nr) {
            nr = parseInt(nr, 10);
        }

        if (reversed || nr || splitter !== '.') {
            curval = curval.split(splitter);

            if (reversed) {
                curval = curval.reverse();
            }

            if (nr && nr > 0) {
                curval = curval.slice(-nr);
            }

            return curval.join('.');
        }

        return curval;
    });
};

module.exports = macro;
