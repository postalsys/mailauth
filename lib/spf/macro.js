'use strict';

const os = require('node:os');
const { parseIp } = require('./syntax');

// RFC 3986 unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
const urlEscape = value =>
    Array.from(Buffer.from(value, 'utf-8'))
        .map(byte => {
            let chr = String.fromCharCode(byte);
            if (/^[A-Za-z0-9\-._~]$/.test(chr)) {
                return chr;
            }
            return `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
        })
        .join('');

/**
 * Renders macro into an output string.
 * @param {String} input Macro to evaluate
 * @param {Object} values Macro variables
 * @param {String} values.sender Sender email address
 * @param {String} values.ip Sender IP address
 * @param {String} values.helo Client's HELO/EHLO domain
 * @param {String} [values.mta] Hostname of the MTA or MX server that processes the message
 * @param {String} [values.domain] Domain currently being evaluated by check_host(), changes on include/redirect recursion (RFC 7208 sections 5.2, 6.1)
 * @param {String} [values.p] Validated domain name of the client IP (RFC 7208 section 7.3), "unknown" if not set
 * @param {Object} [values.addr] `values.ip` parsed with parseIp(), if the caller already has it
 */
const macro = (input, values) => {
    input = (input || '').toString();

    if (input.indexOf('%') < 0) {
        // nothing to expand
        return input;
    }

    let { sender, ip, helo, mta, domain, p, addr } = values || {};

    sender = (sender || '').toString();
    ip = (ip || '').toString();
    helo = (helo || '').toString();

    // the local-part may be a quoted string that contains "@", the domain follows the last "@"
    let atPos = sender.lastIndexOf('@');
    let senderLocal = atPos >= 0 ? sender.substr(0, atPos) : '';
    let senderDomain = atPos >= 0 ? sender.substr(atPos + 1) : sender;

    // the caller can pass the client IP already parsed, it is then not parsed again
    let parsedIp = addr || parseIp(ip);
    let vStr = parsedIp ? (parsedIp.kind() === 'ipv4' ? 'in-addr' : 'ip6') : '';

    return input.replace(/%%|%_|%-|%\{([^}]+)\}|%/gi, (m, c) => {
        if (m === '%') {
            // Lone % found
            let err = new Error('Syntax error on parsing macro');
            err.spfResult = { error: 'permerror', text: `Unexpected % in macro` };
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
                curval = senderDomain;
                break;

            case 'p':
                // validated domain name of the client IP, resolved by the caller (RFC 7208 section 7.3)
                curval = p || 'unknown';
                break;

            case 'd':
                // current <domain> of check_host(), not the sender domain (these only match at the top level)
                curval = domain || senderDomain;
                break;

            case 'i':
                if (!parsedIp) {
                    throw new Error(`Invalid IP address ${ip}`);
                }
                curval = parsedIp.toNormalizedString();
                if (parsedIp.kind() === 'ipv6') {
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
                curval = helo || `[${parsedIp ? parsedIp.toString() : ip}]`;
                break;

            case 'c':
                if (!parsedIp) {
                    throw new Error(`Invalid IP address ${ip}`);
                }
                curval = parsedIp.toString();
                break;

            case 'r':
                curval = mta || os.hostname();
                break;

            case 't':
                curval = Math.round(Date.now() / 1000).toString();
                break;

            default: {
                let err = new Error('Syntax error on parsing macro');
                err.spfResult = { error: 'permerror', text: `Unknown macro letter "${macroChar}"` };
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

        // find the reverse transformer, ABNF literals are case-insensitive, so "R" is the same as "r"
        if (chars.length && chars[0].toLowerCase() === 'r') {
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
            // every delimiter is escaped, an unescaped "-" between two others would make a range
            // in the character class, such as "+-." that also matches ","
            curval = curval.split(new RegExp(`[${delimiters.replace(/./g, '\\$&')}]`));

            if (reversed) {
                curval = curval.reverse();
            }

            if (nr && nr > 0) {
                curval = curval.slice(-nr);
            }

            // no matter the expansion delimiter, values are joined with dots
            curval = curval.join('.');
        }

        // uppercase macros expand exactly as their lowercase equivalents, and are then URL escaped (RFC 7208 section 7.3)
        if (macroChar !== macroChar.toLowerCase()) {
            curval = urlEscape(curval);
        }

        return curval;
    });
};

module.exports = macro;
