'use strict';

const net = require('node:net');
const ipaddr = require('ipaddr.js');

// RFC 7208 section 7.1
const MACRO_EXPAND = /^([a-z])(\d*)(r?)([.\-+,/_=]*)$/i;
const MACRO_LETTERS = 'slodiphcrtv';
// allowed only in "exp" text (RFC 7208 section 7.2)
const EXP_ONLY_LETTERS = 'crt';

// toplabel = ( *alphanum ALPHA *alphanum ) / ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
const TOPLABEL = /^(?:[a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9-]*[a-z0-9])$/i;

// name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." ) (RFC 7208 section 4.6.1)
const MODIFIER_NAME = /^[a-z][a-z0-9\-_.]*$/i;

// qnum based dotted quad (RFC 7208 section 5.6), no leading zeros
const QNUM = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])';
const IP4_NETWORK = new RegExp(`^${QNUM}(?:\\.${QNUM}){3}$`);

// ip4-cidr-length = "/" ("0" / %x31-39 0*1DIGIT), ip6-cidr-length = "/" ("0" / %x31-39 0*2DIGIT)
const IP4_CIDR = /^(?:0|[1-9][0-9]?)$/;
const IP6_CIDR = /^(?:0|[1-9][0-9]{0,2})$/;

const MAX_NAME_LENGTH = 253;

/**
 * Parses an IP address string. ipaddr.js 2.x reads "::a.b.c.d" as the IPv4-mapped
 * "::ffff:a.b.c.d", so IPv6 input is first canonicalized by the WHATWG URL parser,
 * which spells every address in hex groups.
 *
 * @param {String} value IP address
 * @returns {Object|null} ipaddr.js address object, or null if the value is not an IP address
 */
const parseIp = value => {
    value = (value || '').toString().trim();
    switch (net.isIP(value)) {
        case 4:
            return ipaddr.parse(value);
        case 6: {
            // a zone index is local to the host, it is not part of the address
            let address = value.replace(/%.*$/, '');
            try {
                let canonical = new URL(`http://[${address}]/`).hostname.replace(/^\[|\]$/g, '');
                return ipaddr.parse(canonical);
            } catch (err) {
                return null;
            }
        }
        default:
            return null;
    }
};

/**
 * Checks if an address object is within a network
 *
 * @param {Object} addr ipaddr.js address object
 * @param {Object} network ipaddr.js address object for the network
 * @param {Number} prefix Prefix length
 * @returns {Boolean}
 */
const ipInNetwork = (addr, network, prefix) => {
    if (!addr || !network || addr.kind() !== network.kind()) {
        return false;
    }
    return addr.match(network, prefix);
};

/**
 * Removes a single trailing dot and truncates names longer than 253 characters from the
 * left by removing whole labels (RFC 7208 section 7.3)
 *
 * @param {String} name Domain name
 * @returns {String}
 */
const normalizeTargetName = name => {
    name = (name || '').toString().replace(/\.$/, '');
    while (name.length > MAX_NAME_LENGTH && name.indexOf('.') >= 0) {
        name = name.substring(name.indexOf('.') + 1);
    }
    return name;
};

/**
 * Checks if a (macro expanded) target name can be used as a DNS query name: at least two
 * labels, each 1 to 63 visible ASCII characters or spaces (spaces can be produced by "%_"),
 * and a top label that follows the "toplabel" rule of RFC 7208 section 7.1
 *
 * @param {String} name Domain name, without the trailing dot
 * @returns {Boolean}
 */
const isValidTargetName = name => {
    if (typeof name !== 'string' || !name || name.length > MAX_NAME_LENGTH) {
        return false;
    }
    let labels = name.split('.');
    if (labels.length < 2) {
        return false;
    }
    for (let label of labels) {
        if (!label || label.length > 63 || !/^[\x20-\x2D\x2F-\x7E]+$/.test(label)) {
            return false;
        }
    }
    return TOPLABEL.test(labels[labels.length - 1]);
};

const syntaxError = message => {
    let err = new Error(message);
    err.spfSyntax = true;
    return err;
};

/**
 * Validates a macro-string (RFC 7208 section 7.1)
 *
 * @param {String} input Macro string
 * @param {Object} [options]
 * @param {Boolean} [options.explain] If true, validates an explain-string: SP is allowed and so are the c, r and t macros
 * @param {Boolean} [options.expLetters] If true, allows the c, r and t macros
 * @returns {Array} List of tokens, each either { literal } or { expand }
 * @throws {Error} On syntax errors
 */
const parseMacroString = (input, options) => {
    options = options || {};
    input = (input || '').toString();

    let tokens = [];
    let pos = 0;
    while (pos < input.length) {
        let chr = input.charAt(pos);

        if (chr === '%') {
            let next = input.charAt(pos + 1);
            if (next === '%' || next === '_' || next === '-') {
                tokens.push({ expand: chr + next });
                pos += 2;
                continue;
            }

            if (next !== '{') {
                throw syntaxError('Unexpected % in macro');
            }

            let end = input.indexOf('}', pos + 2);
            if (end < 0) {
                throw syntaxError('Unterminated macro');
            }

            let body = input.substring(pos + 2, end);
            let match = body.match(MACRO_EXPAND);
            if (!match) {
                throw syntaxError(`Invalid macro "%{${body}}"`);
            }

            let letter = match[1].toLowerCase();
            if (!MACRO_LETTERS.includes(letter)) {
                throw syntaxError(`Unknown macro letter "${match[1]}"`);
            }

            if (EXP_ONLY_LETTERS.includes(letter) && !options.explain && !options.expLetters) {
                throw syntaxError(`Macro letter "${match[1]}" is only allowed in explanation text`);
            }

            if (match[2] && Number(match[2]) === 0) {
                throw syntaxError(`Invalid macro "%{${body}}", the number of parts must be nonzero`);
            }

            tokens.push({ expand: input.substring(pos, end + 1) });
            pos = end + 1;
            continue;
        }

        let code = input.charCodeAt(pos);
        // macro-literal = %x21-24 / %x26-7E, explain-string also allows SP
        if ((code >= 0x21 && code <= 0x7e) || (code === 0x20 && options.explain)) {
            if (tokens.length && typeof tokens[tokens.length - 1].literal === 'string') {
                tokens[tokens.length - 1].literal += input.charAt(pos);
            } else {
                tokens.push({ literal: input.charAt(pos) });
            }
            pos++;
            continue;
        }

        throw syntaxError('Invalid character in macro string');
    }

    return tokens;
};

/**
 * Validates a domain-spec: domain-spec = macro-string domain-end,
 * domain-end = ( "." toplabel [ "." ] ) / macro-expand
 *
 * @param {String} input
 * @throws {Error} On syntax errors
 */
const validateDomainSpec = input => {
    let tokens = parseMacroString(input);
    if (!tokens.length) {
        throw syntaxError('Empty domain-spec');
    }

    let last = tokens[tokens.length - 1];
    if (last.expand) {
        return;
    }

    // the domain-spec ends with literal text, so it must end with "." toplabel [ "." ]
    let literal = last.literal.replace(/\.$/, '');
    let dotPos = literal.lastIndexOf('.');
    if (dotPos < 0 || !TOPLABEL.test(literal.substring(dotPos + 1))) {
        throw syntaxError(`Invalid domain-spec "${input}"`);
    }
};

// a/mx: [ ":" domain-spec ] [ dual-cidr-length ]
const DUAL_CIDR_TERM = /^(?::(.+?))?(?:\/([0-9]+))?(?:\/\/([0-9]+))?$/;

const validateCidr = (value, re, max) => {
    if (typeof value !== 'string') {
        return;
    }
    if (!re.test(value) || Number(value) > max) {
        throw syntaxError(`Invalid CIDR length "${value}"`);
    }
};

/**
 * Validates a single term of an SPF record
 *
 * @param {String} term
 * @param {Object} counters Modifier counters, updated in place
 * @throws {Error} On syntax errors
 */
const validateTerm = (term, counters) => {
    let eqPos = term.indexOf('=');
    let sepMatch = term.match(/[:/]/);
    let sepPos = sepMatch ? sepMatch.index : -1;

    if (eqPos >= 0 && (sepPos < 0 || eqPos < sepPos)) {
        // modifier
        let name = term.substring(0, eqPos);
        let value = term.substring(eqPos + 1);
        if (!MODIFIER_NAME.test(name)) {
            throw syntaxError(`Invalid modifier name "${name}"`);
        }

        switch (name.toLowerCase()) {
            case 'redirect':
            case 'exp':
                counters[name.toLowerCase()] = (counters[name.toLowerCase()] || 0) + 1;
                validateDomainSpec(value);
                break;
            default:
                // unknown-modifier = name "=" macro-string, the macro-string may be empty
                parseMacroString(value, { expLetters: true });
        }
        return;
    }

    let match = term.match(/^([+\-?~]?)([^:/]*)(.*)$/);
    let mechanism = match[2].toLowerCase();
    let rest = match[3];

    switch (mechanism) {
        case 'all':
            if (rest) {
                throw syntaxError('Unexpected value for "all"');
            }
            return;

        case 'include':
        case 'exists':
            if (rest.charAt(0) !== ':') {
                throw syntaxError(`Missing domain-spec for "${mechanism}"`);
            }
            validateDomainSpec(rest.substring(1));
            return;

        case 'a':
        case 'mx': {
            let parts = rest.match(DUAL_CIDR_TERM);
            if (!parts) {
                throw syntaxError(`Invalid "${mechanism}" term`);
            }
            if (typeof parts[1] === 'string') {
                validateDomainSpec(parts[1]);
            }
            validateCidr(parts[2], IP4_CIDR, 32);
            validateCidr(parts[3], IP6_CIDR, 128);
            return;
        }

        case 'ptr':
            if (!rest) {
                return;
            }
            if (rest.charAt(0) !== ':') {
                throw syntaxError('Invalid "ptr" term');
            }
            validateDomainSpec(rest.substring(1));
            return;

        case 'ip4': {
            let parts = rest.match(/^:([^/]+)(?:\/([^/]*))?$/);
            if (!parts || !IP4_NETWORK.test(parts[1])) {
                throw syntaxError('Invalid "ip4" term');
            }
            validateCidr(parts[2], IP4_CIDR, 32);
            return;
        }

        case 'ip6': {
            let parts = rest.match(/^:([0-9a-f:.]+)(?:\/([^/]*))?$/i);
            if (!parts || !net.isIPv6(parts[1])) {
                throw syntaxError('Invalid "ip6" term');
            }
            validateCidr(parts[2], IP6_CIDR, 128);
            return;
        }

        default:
            throw syntaxError(`Unknown mechanism "${mechanism}"`);
    }
};

/**
 * Validates the terms of an SPF record (RFC 7208 section 4.6)
 *
 * @param {Array} terms List of terms (the record without the version section, split on SP)
 * @returns {String|false} Description of the first syntax error, or false if the record is valid
 */
const validateTerms = terms => {
    let counters = {};
    try {
        for (let term of terms) {
            validateTerm(term, counters);
        }
    } catch (err) {
        if (err.spfSyntax) {
            return err.message;
        }
        throw err;
    }

    for (let modifier of ['redirect', 'exp']) {
        if (counters[modifier] > 1) {
            return `more than 1 ${modifier} found`;
        }
    }

    return false;
};

module.exports = {
    parseIp,
    ipInNetwork,
    normalizeTargetName,
    isValidTargetName,
    parseMacroString,
    validateTerms
};
