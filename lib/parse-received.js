'use strict';

const { DANGEROUS_KEYS } = require('./safe-keys');
const { isIP } = require('node:net');

const TLS_COMMENT = /tls|cipher=|Google Transport Security/i;

const parseReceived = buf => {
    let header = (buf || '').toString();

    let splitPos = header.indexOf(':');
    if (splitPos < 0) {
        return false;
    }

    let headerValue = header.substr(splitPos + 1).trim();

    let state = 'none';

    let values = [];
    let expect = false;
    let quoted = false;
    let escaped = false;
    let curKey;
    let timestamp = '';
    let commentLevel = 0;

    let nextValue = () => {
        curKey = '';
        let val = { key: '', value: '', comment: '' };
        values.push(val);
        return val;
    };

    let curValue = nextValue();

    // adds a character of a key or a value, starting the next one where needed
    let appendChar = c => {
        if (state === 'none') {
            state = 'val';
            switch (curKey) {
                case '':
                    curKey = 'key';
                    break;
                case 'key':
                    curKey = 'value';
                    break;
                case 'value':
                case 'comment':
                    curValue = nextValue();
                    curKey = 'key';
                    break;
            }
        } else if (curKey === 'comment' && c === '(') {
            commentLevel++;
        }
        curValue[curKey] += c;
    };

    for (let i = 0; i < headerValue.length; i++) {
        let c = headerValue.charAt(i);

        if (state === 'timestamp') {
            timestamp += c;
            continue;
        }

        if (escaped) {
            curValue[curKey] += c;
            escaped = false;
            continue;
        }

        if (quoted) {
            // RFC 5322 quoted-string, kept as it is, quotes included, so that an address
            // such as <"x;y"@example.com> keeps its local-part
            if (c === '\\' && i < headerValue.length - 1) {
                curValue[curKey] += c + headerValue.charAt(++i);
                continue;
            }
            curValue[curKey] += c;
            if (c === '"') {
                quoted = false;
            }
            continue;
        }

        if (expect) {
            if (c === expect) {
                if (commentLevel) {
                    commentLevel--;
                    if (commentLevel) {
                        // still in nested comment
                        curValue[curKey] += c;
                        continue;
                    }
                }
                expect = false;
                state = 'none';
                curValue = nextValue();
                continue;
            }
            if (c === '(') {
                commentLevel++;
            }
            curValue[curKey] += c;
            continue;
        }

        switch (c) {
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                state = 'none';
                break;
            case '"':
                // start quoting. Only the double quote quotes (RFC 5322 section 3.2.4), an
                // apostrophe is an ordinary character, as in <o'brien@example.com>
                appendChar(c);
                quoted = c;
                break;
            case '(':
                // start comment block
                expect = ')';
                commentLevel++;
                curKey = 'comment';
                break;
            case ';':
                state = 'timestamp';
                break;
            case '\\':
                escaped = true;
                break;
            default:
                appendChar(c);
        }
    }

    timestamp = timestamp.split(';').shift().trim();

    let result = {};

    // join non key values into strings
    for (let i = values.length - 1; i > 1; i--) {
        let val = values[i];
        let prev = values[i - 1];
        let key = val.key.toLowerCase();
        if (!['from', 'by', 'with', 'id', 'for', 'envelope-from', ''].includes(key) && prev.key) {
            prev.value = [prev.value || []]
                .concat(val.key || [])
                .concat(val.value || [])
                .join(' ');
            prev.comment = [prev.comment || []].concat(val.comment || []).join(' ');
            values.splice(i, 1);
        }
    }

    // A from clause can have more than one comment after it. Postfix writes the TCP-info
    // comment after the HELO name, and a HELO name with parentheses in it looks like a
    // comment of its own, as in "from x([192.0.2.1]) (unknown [198.51.100.7])". The comments
    // are kept together, in order, so that the TCP-info comment is always the last part
    for (let i = 1; i < values.length; i++) {
        let val = values[i];
        let prev = values[i - 1];
        if (!val.key && !val.value && val.comment && (prev.key || '').toLowerCase() === 'from' && !TLS_COMMENT.test(val.comment)) {
            prev.comment = [prev.comment || []].concat(val.comment).join(' ');
            values.splice(i, 1);
            i--;
        }
    }

    for (let val of values) {
        if (val.comment) {
            val.comment = val.comment.replace(/\s+/g, ' ').trim();
        }
        if (val.key) {
            let key = val.key.toLowerCase();
            if (key !== 'from' && !result.tls && TLS_COMMENT.test(val.comment)) {
                result.tls = { value: '', ...(val.comment && { comment: val.comment }) };
                val.comment = '';
            }
            if (DANGEROUS_KEYS.has(key)) {
                // skip the assignment only: the transport security of the hop is worth keeping
                continue;
            }
            result[key] = { value: val.value, ...(val.comment && { comment: val.comment }) };
        } else if (!result.tls && TLS_COMMENT.test(val.comment)) {
            result.tls = { value: val.value, ...(val.comment && { comment: val.comment }) };
        }
    }

    if (!result.tls && /SMTPS/.test(result?.with?.value)) {
        result.tls = { value: '', comment: result?.with?.value };
    }

    if (timestamp) {
        result.timestamp = timestamp;
    }

    result.full = (buf || '').toString().replace(/\s+/g, ' ').trim();

    return result;
};

// An address literal (RFC 5321 section 4.1.3), with an optional port after it as Exim writes
// it. The content is checked with isIP separately
const ADDRESS_LITERAL = /\[(?:IPv6:)?([^\]\s]+)\](?::\d+)?/gi;
// "helo=" or "ehlo=" right before a literal, the client's own claim, not its address
const HELO_PREFIX = /(?:^|[\s(;,])(?:helo|ehlo)=\s*$/i;
// a word of the Received header, anything up to whitespace or a special character
const WORD = /[^\s()";\\]+/y;

/**
 * Splits the from clause of a Received header into its words and comments, up to the "by"
 * keyword that ends it. The receiving server writes the TCP-info comment after the HELO name,
 * and some servers (Postfix) copy the HELO argument as it was given, spaces, parentheses and
 * quotes included. Such a HELO can look like a TCP-info comment and a "by" keyword of its own,
 * so a header that can not be split without guessing returns false: a comment or a quoted
 * string that is not closed, a stray ")" or a backslash, a quoted string in the from clause,
 * more than one top level "by", or a "by" that is not followed by a host name.
 *
 * @param {String} header Received header
 * @returns {Object|false} { words, comments } of the from clause, or false
 */
const splitFromClause = header => {
    let value = header.substring(header.indexOf(':') + 1);

    let tokens = [];
    let i = 0;
    while (i < value.length) {
        let c = value.charAt(i);

        if (/\s/.test(c)) {
            i++;
            continue;
        }

        if (c === ';') {
            // the date-time part
            break;
        }

        if (c === ')' || c === '\\') {
            return false;
        }

        if (c === '(') {
            // RFC 5322 comment, nested comments are part of it
            let start = i;
            let level = 0;
            for (; i < value.length; i++) {
                let cc = value.charAt(i);
                if (cc === '\\') {
                    return false;
                }
                if (cc === '(') {
                    level++;
                } else if (cc === ')' && --level === 0) {
                    break;
                }
            }
            if (level) {
                return false;
            }
            tokens.push({ type: 'comment', value: value.substring(start + 1, i) });
            i++;
            continue;
        }

        if (c === '"') {
            let end = i + 1;
            while (end < value.length && value.charAt(end) !== '"') {
                // a quoted-pair keeps the next character
                end += value.charAt(end) === '\\' ? 2 : 1;
            }
            if (end >= value.length) {
                return false;
            }
            tokens.push({ type: 'quoted', value: value.substring(i, end + 1) });
            i = end + 1;
            continue;
        }

        WORD.lastIndex = i;
        let word = WORD.exec(value)[0];
        tokens.push({ type: 'word', value: word });
        i += word.length;
    }

    if (tokens[0]?.type !== 'word' || tokens[0].value.toLowerCase() !== 'from') {
        return false;
    }

    let byPositions = [];
    tokens.forEach((token, pos) => {
        if (token.type === 'word' && token.value.toLowerCase() === 'by') {
            byPositions.push(pos);
        }
    });

    if (byPositions.length !== 1 || tokens[byPositions[0] + 1]?.type !== 'word') {
        return false;
    }

    let clause = tokens.slice(1, byPositions[0]);
    if (clause.some(token => token.type === 'quoted')) {
        return false;
    }

    return {
        words: clause.filter(token => token.type === 'word').map(token => token.value),
        comments: clause.filter(token => token.type === 'comment').map(token => token.value)
    };
};

/**
 * Finds the IP address of the client in the from clause of a parsed Received header.
 *
 * RFC 5321 section 4.4 puts the address the connection came from into the TCP-info comment
 * of the from clause, "from helo.name (rdns.name [192.0.2.1])". The rest of the clause is the
 * client's own claim: the HELO name, which can itself be an address literal or hold
 * parentheses, and in Exim's format a "helo=" value inside the comment. Those are never used.
 * Exim writes "from [192.0.2.1] (helo=...)" for a client without reverse DNS, where the literal
 * in front of the comment is the address of the connection, which is only used when no comment
 * has an address literal of its own.
 *
 * Only an unambiguous address is returned. A header that can not be split into a from clause
 * and a single "by" (see splitFromClause), or a from clause with more than one address in its
 * comments, returns false instead of a guess.
 *
 * @param {Object} received Parsed Received header, the result of parseReceived()
 * @returns {String|false} IP address, without an "IPv6:" prefix, or false if none was found
 */
const getClientAddress = received => {
    if (!received || typeof received !== 'object' || typeof received.full !== 'string') {
        return false;
    }

    let clause = splitFromClause(received.full);
    if (!clause) {
        return false;
    }

    let addresses = new Set();
    for (let comment of clause.comments) {
        for (let match of comment.matchAll(ADDRESS_LITERAL)) {
            if (!HELO_PREFIX.test(comment.substring(0, match.index)) && isIP(match[1])) {
                addresses.add(match[1]);
            }
        }
    }

    if (addresses.size === 1) {
        return addresses.values().next().value;
    }

    if (addresses.size > 1) {
        // the HELO name holds an address literal of its own, can not tell which one is real
        return false;
    }

    let valueMatch = clause.words.length === 1 && clause.comments.length && clause.words[0].match(/^\[(?:IPv6:)?([^\]\s]+)\](?::\d+)?$/i);
    if (valueMatch && isIP(valueMatch[1])) {
        return valueMatch[1];
    }

    return false;
};

module.exports = { parseReceived, getClientAddress };
