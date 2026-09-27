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

/**
 * Finds the IP address of the client in the from clause of a parsed Received header.
 *
 * RFC 5321 section 4.4 puts the address the connection came from into the TCP-info comment
 * of the from clause, "from helo.name (rdns.name [192.0.2.1])", so it is the last address
 * literal of that comment. The rest of the clause is the client's own claim: the HELO name,
 * which can itself be an address literal, and in Exim's format a "helo=" value inside the
 * comment. Those are never used. Exim writes "from [192.0.2.1] (helo=...)" for a client
 * without reverse DNS, where the literal in front of the comment is the address of the
 * connection, which is only used when the comment has no address literal of its own.
 *
 * @param {Object} from The "from" entry of parseReceived(), { value, comment }
 * @returns {String|false} IP address, without an "IPv6:" prefix, or false if none was found
 */
const getClientAddress = from => {
    if (!from || typeof from !== 'object') {
        return false;
    }

    let comment = typeof from.comment === 'string' ? from.comment : '';
    let value = typeof from.value === 'string' ? from.value.trim() : '';

    let address = false;
    for (let match of comment.matchAll(ADDRESS_LITERAL)) {
        if (HELO_PREFIX.test(comment.substring(0, match.index))) {
            continue;
        }
        if (isIP(match[1])) {
            address = match[1];
        }
    }

    if (address) {
        return address;
    }

    let valueMatch = value.match(/^\[(?:IPv6:)?([^\]\s]+)\](?::\d+)?$/i);
    if (valueMatch && comment && isIP(valueMatch[1])) {
        return valueMatch[1];
    }

    return false;
};

module.exports = { parseReceived, getClientAddress };
