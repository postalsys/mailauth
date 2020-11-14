'use strict';

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
            if (c === quoted) {
                quoted = false;
                state = 'none';
                continue;
            }
            curValue[curKey] += c;
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
            case "'":
                // start quoting
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
                if (state === 'none') {
                    state = 'val';
                    switch (curKey) {
                        case '':
                            curKey = 'key';
                            curValue[curKey] += c;
                            break;
                        case 'key':
                            curKey = 'value';
                            curValue[curKey] += c;
                            break;
                        case 'value':
                        case 'comment':
                            curValue = nextValue();
                            curKey = 'key';
                            curValue[curKey] += c;
                            break;
                    }
                } else {
                    if (curKey === 'comment' && c === '(') {
                        commentLevel++;
                    }
                    curValue[curKey] += c;
                }
        }
    }

    timestamp = timestamp.split(';').shift().trim();

    let result = {};
    for (let val of values) {
        if (val.key) {
            result[val.key] = { value: val.value, comment: val.comment };
        } else if (!result.tls && /tls/i.test(val.comment)) {
            result.tls = { value: val.value, comment: val.comment };
        }
    }

    if (timestamp) {
        result.timestamp = timestamp;
    }

    result.full = (buf || '').toString().replace(/\s+/g, ' ').trim();

    return result;
};

module.exports = { parseReceived };
