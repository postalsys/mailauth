'use strict';

// Independent reference readers for the trace header fields mailauth generates, written from
// the ABNF of RFC 8601 section 2.2 (Authentication-Results) and RFC 7208 section 9.1
// (Received-SPF) with the RFC 5322 lexical tokens they use. They share no code with mailauth.
// Each reader throws on a value that does not follow the grammar, and returns what a consumer
// would see: methods, results, comments and property values with quoting removed.

// RFC 2045 token: any CHAR except SPACE, CTLs and tspecials
const TOKEN_CHAR = /[!#$%&'*+\-.0-9A-Z^_`a-z{|}~\u0080-￿]/;
// RFC 5322 dot-atom-text characters
const ATEXT = /[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~\u0080-￿]/;

// Removes the folding of a header field (RFC 5322 section 2.2.3). A CR or LF that is not part
// of a CRLF followed by WSP is an error
const unfold = value => {
    if (/\r(?!\n[ \t])|(?<!\r)\n/.test(value)) {
        throw new Error('CR or LF outside a fold');
    }
    return value.replace(/\r\n(?=[ \t])/g, '');
};

class Lexer {
    constructor(value) {
        this.s = value;
        this.pos = 0;
        this.comments = [];
    }

    fail(message) {
        throw new Error(`${message} at ${this.pos}: ${JSON.stringify(this.s.slice(this.pos, this.pos + 40))}`);
    }

    peek() {
        return this.s.charAt(this.pos);
    }

    eof() {
        return this.pos >= this.s.length;
    }

    // [CFWS], comments are collected as their unescaped text
    cfws() {
        for (;;) {
            let c = this.peek();
            if (c === ' ' || c === '\t') {
                this.pos++;
            } else if (c === '(') {
                this.comments.push(this.comment());
            } else {
                return;
            }
        }
    }

    // comment = "(" *([FWS] ccontent) [FWS] ")", ccontent = ctext / quoted-pair / comment
    comment() {
        let text = '';
        this.pos++;
        for (;;) {
            if (this.eof()) {
                this.fail('unterminated comment');
            }
            let c = this.peek();
            if (c === ')') {
                this.pos++;
                return text;
            }
            if (c === '(') {
                text += '(' + this.comment() + ')';
            } else if (c === '\\') {
                text += this.quotedPair();
            } else if (/[\x00-\x08\x0a-\x1f\x7f]/.test(c)) {
                this.fail('control character in comment');
            } else {
                text += c;
                this.pos++;
            }
        }
    }

    // quoted-pair = "\" (VCHAR / WSP)
    quotedPair() {
        let c = this.s.charAt(this.pos + 1);
        if (!c || /[\x00-\x08\x0a-\x1f\x7f]/.test(c)) {
            this.fail('invalid quoted-pair');
        }
        this.pos += 2;
        return c;
    }

    // quoted-string, returns the unescaped content
    quotedString() {
        let text = '';
        this.pos++;
        for (;;) {
            if (this.eof()) {
                this.fail('unterminated quoted-string');
            }
            let c = this.peek();
            if (c === '"') {
                this.pos++;
                return text;
            }
            if (c === '\\') {
                text += this.quotedPair();
            } else if (/[\x00-\x08\x0a-\x1f\x7f]/.test(c)) {
                this.fail('control character in quoted-string');
            } else {
                text += c;
                this.pos++;
            }
        }
    }

    run(charRe) {
        let start = this.pos;
        while (!this.eof() && charRe.test(this.peek())) {
            this.pos++;
        }
        return this.s.slice(start, this.pos);
    }

    token() {
        let value = this.run(TOKEN_CHAR);
        if (!value) {
            this.fail('expected a token');
        }
        return value;
    }

    expect(c) {
        if (this.peek() !== c) {
            this.fail(`expected "${c}"`);
        }
        this.pos++;
    }
}

// pvalue = [CFWS] ( value / [ [ local-part ] "@" ] domain-name ) [CFWS], value = token / quoted-string
const readPvalue = lex => {
    lex.cfws();
    let value;
    if (lex.peek() === '"') {
        value = lex.quotedString();
        if (lex.peek() === '@') {
            // a quoted local-part
            lex.pos++;
            value += '@' + lex.run(/[A-Za-z0-9.\-_\u0080-￿]/);
        }
    } else {
        // a token, or [local-part] "@" domain-name, where local-part is a dot-atom
        value = lex.run(/[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.@\u0080-￿]/);
        if (!value) {
            lex.fail('expected a pvalue');
        }
    }
    lex.cfws();
    return value;
};

/**
 * Reads the value of an Authentication-Results header field (RFC 8601 section 2.2)
 *
 * @param {String} value Field value, folded as it was generated
 * @returns {Object} { authservId, results: [{ method, result, comments, props: { 'ptype.property': value } }] }
 */
const parseAuthResults = value => {
    let lex = new Lexer(unfold(value));

    lex.cfws();
    let authservId = lex.peek() === '"' ? lex.quotedString() : lex.token();
    lex.cfws();

    let results = [];
    while (!lex.eof()) {
        lex.expect(';');
        lex.cfws();
        lex.comments = [];

        let method = lex.token();
        lex.cfws();
        lex.expect('=');
        lex.cfws();
        let result = lex.token();
        lex.cfws();

        let props = {};
        while (!lex.eof() && lex.peek() !== ';') {
            let ptype = lex.token();
            if (ptype === 'reason') {
                lex.cfws();
                lex.expect('=');
                props.reason = readPvalue(lex);
                continue;
            }
            lex.cfws();
            let dot = ptype.indexOf('.');
            let property;
            if (dot >= 0) {
                // the token reader takes the "." in "smtp.mailfrom" as part of the token
                property = ptype.slice(dot + 1);
                ptype = ptype.slice(0, dot);
            } else {
                lex.expect('.');
                lex.cfws();
                property = lex.token();
            }
            lex.cfws();
            lex.expect('=');
            let key = `${ptype}.${property}`;
            if (key in props) {
                lex.fail(`duplicate property ${key}`);
            }
            props[key] = readPvalue(lex);
        }

        results.push({ method, result, comments: lex.comments, props });
    }

    return { authservId, results };
};

/**
 * Reads the value of a Received-SPF header field (RFC 7208 section 9.1):
 * result FWS [comment FWS] [ key-value-list ] CRLF, key-value-pair = key [CFWS] "=" ( dot-atom / quoted-string )
 *
 * @param {String} value Field value, folded as it was generated
 * @returns {Object} { result, comments, pairs: { key: value } }
 */
const parseReceivedSpf = value => {
    let lex = new Lexer(unfold(value));

    lex.cfws();
    let result = lex.run(/[a-z]/);
    if (!result) {
        lex.fail('expected a result');
    }
    lex.cfws();

    let pairs = {};
    while (!lex.eof()) {
        let key = lex.run(/[A-Za-z0-9\-_.]/);
        if (!key) {
            lex.fail('expected a key');
        }
        lex.cfws();
        lex.expect('=');
        let pairValue;
        if (lex.peek() === '"') {
            pairValue = lex.quotedString();
        } else {
            pairValue = lex.run(new RegExp(`${ATEXT.source}|\\.`));
            if (!/^[^.]+(?:\.[^.]+)*$/.test(pairValue)) {
                lex.fail('expected a dot-atom');
            }
        }
        if (key in pairs) {
            lex.fail(`duplicate key ${key}`);
        }
        pairs[key] = pairValue;
        lex.cfws();
        if (lex.eof()) {
            break;
        }
        lex.expect(';');
        lex.cfws();
    }

    return { result, comments: lex.comments, pairs };
};

module.exports = { unfold, parseAuthResults, parseReceivedSpf };
