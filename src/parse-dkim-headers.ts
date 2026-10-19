import { DANGEROUS_KEYS } from './safe-keys.js';
import { trimChars } from './trim.js';

/**
 * One tag-spec of a tag-list (RFC 6376 section 3.2), in the order it was written
 */
export interface TagSpec {
    /** Tag name, case preserved */
    name: string;
    /** Tag value, FWS around it removed and inner whitespace collapsed to single spaces */
    value: string;
}

/**
 * A parsed tag, or a parsed resinfo of an Authentication-Results header. A tag-list value is a
 * number for the numeric tags (l=, v=, t=, x= and the i= of an ARC header field). A resinfo also
 * has its comment and the ptype objects of its propspecs, eg. `header: { i: '@example.com' }`
 */
export interface ParsedTag {
    value: string | number;
    comment?: string | undefined;
    [property: string]: any;
}

/**
 * The parsed map of a header field or a tag-list. `header` is the lower case header name and
 * `value` the first key-only part (the authserv-id of an Authentication-Results header).
 * Every other key is a tag name (or a resinfo method) mapped to a ParsedTag, the "dkim" method
 * of an Authentication-Results header maps to a list of them
 */
export interface ParsedTagMap {
    header?: string | undefined;
    value?: string | undefined;
    [key: string]: any;
}

export interface ParseOptions {
    /** Key the map of a tag-list by the tag names as written (RFC 6376 section 3.2) */
    strict?: boolean | undefined;
}

export interface ParsedHeaderField {
    parsed: ParsedTagMap;
    original: Buffer | string;
    /** Tag-lists only, see tagListParser */
    tags?: TagSpec[] | undefined;
    /** Tag-lists only, see tagListParser */
    syntaxErrors?: string[] | undefined;
}

export interface ParsedTagList {
    parsed: ParsedTagMap;
    original: Buffer | string;
    tags: TagSpec[];
    syntaxErrors: string[];
}

// Keys the headerParser result pre-seeds: "header" holds the header name and "value" the
// authserv-id picked from the first key-only part. A crafted part must not overwrite them,
// readers expect strings there, not parsed entry objects. This is a schema fact of this
// parser (valueParser has its own reservation: "header" is a legitimate ptype there).
const RESERVED_RESULT_KEYS = new Set(['header', 'value']);

// Header fields whose value follows the Authentication-Results grammar of RFC 8601 section
// 2.2, which has RFC 5322 comments and quoted strings. Every other header field this module
// is used for (DKIM-Signature, ARC-Seal, ARC-Message-Signature, BIMI-Selector, and the DNS
// records passed in with a "DNS: TXT;" prefix) is a tag-list of RFC 6376 section 3.2, where
// quotes, parentheses and backslashes are ordinary value characters
const AR_HEADERS = new Set<string | undefined>(['authentication-results', 'arc-authentication-results']);

// tags whose values have all whitespace removed (RFC 6376 section 3.5: FWS in b= and bh= is
// ignored, section 3.6.1 allows it anywhere in p=, and h= allows it around the colons)
const WHITESPACE_FREE_TAGS = new Set(['bh', 'b', 'p', 'h']);
// tags whose values are converted to numbers when they look like one
const NUMERIC_TAGS = new Set(['l', 'v', 't', 'x']);

// RFC 6376 section 3.2: tag-name = ALPHA *ALNUMPUNC
const TAG_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;
// FWS around a tag-spec, only SP, HTAB and the CRLF of a fold
const FWS_CHARS = ' \t\r\n';

const normalizeString = (value: string): string => value.replace(/\s+/g, ' ').trim();

// Converts the value of a known tag (lower case `key`) to the form readers expect: no
// whitespace in the values of WHITESPACE_FREE_TAGS, numbers for NUMERIC_TAGS and for the
// instance of an ARC header field
const normalizeTagValue = (key: string, value: string, headerKey: string | undefined): string | number => {
    if (WHITESPACE_FREE_TAGS.has(key)) {
        return value.replace(/\s+/g, '');
    }
    if (NUMERIC_TAGS.has(key) && !isNaN(value as unknown as number)) {
        return Number(value);
    }
    if (key === 'i' && /^arc-/i.test(headerKey || '')) {
        return Number(value);
    }
    return value;
};

// Builds the { key: { value } } map of a tag-list from tags whose values tagListParser has
// already normalized. `caseSensitive` keeps tag names as they are (RFC 6376 section 3.2,
// "Tags MUST be interpreted in a case-sensitive manner"), the default folds them to lower
// case the way this parser always has
const buildTagMap = (tags: TagSpec[], headerKey: string | undefined, caseSensitive: boolean): ParsedTagMap => {
    let result: ParsedTagMap = {
        header: headerKey
    };

    for (let tag of tags) {
        let key = normalizeString(tag.name);
        if (!caseSensitive) {
            key = key.toLowerCase();
        }

        if (!key || RESERVED_RESULT_KEYS.has(key) || DANGEROUS_KEYS.has(key)) {
            continue;
        }

        let value: string | number = tag.value;
        if (!caseSensitive || key === key.toLowerCase()) {
            // every tag name this module interprets is lower case, so in the case-sensitive
            // mode a name with an upper case letter in it is an unknown tag, and unknown tags
            // are kept verbatim
            value = normalizeTagValue(key.toLowerCase(), value, headerKey);
        }

        result[key] = { value };
    }

    return result;
};

/**
 * Parses a tag-list (RFC 6376 section 3.2). Semicolons separate the tag-specs, the first
 * "=" separates a tag name from its value, and nothing else is syntax: a tag-value can hold
 * any printable character except the semicolon, so quotes, parentheses and backslashes in
 * n= notes, z= copies or unknown tags are part of the value.
 *
 * Returns the same shape the parser always had ({ parsed }) plus
 *  - tags: every tag-spec in order, as { name, value }, with the name case preserved and the
 *    value a string (FWS around it removed, inner whitespace collapsed to single spaces)
 *  - syntaxErrors: a list of reasons why the tag-list is not valid RFC 6376 syntax. Empty for
 *    a valid tag-list. The lenient readers ignore it, strict readers reject the tag-list
 *
 * With `strict` set, `parsed` is keyed by the tag names as they are written (RFC 6376 section
 * 3.2) and holds the tag-specs only: key-only parts, which are syntax errors, are left out
 */
const tagListParser = (line: string, headerKey: string | undefined, strict: boolean): { parsed: ParsedTagMap; tags: TagSpec[]; syntaxErrors: string[] } => {
    let tags: TagSpec[] = [];
    // parts without "=" after the first one
    let keyOnly: string[] = [];
    let syntaxErrors: string[] = [];
    let defaultValue: string | undefined;

    let segments = line.split(';');
    let seen = new Set<string>();

    for (let i = 0; i < segments.length; i++) {
        let segment = segments[i];
        let trimmed = trimChars(segment, FWS_CHARS);

        if (!trimmed) {
            // one trailing semicolon is allowed, an empty tag-spec anywhere else is not
            if (i < segments.length - 1 || segments.length === 1) {
                syntaxErrors.push('empty tag-spec');
            }
            continue;
        }

        let eqPos = segment.indexOf('=');
        if (eqPos < 0) {
            syntaxErrors.push(`tag-spec without "=": ${JSON.stringify(normalizeString(trimmed))}`);
            // the first key-only part is the default value, which is how the "DNS: TXT;"
            // prefix and the authserv-id of an AR header have always been exposed
            if (typeof defaultValue === 'undefined') {
                defaultValue = normalizeString(trimmed).toLowerCase();
            } else {
                keyOnly.push(normalizeString(trimmed));
            }
            continue;
        }

        let name = trimChars(segment.substring(0, eqPos), FWS_CHARS);
        let value = normalizeString(segment.substring(eqPos + 1));

        if (!TAG_NAME.test(name)) {
            syntaxErrors.push(`invalid tag name: ${JSON.stringify(normalizeString(name))}`);
        }

        if (seen.has(name)) {
            // RFC 6376 section 3.2: a duplicate tag name makes the entire tag-list invalid
            syntaxErrors.push(`duplicate tag: ${JSON.stringify(name)}`);
        }
        seen.add(name);

        tags.push({ name, value });
    }

    let parsed = buildTagMap(tags, headerKey, strict);

    if (!strict) {
        // key-only parts after the first one were stored as empty values, keep doing that
        for (let name of keyOnly) {
            let key = name.toLowerCase();
            if (key && !RESERVED_RESULT_KEYS.has(key) && !DANGEROUS_KEYS.has(key)) {
                parsed[key] = { value: '' };
            }
        }

        if (typeof defaultValue !== 'undefined') {
            parsed.value = defaultValue;
        }
    }

    return { parsed, tags, syntaxErrors };
};

// Parses the resinfo payload of a single Authentication-Results method, eg.
// `pass header.i=@example.com header.s="sel 1"`, into { value, ptype: { property } }
const valueParser = (str: string): Record<string, any> => {
    let line = str.replace(/\s+/g, ' ').trim();

    let parts: { key: string; value: string }[] = [];

    const createPart = (): { key: string; value: string } => {
        let part = {
            key: '',
            value: ''
        };
        parts.push(part);
        return part;
    };

    const parse = (): Record<string, any> => {
        let state: 'key' | 'value' = 'key';
        let quoted = false;

        let curPart = createPart();

        for (let i = 0; i < line.length; i++) {
            let c = line.charAt(i);

            if (quoted) {
                // RFC 5322 quoted-string, a quoted-pair stands for the character it escapes
                if (c === '\\' && i < line.length - 1) {
                    curPart[state] += line.charAt(++i);
                } else if (c === '"') {
                    quoted = false;
                } else {
                    curPart[state] += c;
                }
                continue;
            }

            switch (c) {
                case '=':
                    if (state === 'key') {
                        state = 'value';
                    } else {
                        curPart[state] += c;
                    }
                    break;

                case ' ':
                    // start new part
                    curPart = createPart();
                    state = 'key';
                    break;

                case '\\':
                    // not meaningful outside a quoted string, kept as an escape of the next
                    // character the way this parser has always read it
                    if (i < line.length - 1) {
                        curPart[state] += line.charAt(++i);
                    }
                    break;

                case '"':
                    quoted = true;
                    break;

                default:
                    curPart[state] += c;
                    break;
            }
        }

        let result: Record<string, any> = {
            value: parts[0].key
        };
        parts.slice(1).forEach(part => {
            if (part.key || part.value) {
                let path = part.key.split('.');

                // A propspec is "ptype.property" (RFC 8601 2.2), so at most two segments, and
                // "value" already holds the method result. Anything else would either overwrite
                // that or nest an object where every reader of this shape expects a string.
                if (path.length > 2 || path.some(p => p === 'value' || DANGEROUS_KEYS.has(p))) {
                    return;
                }

                let curRes: Record<string, any> = result;
                // split() always returns at least one entry
                let final = path.pop() as string;

                for (let p of path) {
                    if (typeof curRes[p] !== 'object' || !curRes[p]) {
                        curRes[p] = {};
                    }
                    curRes = curRes[p];
                }
                curRes[final] = part.value;
            }
        });

        return result;
    };

    return parse();
};

// Authentication-Results grammar (RFC 8601 section 2.2): semicolons separate the resinfo
// parts unless they are inside a comment or a quoted string. Comments (which nest) are
// collected into the comment property of their part, quoted strings are kept as they are,
// quotes and quoted-pairs included, so that valueParser can read them
interface ARPart {
    key: string;
    value: string | number;
    comment: string;
    hasValue: boolean;
}

const arParser = (line: string, headerKey: string | undefined): ParsedTagMap => {
    let parts: ARPart[] = [];
    // always set to 'key' or 'value' before the comment or quoted state is entered
    let lastState: false | 'key' | 'value' = false;

    const createPart = (): ARPart => {
        let part: ARPart = {
            key: '',
            value: '',
            comment: '',
            hasValue: false
        };
        parts.push(part);
        return part;
    };

    let state: 'key' | 'value' | 'comment' | 'quoted' = 'key';
    let commentDepth = 0;

    let curPart = createPart();

    for (let i = 0; i < line.length; i++) {
        let c = line.charAt(i);

        switch (state) {
            // @ts-expect-error TS7029, the fall through to 'value' is intended
            case 'key':
                if (c === '=') {
                    state = 'value';
                    curPart.hasValue = true;
                    break;
                }
            // falls through

            case 'value': {
                switch (c) {
                    case ';':
                        // start new part
                        curPart = createPart();
                        state = 'key';
                        break;

                    case '\\':
                        // not meaningful outside a quoted string or a comment, the next
                        // character is taken as it is
                        if (i < line.length - 1) {
                            curPart[state] += line.charAt(++i);
                        }
                        break;

                    case '(':
                        lastState = state;
                        state = 'comment';
                        commentDepth = 1;
                        if (curPart.comment) {
                            // a second comment in the same part
                            curPart.comment += ' ';
                        }
                        break;

                    case '"':
                        lastState = state;
                        curPart[state] += c;
                        state = 'quoted';
                        break;

                    default:
                        curPart[state] += c;
                        break;
                }

                break;
            }

            case 'comment':
                switch (c) {
                    case '\\':
                        // quoted-pair
                        if (i < line.length - 1) {
                            curPart.comment += line.charAt(++i);
                        }
                        break;

                    case '(':
                        commentDepth++;
                        curPart.comment += c;
                        break;

                    case ')':
                        commentDepth--;
                        if (commentDepth <= 0) {
                            state = lastState as 'key' | 'value';
                        } else {
                            curPart.comment += c;
                        }
                        break;

                    default:
                        curPart.comment += c;
                        break;
                }

                break;

            case 'quoted':
                switch (c) {
                    case '\\':
                        // quoted-pair, kept for valueParser to decode
                        curPart[lastState as 'key' | 'value'] += c;
                        if (i < line.length - 1) {
                            curPart[lastState as 'key' | 'value'] += line.charAt(++i);
                        }
                        break;

                    case '"':
                        state = lastState as 'key' | 'value';
                        curPart[lastState as 'key' | 'value'] += c;
                        break;

                    default:
                        curPart[lastState as 'key' | 'value'] += c;
                        break;
                }

                break;
        }
    }

    for (let i = parts.length - 1; i >= 0; i--) {
        for (let key of Object.keys(parts[i])) {
            if (typeof (parts[i] as unknown as Record<string, unknown>)[key] === 'string') {
                (parts[i] as unknown as Record<string, string>)[key] = normalizeString((parts[i] as unknown as Record<string, string>)[key]);
            }
        }

        parts[i].key = parts[i].key.toLowerCase();

        if (!parts[i].key) {
            // remove empty value
            parts.splice(i, 1);
        } else {
            parts[i].value = normalizeTagValue(parts[i].key, parts[i].value as string, headerKey);
        }
    }

    let result: ParsedTagMap = {
        header: headerKey
    };

    for (let i = 0; i < parts.length; i++) {
        // find the first entry with key only and use it as the default value
        if (parts[i].key && !parts[i].hasValue) {
            result.value = parts[i].key;
            parts.splice(i, 1);
            break;
        }
    }

    parts.forEach(part => {
        if (!part.key || RESERVED_RESULT_KEYS.has(part.key) || DANGEROUS_KEYS.has(part.key)) {
            // nothing would be assigned, so do not parse the part either
            return;
        }

        let entry: ParsedTag = {
            value: part.value
        };

        if (AR_HEADERS.has(headerKey) && typeof part.value === 'string') {
            // parse value into subparts as well
            entry = Object.assign(entry, valueParser(entry.value as string));
        }

        if (part.comment) {
            entry.comment = part.comment;
        }

        if (AR_HEADERS.has(headerKey) && part.key === 'dkim') {
            if (!result[part.key]) {
                result[part.key] = [];
            }
            result[part.key].push(entry);
        } else {
            result[part.key] = entry;
        }
    });

    return result;
};

/**
 * Parses a header field. DKIM-Signature, ARC-Seal, ARC-Message-Signature and other tag-list
 * fields are parsed with the RFC 6376 section 3.2 grammar, Authentication-Results and
 * ARC-Authentication-Results with the RFC 8601 grammar. A value with no header name in front
 * of it is parsed with the RFC 8601 grammar, as it always was; use parseTagList() for a bare
 * tag-list such as a DNS record.
 *
 * @param {Buffer|String} buf Header line
 * @param {Object} [options]
 * @param {Boolean} [options.strict] Key the map of a tag-list by the tag names as written
 *        (RFC 6376 section 3.2), see tagListParser. Authentication-Results are not affected
 * @returns {Object} { parsed, original } and, for tag-lists, also { tags, syntaxErrors }
 */
const headerParser = (buf: Buffer | string, options?: ParseOptions): ParsedHeaderField => {
    let line = (buf || '').toString().trim();
    let splitterPos = line.indexOf(':');
    let headerKey: string | undefined;
    if (splitterPos >= 0) {
        headerKey = line.substring(0, splitterPos).trim().toLowerCase();
        line = line.slice(splitterPos + 1).trim();
    }

    if (headerKey && !AR_HEADERS.has(headerKey)) {
        let { parsed, tags, syntaxErrors } = tagListParser(line, headerKey, !!options?.strict);
        return { parsed, original: buf, tags, syntaxErrors };
    }

    return { parsed: arParser(line, headerKey), original: buf };
};

/**
 * Parses a bare tag-list, such as a DKIM key record, without looking for a header name
 *
 * @param {Buffer|String} value Tag-list
 * @param {Object} [options]
 * @param {Boolean} [options.strict] Key the map by the tag names as written, see tagListParser
 * @returns {Object} { parsed, original, tags, syntaxErrors }
 */
const parseTagList = (value: Buffer | string, options?: ParseOptions): ParsedTagList => {
    let line = (value || '').toString().trim();
    let { parsed, tags, syntaxErrors } = tagListParser(line, undefined, !!options?.strict);
    return { parsed, original: value, tags, syntaxErrors };
};

headerParser.parseTagList = parseTagList;

export default headerParser;

// the properties of the default export, also as named exports for ES module consumers
export { parseTagList };
