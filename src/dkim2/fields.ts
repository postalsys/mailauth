// Parsing, formatting and canonicalization of the two DKIM2 header fields, Message-Instance
// and DKIM2-Signature (draft-ietf-dkim-dkim2-spec-09 sections 2.14, 4, 6, 7, 8, 9, 10 and 12.8)

import { Buffer } from 'node:buffer';
import { formatRelaxedLine, toLineBytes, isValidDnsName } from '../tools.js';
import { parsePath, isSmtpPath, custodyProblem } from './domains.js';
import { MI_KEY, SIG_KEY, isHashedField } from './signed-fields.js';
import { trimChars } from '../trim.js';
import { parseRecipe } from './recipe.js';
import type { ParsedRecipe } from './recipe.js';
import type { DKIM2Recipe } from '../types.js';

// One hash-set of the h= tag of a Message-Instance. `group` is the position of its "|" group,
// counted from 0 (section 9.3)
interface InstanceHash {
    algorithm: string;
    headerHash: string;
    bodyHash: string;
    group?: number | undefined;
}

// A parsed Message-Instance. Only `m` can be relied on when `error` is set. Parsed hash-sets
// always have their group
interface ParsedMessageInstance {
    m: number;
    hashes: (InstanceHash & { group: number })[];
    recipe: ParsedRecipe | undefined;
    error: string | null;
}

// One sig-set of the s= tag of a DKIM2-Signature. `group` is the position of its "|" group,
// counted from 0 (section 10.9)
interface SignatureValue {
    selector: string;
    algorithm: string;
    signature: string;
    group?: number | undefined;
}

// A parsed DKIM2-Signature. Only `i` can be relied on when `error` is set
interface ParsedSignature {
    i: number;
    m: number;
    t: number;
    nonce: string | undefined;
    mailFrom: string | false | undefined;
    rcptTo: (string | false)[] | undefined;
    nextDomain: string | null | undefined;
    signingDomain: string | null | undefined;
    signatures: (SignatureValue & { group: number })[];
    flags: string[];
    error: string | null;
}

// A Message-Instance of a chain, parsed with no error
interface ChainInstance extends ParsedMessageInstance {
    line: Buffer;
}

// A DKIM2-Signature of a chain, parsed with no error. It has either `nextDomain` or both
// `mailFrom` and `rcptTo`
interface ChainSignature {
    line: Buffer;
    i: number;
    m: number;
    t: number;
    nonce: string | undefined;
    mailFrom: string | undefined;
    rcptTo: string[] | undefined;
    nextDomain: string | undefined;
    signingDomain: string;
    signatures: (SignatureValue & { group: number })[];
    flags: string[];
    error: null;
}

// The values formatSignature() puts into a DKIM2-Signature
interface SignatureFields {
    i: number;
    m: number;
    t: number;
    mailFrom?: string | undefined;
    rcptTo?: string[] | undefined;
    nextDomain?: string | undefined;
    signingDomain: string;
    nonce?: string | undefined;
    flags?: string[] | undefined;
    signatures: { selector: string; algorithm: string; signature?: string | undefined; group?: number | undefined }[];
}

// Section 3.1. Algorithm names are case-sensitive (section 2.14)
const HASH_ALGORITHMS = new Set(['sha256', 'sha512']);

// Section 10.3: at most 64 printable ASCII characters, no semicolon
const NONCE = /^[\x21-\x3a\x3c-\x7e]{0,64}$/;
// Section 2.14 textstring, without the surrounding FWS
const TEXTSTRING = /^[A-Za-z0-9_-]+$/;
// RFC 5234 1*DIGIT for i= and m=. 15 digits keep every value a safe integer
const NUMBER = /^[0-9]{1,15}$/;
// Section 2.14 base64string with the FWS removed. It "MUST be padded", so the length is a multiple of 4
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
// ... and "padded with zero bits": the bits the padding leaves over are zero, so a value has one form
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$/;
// RFC 5321 Domain, also used for selectors (section 3.6). The underscore is accepted as it is
// in DKIM1 key record names
const DOMAIN_LABEL = '[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?';
const DOMAIN = new RegExp(`^${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})*$`);
// Section 8 tag-name. Tag names are case-sensitive, and the DKIM2 tags are all in lower case
const TAG_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;

const WSP = /[ \t\r\n]/;
const WSP_ALL = /[ \t\r\n]+/g;
const WSP_CHARS = ' \t\r\n';

const isBase64 = (value: string | null | undefined): boolean => !!value && BASE64.test(value);
const isDomain = (value: string | null | undefined): value is string => !!value && DOMAIN.test(value) && isValidDnsName(value);

const toNumber = (value: string): number => (NUMBER.test(value) ? Number(value) : NaN);

/**
 * Splits the value of a DKIM2 header field into its tags (section 8). Tag names are
 * case-sensitive, so "M=1" is an unknown tag and not the m= tag. Semicolons never occur inside
 * a value.
 *
 * @param {String} value Header field value as a 'binary' string
 * @returns {Object} { tags: Map of name to value with the FWS around it removed, error }
 */
const parseTags = (value: string): { tags: Map<string, string>; error: string | null } => {
    let tags = new Map<string, string>();
    let segments = value.split(';');

    for (let i = 0; i < segments.length; i++) {
        let segment = trimChars(segments[i], WSP_CHARS);
        if (!segment) {
            // the tag-list ends every tag with a semicolon, and a final one can be left out
            if (i < segments.length - 1) {
                return { tags, error: 'empty tag' };
            }
            continue;
        }

        let eqPos = segment.indexOf('=');
        if (eqPos < 0) {
            return { tags, error: 'tag without a value' };
        }

        let name = trimChars(segment.substring(0, eqPos), WSP_CHARS);
        if (!TAG_NAME.test(name)) {
            return { tags, error: 'invalid tag name' };
        }

        // "if a tag name does occur more than once, the entire tag-list is invalid"
        if (tags.has(name)) {
            return { tags, error: `duplicate tag ${name}` };
        }

        tags.set(name, trimChars(segment.substring(eqPos + 1), WSP_CHARS));
    }

    return { tags, error: null };
};

// the value of a header line, after the colon, as a 'binary' string
const getFieldValue = (line: Buffer | string): string => {
    let str = toLineBytes(line).toString('binary');
    let colonPos = str.indexOf(':');
    return colonPos >= 0 ? str.substring(colonPos + 1) : '';
};

/**
 * Reads a section 2.14 base64string: FWS is allowed between its characters, but not in front of
 * the first one or after the last one
 *
 * @param {String} value Text that has to be exactly one base64string
 * @returns {String|null} The value with the FWS removed, or null when it is not a base64string
 */
const readBase64 = (value: string): string | null => {
    if (!value || WSP.test(value.charAt(0)) || WSP.test(value.charAt(value.length - 1))) {
        return null;
    }
    let plain = value.replace(WSP_ALL, '');
    return plain && CANONICAL_BASE64.test(plain) ? plain : null;
};

// The value of a tag that can not contain whitespace, such as a number or a domain
const plainValue = (value: string): string | null => (WSP.test(value) ? null : value);

/**
 * Splits an h= or s= value into its "|" groups of "," separated items (sections 9.3 and 10.9).
 * FWS is allowed around both separators, so it is removed from both ends of every item
 *
 * @param {String} value Tag value
 * @returns {Array|null} [{ item, group }], or null when an item is empty
 */
const splitGroups = (value: string): { item: string; group: number }[] | null => {
    let items: { item: string; group: number }[] = [];
    let groups = value.split('|');
    for (let group = 0; group < groups.length; group++) {
        for (let item of groups[group].split(',')) {
            item = trimChars(item, WSP_CHARS);
            if (!item) {
                return null;
            }
            items.push({ item, group });
        }
    }
    return items;
};

/**
 * Parses a Message-Instance header field (section 9)
 *
 * @param {Buffer|String} line Header line
 * @returns {Object} { m, hashes: [{ algorithm, headerHash, bodyHash, group }], recipe, error }.
 *          `m` is NaN when the m= tag could not be read, `recipe` is undefined without an r= tag
 */
const parseMessageInstance = (line: Buffer | string): ParsedMessageInstance => {
    let result: ParsedMessageInstance = { m: NaN, hashes: [], recipe: undefined, error: null };
    let { tags, error } = parseTags(getFieldValue(line));

    let mValue = tags.get('m');
    if (typeof mValue === 'string') {
        result.m = toNumber(plainValue(mValue) || '');
    }

    const fail = (message: string) => {
        result.error = message;
        return result;
    };

    if (error) {
        return fail('syntax error');
    }

    for (let tag of ['m', 'h']) {
        if (!tags.has(tag)) {
            return fail(`tag=${tag} missing`);
        }
    }

    if (!(result.m >= 1)) {
        return fail('syntax error');
    }

    // hash-set = hash-name [FWS] ":" header-hash ":" body-hash, where hash-name is a textstring
    // with optional FWS around it, and the base64strings neither start nor end with FWS
    let sets = splitGroups(tags.get('h')!);
    if (!sets) {
        return fail('syntax error');
    }
    let seen = new Set<string>();
    for (let { item, group } of sets) {
        let parts = item.split(':');
        let algorithm = trimChars(parts[0], WSP_CHARS);
        let headerHash = parts.length === 3 ? readBase64(parts[1]) : null;
        let bodyHash = parts.length === 3 ? readBase64(parts[2]) : null;
        if (!TEXTSTRING.test(algorithm) || !headerHash || !bodyHash) {
            return fail('syntax error');
        }

        // section 9.3: an algorithm MUST NOT be present more than once, in any group
        if (seen.has(algorithm)) {
            return fail('has a duplicate hash algorithm');
        }
        seen.add(algorithm);

        result.hashes.push({ algorithm, headerHash, bodyHash, group });
    }

    if (tags.has('r')) {
        let recipeValue = readBase64(tags.get('r')!);
        if (!recipeValue) {
            return fail('syntax error');
        }

        let recipe = parseRecipe(Buffer.from(recipeValue, 'base64'));
        if (recipe.error) {
            return fail(recipe.error);
        }
        result.recipe = recipe.value;
    }

    return result;
};

// Decodes an mf= or rt= path: the base64 encoded RFC 5321 reverse-path or Forward-path, angle
// brackets included (sections 10.5 and 10.6). Returns false for a value that is not a path
const decodePath = (value: string, allowNull: boolean): string | false => {
    let plain = readBase64(value);
    if (!plain) {
        return false;
    }
    let path = Buffer.from(plain, 'base64').toString('utf8');
    if (!isSmtpPath(path) || (path === '<>' && !allowNull)) {
        return false;
    }
    return path;
};

// Section 10.9: sig-set = selector [FWS] ":" [FWS] sig-name [FWS] ":" message-sig
const parseSigSet = (item: string): Omit<SignatureValue, 'group'> | null => {
    let parts = item.split(':');
    if (parts.length !== 3) {
        return null;
    }
    let selector = trimChars(parts[0], WSP_CHARS);
    let algorithm = trimChars(parts[1], WSP_CHARS);
    let signature = readBase64(parts[2]);
    if (!isDomain(selector) || !TEXTSTRING.test(algorithm) || !signature) {
        return null;
    }
    // a selector is a DNS name, which is not case-sensitive
    return { selector: selector.toLowerCase(), algorithm, signature };
};

/**
 * Parses a DKIM2-Signature header field (section 10)
 *
 * @param {Buffer|String} line Header line
 * @returns {Object} { i, m, t, nonce, mailFrom, rcptTo, nextDomain, signingDomain, signatures,
 *          flags, error }. `i` is NaN when the i= tag could not be read
 */
const parseSignature = (line: Buffer | string): ParsedSignature => {
    let result: ParsedSignature = {
        i: NaN,
        m: NaN,
        t: NaN,
        nonce: undefined,
        mailFrom: undefined,
        rcptTo: undefined,
        nextDomain: undefined,
        signingDomain: undefined,
        signatures: [],
        flags: [],
        error: null
    };

    let { tags, error } = parseTags(getFieldValue(line));

    let iValue = tags.get('i');
    if (typeof iValue === 'string') {
        result.i = toNumber(plainValue(iValue) || '');
    }

    const fail = (message: string) => {
        result.error = message;
        return result;
    };

    if (error) {
        return fail('syntax error');
    }

    for (let tag of ['i', 'm', 't', 'd', 's']) {
        if (!tags.has(tag)) {
            return fail(`tag=${tag} missing`);
        }
    }

    // there is either an nd= tag or both mf= and rt=, never both kinds
    if (tags.has('nd')) {
        for (let tag of ['mf', 'rt']) {
            if (tags.has(tag)) {
                return fail(`tag=${tag} was unexpected`);
            }
        }
    } else {
        for (let tag of ['mf', 'rt']) {
            if (!tags.has(tag)) {
                return fail(`tag=${tag} missing`);
            }
        }
    }

    result.m = toNumber(plainValue(tags.get('m')!) || '');
    // t= is any number of digits (section 10.4). One too large to be exact is still far in the
    // future, which section 14.3 reports
    let t = plainValue(tags.get('t')!) || '';
    result.t = /^[0-9]+$/.test(t) ? Number(t) : NaN;
    if (!(result.i >= 1) || !(result.m >= 1) || isNaN(result.t)) {
        return fail('syntax error');
    }

    result.signingDomain = plainValue(tags.get('d')!);
    if (!isDomain(result.signingDomain)) {
        return fail('syntax error');
    }
    result.signingDomain = result.signingDomain.toLowerCase();

    if (tags.has('nd')) {
        result.nextDomain = plainValue(tags.get('nd')!);
        if (!isDomain(result.nextDomain)) {
            return fail('syntax error');
        }
        result.nextDomain = result.nextDomain.toLowerCase();
    } else {
        // sig-rt-tag = "rt" [FWS] "=" base64string *("," base64string), with no FWS around the
        // commas
        result.mailFrom = decodePath(tags.get('mf')!, true);
        result.rcptTo = tags
            .get('rt')!
            .split(',')
            .map(value => decodePath(value, false));
        if (!result.mailFrom || result.rcptTo.some(path => !path)) {
            return fail('syntax error');
        }
    }

    if (tags.has('n')) {
        // section 10.3: at most 64 characters
        result.nonce = tags.get('n')!;
        if (!NONCE.test(result.nonce)) {
            return fail('syntax error');
        }
    }

    if (tags.has('f')) {
        for (let flag of tags.get('f')!.split(',')) {
            flag = trimChars(flag, WSP_CHARS);
            if (!TEXTSTRING.test(flag)) {
                return fail('syntax error');
            }
            // flag values are case-sensitive, and unknown ones have no effect
            result.flags.push(flag);
        }
    }

    // sig-any = sig-all *("|" sig-all), sig-all = sig-set *("," sig-set)
    let sets = splitGroups(tags.get('s')!);
    if (!sets) {
        return fail('syntax error');
    }
    let selectors = new Set<string>();
    for (let { item, group } of sets) {
        let value = parseSigSet(item);
        if (!value) {
            return fail('syntax error');
        }

        // section 10.9: a selector MUST NOT be present more than once. The same algorithm may
        // be used any number of times with different selectors
        if (selectors.has(value.selector)) {
            return fail('has a duplicate selector');
        }
        selectors.add(value.selector);

        result.signatures.push({ ...value, group });
    }

    // section 12.5: the first signature is never "exploded"
    if (result.i === 1 && result.flags.includes('exploded')) {
        return fail('has an exploded flag');
    }

    return result;
};

/**
 * Canonicalizes a header field for the header hash (section 6.2). This is the same
 * transformation as the DKIM1 "relaxed" header canonicalization
 *
 * @param {Buffer|String} line Header line
 * @returns {Buffer} Canonicalized line, ending with CRLF
 */
const canonicalHeaderField = (line: Buffer | string): Buffer => formatRelaxedLine(line, '\r\n');

// Empties the signature values of the s= tag of a DKIM2-Signature value that has no whitespace
// left in it, for the signature input (section 12.8). The selectors, the algorithm names and the
// ":", "," and "|" punctuation stay. Semicolons can not occur inside a value, so splitting on
// them finds the tag the same way the parser does
const blankSignatureValues = (value: string): string =>
    value
        .split(';')
        .map(segment => {
            let eqPos = segment.indexOf('=');
            if (eqPos < 0 || segment.substring(0, eqPos) !== 's') {
                return segment;
            }
            let sigSets = segment
                .substring(eqPos + 1)
                .split(/([,|])/)
                .map(sigSet => {
                    // selector:sig-name:value, only the value is emptied. Anything else is a
                    // separator, or a syntax error that is reported anyway, and is left as it is
                    let parts = sigSet.split(':');
                    return parts.length === 3 ? `${parts[0]}:${parts[1]}:` : sigSet;
                });
            return `${segment.substring(0, eqPos + 1)}${sigSets.join('')}`;
        })
        .join(';');

/**
 * Canonicalizes a Message-Instance or DKIM2-Signature header field for the signature input
 * (section 12.8): the name in lower case, the field unfolded and every WSP character removed
 *
 * @param {Buffer|String} line Header line
 * @param {Boolean} [blank] Empty the signature values of the s= tag
 * @returns {Buffer} Canonicalized line, ending with CRLF
 */
const canonicalSignatureField = (line: Buffer | string, blank?: boolean): Buffer => {
    let str = toLineBytes(line).toString('binary').replace(WSP_ALL, '');
    let colonPos = str.indexOf(':');
    let name = str.substring(0, colonPos).toLowerCase();
    let value = str.substring(colonPos + 1);
    if (blank) {
        value = blankSignatureValues(value);
    }
    return Buffer.from(`${name}:${value}\r\n`, 'binary');
};

// The longest a folded line gets, not counting the CRLF
const LINE_LENGTH = 76;

/**
 * Builds the value of a header field and records where the ABNF allows a fold: in the space
 * between two tags, or between two characters of a base64string (section 2.14). Never next to
 * the ":", "," or "|" that a base64string is joined to, as the ABNF of the hash-sets of h=, the
 * sig-sets of s= and the paths of rt= has no FWS there
 */
class FieldBuilder {
    declare text: string;
    // the positions in `text` that a fold can go in front of
    declare breaks: Set<number>;

    constructor() {
        this.text = '';
        this.breaks = new Set();
    }

    // starts a new tag, separated from the previous one with a space
    tag(text: string): this {
        if (this.text) {
            this.breaks.add(this.text.length);
            this.text += ' ';
        }
        this.text += text;
        return this;
    }

    // text that a fold can not go into or next to
    fixed(text: string): this {
        this.text += text;
        return this;
    }

    // a base64string, a fold can go between any two of its characters
    base64(value: string): this {
        // the ABNF allows FWS before the padding too, but a fold there trips careless readers
        for (let pos = 1; pos < value.length && value.charAt(pos) !== '='; pos++) {
            this.breaks.add(this.text.length + pos);
        }
        this.text += value;
        return this;
    }

    // where the line that starts at `start` is folded: the last break that keeps it within
    // `limit`, or the first one after that for a line that can not be kept short. -1 for none
    nextBreak(start: number, limit: number): number {
        for (let pos = Math.min(limit, this.text.length - 1); pos > start; pos--) {
            if (this.breaks.has(pos)) {
                return pos;
            }
        }
        for (let pos = Math.max(limit, start) + 1; pos < this.text.length; pos++) {
            if (this.breaks.has(pos)) {
                return pos;
            }
        }
        return -1;
    }

    /**
     * Formats the header field, folded so that lines stay within LINE_LENGTH wherever the ABNF
     * allows a fold
     *
     * @param {String} name Header field name
     * @returns {String} Folded header line, without the final CRLF
     */
    format(name: string): string {
        let text = this.text;
        let lines: string[] = [];
        // the start of the current line, the rest comes from text[pos]
        let prefix = `${name}: `;
        let pos = 0;
        while (prefix.length + text.length - pos > LINE_LENGTH) {
            let at = this.nextBreak(pos, pos + LINE_LENGTH - prefix.length);
            if (at < 0) {
                break;
            }
            lines.push(prefix + text.substring(pos, at));
            if (text.charAt(at) === ' ') {
                // the space between two tags becomes the WSP of the fold
                at++;
            }
            prefix = ' ';
            pos = at;
        }
        lines.push(prefix + text.substring(pos));
        return lines.join('\r\n');
    }
}

// the separator in front of an h= or s= entry: "," within a group, "|" between groups. A value
// to format without a group is in the first one
const groupSeparator = (list: { group?: number | undefined }[], index: number): string =>
    (list[index].group || 0) === (list[index - 1].group || 0) ? ',' : '|';

/**
 * Formats a Message-Instance header field
 *
 * @param {Object} options
 * @param {Number} options.m Revision number
 * @param {Object[]} options.hashes [{ algorithm, headerHash, bodyHash, group }]
 * @param {Object} [options.recipe] Recipe object for the r= tag
 * @returns {String} Folded header line, without the final CRLF
 */
const formatMessageInstance = ({ m, hashes, recipe }: { m: number; hashes: InstanceHash[]; recipe?: DKIM2Recipe | undefined }): string => {
    let field = new FieldBuilder().tag(`m=${m};`).tag('h=');

    hashes.forEach((hash, index) => {
        if (index) {
            field.fixed(groupSeparator(hashes, index));
        }
        field.fixed(`${hash.algorithm}:`).base64(hash.headerHash).fixed(':').base64(hash.bodyHash);
    });
    field.fixed(';');

    if (recipe) {
        field
            .tag('r=')
            .base64(Buffer.from(JSON.stringify(recipe)).toString('base64'))
            .fixed(';');
    }

    return field.format('Message-Instance');
};

const encodePath = (path: string): string => Buffer.from(path).toString('base64');

/**
 * Formats a DKIM2-Signature header field. Signature values that are not known yet are written
 * as empty strings, which is the form the signature input uses (section 12.8)
 *
 * @param {Object} options
 * @returns {String} Folded header line, without the final CRLF
 */
const formatSignature = ({ i, m, t, mailFrom, rcptTo, nextDomain, signingDomain, nonce, flags, signatures }: SignatureFields): string => {
    let field = new FieldBuilder().tag(`i=${i};`).tag(`m=${m};`).tag(`t=${t};`).tag(`d=${signingDomain};`);

    if (nextDomain) {
        field.tag(`nd=${nextDomain};`);
    } else {
        field.tag('mf=').base64(encodePath(mailFrom!)).fixed(';');
        field.tag('rt=');
        rcptTo!.forEach((path, index) => {
            field.fixed(index ? ',' : '').base64(encodePath(path));
        });
        field.fixed(';');
    }

    if (typeof nonce === 'string') {
        field.tag(`n=${nonce};`);
    }

    if (flags?.length) {
        field.tag(`f=${flags.join(',')};`);
    }

    field.tag('s=');
    signatures.forEach((entry, index) => {
        if (index) {
            field.fixed(groupSeparator(signatures, index));
        }
        field.fixed(`${entry.selector}:${entry.algorithm}:`);
        if (entry.signature) {
            field.base64(entry.signature);
        }
    });
    field.fixed(';');

    return field.format('DKIM2-Signature');
};

/**
 * Section 7.1 item 1: whether a hop continues the chain of custody of the hop before it, see
 * custodyProblem()
 *
 * @param {Object} previous Parsed previous DKIM2-Signature
 * @param {String} [mailFrom] MAIL FROM path of the hop
 * @param {String} signingDomain Signing domain of the hop
 * @returns {Boolean}
 */
const continuesCustody = (previous: Pick<ChainSignature, 'nextDomain' | 'rcptTo'> | undefined, mailFrom: string | undefined, signingDomain: string): boolean =>
    custodyProblem(previous, { mailFrom, signingDomain }) === null;

/**
 * Builds the signature input of section 12.8: the Message-Instance fields by m=, the
 * DKIM2-Signature fields before the signature by i=, and the signature itself with its signature
 * values emptied
 *
 * @param {Array} instanceLines Message-Instance header lines in m= order
 * @param {Array} signatureLines Earlier DKIM2-Signature header lines in i= order
 * @param {Buffer|String} ownLine The DKIM2-Signature that is signed or verified
 * @returns {Buffer}
 */
const buildSignatureInput = (instanceLines: (Buffer | string)[], signatureLines: (Buffer | string)[], ownLine: Buffer | string): Buffer =>
    Buffer.concat([
        ...instanceLines.map(line => canonicalSignatureField(line)),
        ...signatureLines.map(line => canonicalSignatureField(line)),
        canonicalSignatureField(ownLine, true)
    ]);

export {
    MI_KEY,
    SIG_KEY,
    HASH_ALGORITHMS,
    NONCE,
    TEXTSTRING,
    isHashedField,
    isDomain,
    parseMessageInstance,
    parseSignature,
    canonicalHeaderField,
    canonicalSignatureField,
    formatMessageInstance,
    formatSignature,
    parsePath,
    isBase64,
    continuesCustody,
    buildSignatureInput
};
export type { InstanceHash, ParsedMessageInstance, SignatureValue, ParsedSignature, ChainInstance, ChainSignature, SignatureFields };
