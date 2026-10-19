// Parsing, formatting and canonicalization of the two DKIM2 header fields, Message-Instance
// and DKIM2-Signature (draft-ietf-dkim-dkim2-spec-06 sections 6, 7, 8 and 9.6)

import { Buffer } from 'node:buffer';
import { formatRelaxedLine, toLineBytes, isValidDnsName, isSameOrSubdomain } from '../tools.js';
import { trimChars, trimEndChars } from '../trim.js';
import { parseRecipe } from './recipe.js';
import type { ParsedRecipe } from './recipe.js';
import type { DKIM2Recipe } from '../types.js';

// One hash-set of the h= tag of a Message-Instance
interface InstanceHash {
    algorithm: string;
    headerHash: string;
    bodyHash: string;
}

// A parsed Message-Instance. Only `m` can be relied on when `error` is set
interface ParsedMessageInstance {
    m: number;
    hashes: InstanceHash[];
    recipe: ParsedRecipe | undefined;
    error: string | null;
}

// One sig-set of the s= tag of a DKIM2-Signature
interface SignatureValue {
    selector: string;
    algorithm: string;
    signature: string;
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
    signatures: SignatureValue[];
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
    signatures: SignatureValue[];
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
    signatures: { selector: string; algorithm: string; signature?: string | undefined }[];
}

// A piece of a header field that a fold can go in front of
interface Atom {
    text: string;
    space: boolean;
}

const MI_KEY = 'message-instance';
const SIG_KEY = 'dkim2-signature';

// Section 4.1: header fields that are not signed, processed as if they were not present
const UNSIGNED_FIELDS = new Set([
    'apparently-to',
    'arc-authentication-results',
    'arc-message-signature',
    'arc-seal',
    'authentication-results',
    'auto-submitted',
    'delivered-to',
    'dkim-signature',
    'dl-expansion-history',
    'original-recipient',
    'received',
    'return-path',
    'sio-label-history',
    'vbr-info',
    'x400-received',
    'x400-trace'
]);

const isUnsignedField = (key: string): boolean => UNSIGNED_FIELDS.has(key) || key.startsWith('received-') || key.startsWith('x-');

// Section 6.2: the header hash leaves out the unsigned fields and the DKIM2 fields themselves
const isHashedField = (key: string | null | undefined): key is string => !!key && key !== MI_KEY && key !== SIG_KEY && !isUnsignedField(key);

const HASH_ALGORITHMS = new Set(['sha256', 'sha512']);

// Section 8.3: at most 64 printable ASCII characters, no semicolon
const NONCE = /^[\x21-\x3a\x3c-\x7e]{0,64}$/;
// Section 2.14 textstring, without the surrounding FWS
const TEXTSTRING = /^[A-Za-z0-9_-]+$/;
// RFC 5234 1*DIGIT. t= values up to 10^12 have to be accepted (section 8.4), 15 digits keep every
// value a safe integer
const NUMBER = /^[0-9]{1,15}$/;
// Section 2.14 base64string with the FWS removed. It "MUST be padded", so the length is a multiple of 4
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
// RFC 5321 Domain, also used for selectors (section 3.5). The underscore is accepted as it is
// in DKIM1 key record names
const DOMAIN_LABEL = '[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?';
const DOMAIN = new RegExp(`^${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})*$`);
// Section 7 and 8 x-tag-name
const TAG_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;

const WSP_ALL = /[ \t\r\n]+/g;

const isBase64 = (value: string | null | undefined): boolean => !!value && BASE64.test(value);
const isDomain = (value: string | null | undefined): value is string => !!value && DOMAIN.test(value) && isValidDnsName(value);

const toNumber = (value: string): number => (NUMBER.test(value) ? Number(value) : NaN);

/**
 * Splits the value of a DKIM2 header field into its tags. Tag names are case insensitive
 * (sections 7 and 8), so they are returned in lower case. Semicolons never occur inside a value.
 *
 * @param {String} value Header field value as a 'binary' string
 * @returns {Object} { tags: Map of name to value with the FWS around it removed, error }
 */
const parseTags = (value: string): { tags: Map<string, string>; error: string | null } => {
    let tags = new Map<string, string>();
    let segments = value.split(';');

    for (let i = 0; i < segments.length; i++) {
        let segment = trimChars(segments[i], ' \t\r\n');
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

        let name = trimEndChars(segment.substring(0, eqPos), ' \t\r\n');
        if (!TAG_NAME.test(name)) {
            return { tags, error: 'invalid tag name' };
        }
        name = name.toLowerCase();

        if (tags.has(name)) {
            return { tags, error: `duplicate tag ${name}` };
        }

        tags.set(name, segment.substring(eqPos + 1).replace(/^[ \t\r\n]+/, ''));
    }

    return { tags, error: null };
};

// the value of a header line, after the colon, as a 'binary' string
const getFieldValue = (line: Buffer | string): string => {
    let str = toLineBytes(line).toString('binary');
    let colonPos = str.indexOf(':');
    return colonPos >= 0 ? str.substring(colonPos + 1) : '';
};

// A list of base64strings, each of which can contain FWS (section 2.14)
const splitBase64List = (value: string): string[] => value.replace(WSP_ALL, '').split(',');

// The value of a tag that can not contain whitespace, such as a number or a domain
const plainValue = (value: string): string | null => (/[ \t\r\n]/.test(value) ? null : value);

/**
 * Parses a Message-Instance header field (section 7)
 *
 * @param {Buffer|String} line Header line
 * @returns {Object} { m, hashes: [{ algorithm, headerHash, bodyHash }], recipe, error }. `m` is
 *          NaN when the m= tag could not be read, `recipe` is undefined without an r= tag
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

    // mi-h-tag: hash-set *("," hash-set), hash-set = hash-name ":" header-hash ":" body-hash
    let seen = new Set<string>();
    for (let hashSet of tags.get('h')!.replace(WSP_ALL, '').split(',')) {
        let parts = hashSet.split(':');
        if (parts.length !== 3 || !TEXTSTRING.test(parts[0]) || !isBase64(parts[1]) || !isBase64(parts[2])) {
            return fail('syntax error');
        }

        let algorithm = parts[0].toLowerCase();
        if (seen.has(algorithm)) {
            return fail('has a duplicate hash algorithm');
        }
        seen.add(algorithm);

        result.hashes.push({ algorithm, headerHash: parts[1], bodyHash: parts[2] });
    }

    if (tags.has('r')) {
        let recipeValue = tags.get('r')!.replace(WSP_ALL, '');
        if (!isBase64(recipeValue)) {
            return fail('syntax error');
        }

        let recipe = parseRecipe(Buffer.from(recipeValue, 'base64').toString('utf8'));
        if (recipe.error) {
            return fail(`contains invalid JSON: ${recipe.error}`);
        }
        result.recipe = recipe.value;
    }

    return result;
};

// Decodes an mf= or rt= path: the base64 encoded RFC 5321 reverse-path or Forward-path, angle
// brackets included (sections 8.5 and 8.6). Returns false for a value that is not a path
const decodePath = (value: string, allowNull: boolean): string | false => {
    if (!isBase64(value)) {
        return false;
    }
    let path = Buffer.from(value, 'base64').toString('utf8');
    if (!/^<[^<>\r\n]*>$/.test(path) || (path === '<>' && !allowNull)) {
        return false;
    }
    return path;
};

/**
 * Parses a DKIM2-Signature header field (section 8)
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
    result.t = toNumber(plainValue(tags.get('t')!) || '');
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
        result.mailFrom = decodePath(tags.get('mf')!.replace(WSP_ALL, ''), true);
        result.rcptTo = splitBase64List(tags.get('rt')!).map(value => decodePath(value, false));
        if (!result.mailFrom || result.rcptTo.some(path => !path)) {
            return fail('syntax error');
        }
    }

    if (tags.has('n')) {
        // section 8.3: implementations SHOULD reject a nonce longer than 64 characters
        result.nonce = tags.get('n')!;
        if (!NONCE.test(result.nonce)) {
            return fail('syntax error');
        }
    }

    if (tags.has('f')) {
        for (let flag of tags.get('f')!.split(',')) {
            flag = trimChars(flag, ' \t\r\n');
            if (!TEXTSTRING.test(flag)) {
                return fail('syntax error');
            }
            // flag values are case significant, and unknown ones are ignored
            result.flags.push(flag);
        }
    }

    // sig-s-tag: sig-set *("," sig-set), sig-set = selector ":" sig-name ":" message-sig
    let selectors = new Set<string>();
    let algorithmCounts = new Map<string, number>();
    for (let sigSet of tags.get('s')!.replace(WSP_ALL, '').split(',')) {
        let parts = sigSet.split(':');
        if (parts.length !== 3 || !isDomain(parts[0]) || !TEXTSTRING.test(parts[1]) || !isBase64(parts[2])) {
            return fail('syntax error');
        }

        let selector = parts[0].toLowerCase();
        let algorithm = parts[1].toLowerCase();

        if (selectors.has(selector)) {
            return fail('has a duplicate selector');
        }
        selectors.add(selector);

        // section 8.9: one additional signature with the same algorithm is allowed
        let count = (algorithmCounts.get(algorithm) || 0) + 1;
        if (count > 2) {
            return fail('has more selectors than allowed');
        }
        algorithmCounts.set(algorithm, count);

        result.signatures.push({ selector, algorithm, signature: parts[2] });
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
// left in it, for the signature input (sections 9.6 and 11.6). Semicolons can not occur inside a
// value, so splitting on them finds the tag the same way the parser does
const blankSignatureValues = (value: string): string =>
    value
        .split(';')
        .map(segment => {
            let eqPos = segment.indexOf('=');
            if (eqPos < 0 || segment.substring(0, eqPos).toLowerCase() !== 's') {
                return segment;
            }
            let sigSets = segment
                .substring(eqPos + 1)
                .split(',')
                .map(sigSet => {
                    // selector:sig-name:value, only the value is emptied. Anything else is a syntax
                    // error that is reported anyway, and is left as it is
                    let parts = sigSet.split(':');
                    return parts.length === 3 ? `${parts[0]}:${parts[1]}:` : sigSet;
                });
            return `${segment.substring(0, eqPos + 1)}${sigSets.join(',')}`;
        })
        .join(';');

/**
 * Canonicalizes a Message-Instance or DKIM2-Signature header field for the signature input
 * (section 9.6): the name in lower case, the field unfolded and every WSP character removed
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
const BASE64_CHUNK = 64;

// Splits a base64 value into pieces a fold can go between. FWS is allowed anywhere inside a
// base64string (section 2.14) and is ignored when the value is used. `lead` is the text in front
// of the value, such as "s=selector:rsa-sha256:", and `space` tells if it starts a new tag
const base64Atoms = (lead: string, value: string, trail?: string, space?: boolean): Atom[] => {
    let atoms: Atom[] = lead ? [{ text: lead, space: space !== false }] : [];
    for (let pos = 0; pos < value.length; pos += BASE64_CHUNK) {
        atoms.push({ text: value.substring(pos, pos + BASE64_CHUNK), space: false });
    }
    if (!atoms.length) {
        atoms.push({ text: '', space: space !== false });
    }
    atoms[atoms.length - 1].text += trail || '';
    return atoms;
};

// Joins the atoms of a header field, folding between them when a line would get too long. An
// atom with `space` set is a new tag and gets a space in front of it when it is not folded
const foldAtoms = (name: string, atoms: Atom[]): string => {
    let lines: string[] = [];
    let line = `${name}:`;
    for (let atom of atoms) {
        let separator = atom.space ? ' ' : '';
        if (line.length + separator.length + atom.text.length > LINE_LENGTH && line.length > name.length + 1) {
            lines.push(line);
            line = ` ${atom.text}`;
        } else {
            line += separator + atom.text;
        }
    }
    lines.push(line);
    return lines.join('\r\n');
};

const plainAtom = (text: string): Atom => ({ text, space: true });

/**
 * Formats a Message-Instance header field
 *
 * @param {Object} options
 * @param {Number} options.m Revision number
 * @param {Object[]} options.hashes [{ algorithm, headerHash, bodyHash }]
 * @param {Object} [options.recipe] Recipe object for the r= tag
 * @returns {String} Folded header line, without the final CRLF
 */
const formatMessageInstance = ({ m, hashes, recipe }: { m: number; hashes: InstanceHash[]; recipe?: DKIM2Recipe | undefined }): string => {
    let atoms = [plainAtom(`m=${m};`)];

    hashes.forEach((hash, index) => {
        // a fold can go before the "," as FWS at the end of the previous base64string
        atoms.push(
            ...base64Atoms(`${index ? ',' : 'h='}${hash.algorithm}:`, hash.headerHash, ':', !index),
            ...base64Atoms('', hash.bodyHash, index === hashes.length - 1 ? ';' : '')
        );
    });

    if (recipe) {
        atoms.push(...base64Atoms('r=', Buffer.from(JSON.stringify(recipe)).toString('base64'), ';'));
    }

    return foldAtoms('Message-Instance', atoms);
};

const encodePath = (path: string): string => Buffer.from(path).toString('base64');

/**
 * Formats a DKIM2-Signature header field. Signature values that are not known yet are written
 * as empty strings, which is the form the signature input uses (section 9.6)
 *
 * @param {Object} options
 * @returns {String} Folded header line, without the final CRLF
 */
const formatSignature = ({ i, m, t, mailFrom, rcptTo, nextDomain, signingDomain, nonce, flags, signatures }: SignatureFields): string => {
    let atoms = [plainAtom(`i=${i};`), plainAtom(`m=${m};`), plainAtom(`t=${t};`), plainAtom(`d=${signingDomain};`)];

    if (nextDomain) {
        atoms.push(plainAtom(`nd=${nextDomain};`));
    } else {
        atoms.push(...base64Atoms('mf=', encodePath(mailFrom!), ';'));
        rcptTo!.forEach((path, index) => {
            atoms.push(...base64Atoms(index ? ',' : 'rt=', encodePath(path), index === rcptTo!.length - 1 ? ';' : '', !index));
        });
    }

    if (typeof nonce === 'string') {
        atoms.push(plainAtom(`n=${nonce};`));
    }

    if (flags?.length) {
        atoms.push(plainAtom(`f=${flags.join(',')};`));
    }

    signatures.forEach((entry, index) => {
        atoms.push(
            ...base64Atoms(
                `${index ? ',' : 's='}${entry.selector}:${entry.algorithm}:`,
                entry.signature || '',
                index === signatures.length - 1 ? ';' : '',
                !index
            )
        );
    });

    return foldAtoms('DKIM2-Signature', atoms);
};

/**
 * Splits an RFC 5321 path into its address, with the domain in lower case as section 11.4
 * compares it. A source route in front of the mailbox is left out
 *
 * @param {String} path Path with or without the angle brackets
 * @returns {Object} { address, domain }, both empty for the null path
 */
const parsePath = (path: string | null | undefined): { address: string; domain: string } => {
    let address = (path || '').toString().trim().replace(/^<|>$/g, '');
    if (address.charAt(0) === '@' && address.indexOf(':') > 0) {
        address = address.substring(address.indexOf(':') + 1);
    }
    let atPos = address.lastIndexOf('@');
    if (atPos < 0) {
        return { address, domain: '' };
    }
    let domain = address.substring(atPos + 1).toLowerCase();
    return { address: `${address.substring(0, atPos)}@${domain}`, domain };
};

/**
 * Section 9.4: whether a hop continues the chain of custody of the hop before it. Its MAIL FROM
 * domain has to match a RCPT TO of the previous hop after removing labels from the left, which is
 * the same as being that domain or one of its subdomains. A hop with nd= has no MAIL FROM, and the
 * null MAIL FROM has no domain, so the signing domain is matched instead: section 8.8 only waives
 * the match of d= and mf= for the null MAIL FROM, never the chain of custody. A previous hop with
 * nd= is checked against the d= of the next hop instead
 *
 * @param {Object} previous Parsed previous DKIM2-Signature
 * @param {String} [mailFrom] MAIL FROM path of the hop
 * @param {String} signingDomain Signing domain of the hop
 * @returns {Boolean}
 */
const continuesCustody = (
    previous: Pick<ChainSignature, 'nextDomain' | 'rcptTo'> | undefined,
    mailFrom: string | undefined,
    signingDomain: string
): boolean => {
    if (!previous || previous.nextDomain) {
        return true;
    }
    let domain = mailFrom && mailFrom !== '<>' ? parsePath(mailFrom).domain : signingDomain;
    return previous.rcptTo!.some(path => isSameOrSubdomain(domain, parsePath(path).domain));
};

/**
 * Builds the signature input of section 9.6: the Message-Instance fields by m=, the
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
