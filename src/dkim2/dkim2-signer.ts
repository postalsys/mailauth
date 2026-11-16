// DKIM2 signer (draft-ietf-dkim-dkim2-spec-09 section 12)

import crypto from 'node:crypto';
import { getPrivateKey, getCurTime } from '../tools.js';
import {
    MI_KEY,
    SIG_KEY,
    HASH_ALGORITHMS,
    NONCE,
    TEXTSTRING,
    isDomain,
    parseMessageInstance,
    parseSignature,
    canonicalSignatureField,
    formatMessageInstance,
    formatSignature,
    buildSignatureInput
} from './fields.js';
import { parsePath, relaxedMatch, custodyProblem } from './domains.js';
import { parseRecipe } from './recipe.js';
import { Dkim2Parser } from './dkim2-parser.js';
import { rsaKeyProblem } from './key.js';
import { ALGORITHM_KEY_TYPES, KEY_TYPES, createSignature } from './algorithms.js';
import { createPolicyLookup } from './records.js';
import { checkAuthentic, sameFields } from './from.js';
import type { ChainInstance, ChainSignature, InstanceHash, SignatureFields } from './fields.js';
import type { ParsedRecipe } from './recipe.js';
import type { CurrentState, MessageState } from './message-state.js';
import type { HeaderRow, ParsedHeaders } from '../dkim/message-parser.js';
import type { DKIM2Recipe, DKIM2SignOptions, DKIM2SignatureKey, DNSResolver } from '../types.js';

// A signing key, loaded and checked. `group` is the position of its "|" group in s=
interface SigningKey {
    selector: string;
    algorithm: string;
    keyObject: crypto.KeyObject;
    group: number;
}

// The signing options in the form the signer uses. There is either `nextDomain` or both
// `mailFrom` and `rcptTo`
interface SignerOptions {
    signingDomain: string;
    keys: SigningKey[];
    nextDomain?: string | undefined;
    mailFrom?: string | undefined;
    rcptTo?: string[] | undefined;
    nonce?: string | undefined;
    flags: string[];
    hashAlgorithms: string[];
    recipe?: DKIM2Recipe | undefined;
    parsedRecipe?: ParsedRecipe | undefined;
    t: number;
    resolver?: DNSResolver | undefined;
}

// A new Message-Instance to format
interface NewInstance {
    m: number;
    hashes: InstanceHash[];
    recipe: DKIM2Recipe | undefined;
}

// the signing algorithm of each Node.js key type
const KEY_ALGORITHMS = new Map<string | undefined, string>(
    Array.from(ALGORITHM_KEY_TYPES, ([algorithm, keyType]): [string, string] => [KEY_TYPES.get(keyType)!.nodeType, algorithm])
);

const signError = (message: string, code?: string): Error & { code?: string } => {
    let err: Error & { code?: string } = new Error(message);
    err.code = code || 'EDKIM2SIGN';
    return err;
};

// Converts an address to an RFC 5321 path with the angle brackets (sections 10.5 and 10.6)
const toPath = (value: unknown, allowNull: boolean): string => {
    let path = String(value ?? '').trim();
    if (path && !/^<.*>$/.test(path)) {
        path = `<${path}>`;
    }
    if (!path || path === '<>') {
        if (!allowNull) {
            throw signError('A RCPT TO address can not be empty', 'EINVALIDPATH');
        }
        return '<>';
    }
    if (!/^<[^<>\r\n]+>$/.test(path)) {
        throw signError(`Invalid SMTP path ${JSON.stringify(path)}`, 'EINVALIDPATH');
    }
    return path;
};

// Section 3: the signing algorithm follows the key type
const loadKey = ({ selector, privateKey, algorithm }: Partial<DKIM2SignatureKey> & { privateKey: string | Buffer }, group: number): SigningKey => {
    if (!isDomain(selector)) {
        throw signError(`Invalid selector ${JSON.stringify(selector)}`, 'EINVALIDSELECTOR');
    }

    let keyObject = getPrivateKey(privateKey);
    let keyAlgorithm = KEY_ALGORITHMS.get(keyObject.asymmetricKeyType);
    if (!keyAlgorithm) {
        throw signError(`Unsupported key type ${keyObject.asymmetricKeyType}`, 'EINVALIDALGO');
    }
    if (algorithm && algorithm.toLowerCase() !== keyAlgorithm) {
        throw signError(`Algorithm ${algorithm} does not match the ${keyObject.asymmetricKeyType} key of selector ${selector}`, 'EINVALIDALGO');
    }

    // section 3.2: RSA keys of at least 1024 bits with the public exponent 65537
    let problem = keyObject.asymmetricKeyType === 'rsa' && rsaKeyProblem(keyObject);
    if (problem) {
        throw signError(`The RSA key of selector ${selector} ${problem}`, problem === 'is too short' ? 'ESHORTKEY' : 'EINVALIDKEY');
    }

    return { selector: selector.toLowerCase(), algorithm: keyAlgorithm, keyObject, group };
};

// The signing keys with the position of their "|" group: a list of keys is one group, a list of
// lists is a group per list
const loadKeys = (options: Partial<DKIM2SignOptions>): SigningKey[] => {
    let keyList: (DKIM2SignatureKey | DKIM2SignatureKey[])[] =
        options.signatureData || (options.privateKey ? [{ selector: options.selector!, privateKey: options.privateKey, algorithm: options.algorithm }] : []);

    let keys: SigningKey[] = [];
    if (keyList.length && keyList.every(entry => Array.isArray(entry))) {
        keyList.forEach((group, index) => {
            if (!group.length) {
                throw signError('A group of signing keys is empty', 'ENOKEY');
            }
            keys.push(...group.map(key => loadKey(key, index)));
        });
    } else if (keyList.some(entry => Array.isArray(entry))) {
        throw signError('signatureData is either a list of keys or a list of groups of keys', 'EINVALIDOPTS');
    } else {
        keys = (keyList as DKIM2SignatureKey[]).map(key => loadKey(key, 0));
    }

    if (!keys.length) {
        throw signError('No signing keys provided', 'ENOKEY');
    }

    // section 10.9: no selector twice. The same algorithm may be used with several selectors
    let selectors = new Set<string>();
    for (let { selector } of keys) {
        if (selectors.has(selector)) {
            throw signError(`Selector ${selector} is listed more than once`, 'EINVALIDSELECTOR');
        }
        selectors.add(selector);
    }
    return keys;
};

// Validates the signing options and puts them into the form the signer uses
const normalizeOptions = (options: Partial<DKIM2SignOptions> | undefined): SignerOptions => {
    options = options || {};

    let signingDomain = (options.signingDomain || '').toString().trim().toLowerCase();
    if (!isDomain(signingDomain)) {
        throw signError(`Invalid signing domain ${JSON.stringify(options.signingDomain)}`, 'EINVALIDDOMAIN');
    }

    let result = { signingDomain, keys: loadKeys(options), resolver: options.resolver } as SignerOptions;

    if (options.nextDomain) {
        // section 10.7: nd= replaces both mf= and rt=
        if (options.mailFrom !== undefined || options.rcptTo !== undefined) {
            throw signError('nextDomain can not be used together with mailFrom or rcptTo', 'EINVALIDOPTS');
        }
        result.nextDomain = options.nextDomain.toString().trim().toLowerCase();
        if (!isDomain(result.nextDomain)) {
            throw signError(`Invalid next domain ${JSON.stringify(options.nextDomain)}`, 'EINVALIDDOMAIN');
        }
    } else {
        // section 12.2: the envelope MUST be available to the signer
        if (options.mailFrom === undefined || options.rcptTo === undefined) {
            throw signError('mailFrom and rcptTo are required, unless nextDomain is set', 'EINVALIDOPTS');
        }
        result.mailFrom = toPath(options.mailFrom, true);
        result.rcptTo = ([] as string[]).concat(options.rcptTo).map(value => toPath(value, false));
        if (!result.rcptTo.length) {
            throw signError('rcptTo needs at least one address', 'EINVALIDOPTS');
        }

        // section 10.8: the d= domain is the MAIL FROM domain or a parent of it
        if (result.mailFrom !== '<>' && !relaxedMatch(parsePath(result.mailFrom).domain, signingDomain)) {
            throw signError(`The MAIL FROM domain does not match the signing domain ${signingDomain}`, 'EINVALIDDOMAIN');
        }
    }

    if (options.nonce !== undefined) {
        result.nonce = options.nonce.toString();
        if (!NONCE.test(result.nonce)) {
            throw signError('A nonce is at most 64 printable ASCII characters with no semicolon', 'EINVALIDOPTS');
        }
    }

    result.flags = ([] as string[]).concat(options.flags || []).map(flag => flag.toString());
    for (let flag of result.flags) {
        if (!TEXTSTRING.test(flag)) {
            throw signError(`Invalid flag ${JSON.stringify(flag)}`, 'EINVALIDOPTS');
        }
    }

    result.hashAlgorithms = Array.from(
        new Set(([] as string[]).concat(options.hashAlgorithms || ['sha256']).map(algorithm => algorithm.toString().toLowerCase()))
    );
    for (let algorithm of result.hashAlgorithms) {
        if (!HASH_ALGORITHMS.has(algorithm)) {
            throw signError(`Unsupported hash algorithm ${algorithm}`, 'EINVALIDALGO');
        }
    }

    if (options.recipe !== undefined && options.recipe !== null) {
        let parsed = parseRecipe(JSON.stringify(options.recipe));
        if (parsed.error) {
            throw signError(`Invalid recipe, it ${parsed.error}`, 'EINVALIDRECIPE');
        }
        result.recipe = options.recipe;
        result.parsedRecipe = parsed.value;
    }

    // section 12.6, the time is read once so that the signed and the emitted t= are the same
    result.t = Math.floor(getCurTime(options.signTime).getTime() / 1000);

    return result;
};

// Reads the DKIM2 header fields that are already on the message. They have to be valid and
// numbered without gaps, otherwise the next numbers are not known
const readChain = <F extends 'm' | 'i', T extends { error: string | null } & Record<F, number>>(
    rows: readonly HeaderRow[],
    key: string,
    parser: (line: Buffer) => T,
    label: string,
    field: F
): Map<number, T & { line: Buffer }> => {
    let map = new Map<number, T & { line: Buffer }>();
    for (let row of rows) {
        if (row.key !== key) {
            continue;
        }
        let parsed = parser(row.line);
        if (parsed.error || map.has(parsed[field])) {
            throw signError(`Can not sign a message with an invalid ${label} header field (${parsed.error || 'duplicate'})`, 'EINVALIDCHAIN');
        }
        map.set(parsed[field], Object.assign({ line: row.line }, parsed));
    }
    for (let pos = 1; pos <= map.size; pos++) {
        if (!map.has(pos)) {
            throw signError(`Can not sign a message where ${label} ${field}=${pos} is missing`, 'EINVALIDCHAIN');
        }
    }
    return map;
};

class Dkim2Signer extends Dkim2Parser {
    declare options: SignerOptions;
    declare signatureHeaders: string[];
    declare instances: Map<number, ChainInstance>;
    declare signatures: Map<number, ChainSignature>;
    declare topInstance: ChainInstance | undefined;
    declare i: number;
    declare m: number;

    constructor(options: DKIM2SignOptions) {
        super();
        this.options = normalizeOptions(options);

        // the header fields to put on top of the message, DKIM2-Signature first
        this.signatureHeaders = [];
    }

    override async messageHeaders(headers: ParsedHeaders): Promise<void> {
        this.instances = readChain(headers.parsed, MI_KEY, parseMessageInstance, 'Message-Instance', 'm');
        this.signatures = readChain(headers.parsed, SIG_KEY, parseSignature, 'DKIM2-Signature', 'i') as Map<number, ChainSignature>;

        this.options.hashAlgorithms.forEach(algorithm => this.hashBodyWith(algorithm));
        this.topInstance = this.instances.get(this.instances.size);
        if (this.topInstance) {
            // the hashes of the top instance are compared with the message as it is now
            for (let { algorithm } of this.topInstance.hashes) {
                if (HASH_ALGORITHMS.has(algorithm)) {
                    this.hashBodyWith(algorithm);
                }
            }
            if (Array.isArray(this.options.parsedRecipe?.b)) {
                // the recipe is checked against the previous instance, which needs the body lines
                this.keepBody();
            }
        }
    }

    // Section 12.1: a new Message-Instance when the message has no instance yet, or when it has
    // changed since the top one, with a Recipe that recreates the top one. `previous` is the
    // recreated top instance
    buildInstance(current: CurrentState): (NewInstance & { previous?: MessageState | undefined }) | null {
        let options = this.options;
        let hashes = options.hashAlgorithms.map(algorithm => ({ algorithm, headerHash: current.headerHash(algorithm), bodyHash: current.bodyHash(algorithm) }));

        if (!this.topInstance) {
            return { m: 1, hashes, recipe: options.recipe };
        }

        let top = this.topInstance;
        let comparable = top.hashes.filter(hash => HASH_ALGORITHMS.has(hash.algorithm));
        if (!comparable.length) {
            throw signError(`Message-Instance m=${top.m} has no supported hash algorithm`, 'EINVALIDCHAIN');
        }

        let changed = comparable.some(hash => current.headerHash(hash.algorithm) !== hash.headerHash || current.bodyHash(hash.algorithm) !== hash.bodyHash);
        if (!changed) {
            return null;
        }

        if (!options.parsedRecipe) {
            throw signError(`The message has changed since Message-Instance m=${top.m}, a recipe is required`, 'ENORECIPE');
        }

        let previous;
        try {
            previous = current.previous(options.parsedRecipe);
        } catch (err: any) {
            throw signError(`Invalid recipe, it ${err.message}`, 'EINVALIDRECIPE');
        }

        for (let { algorithm, headerHash, bodyHash } of comparable) {
            let previousBodyHash = previous.bodyHash(algorithm);
            // a null body Recipe declares that the previous body can not be recreated
            if (previous.headerHash(algorithm) !== headerHash || (previousBodyHash !== null && previousBodyHash !== bodyHash)) {
                throw signError(`The recipe does not recreate Message-Instance m=${top.m}`, 'EINVALIDRECIPE');
            }
        }

        return { m: top.m + 1, hashes, recipe: options.recipe, previous };
    }

    // Section 12.2: the new signature continues the chain of custody of the previous one
    checkCustody(): void {
        let options = this.options;
        let previous = this.signatures.get(this.signatures.size);
        if (!previous) {
            return;
        }

        if (previous.nextDomain) {
            if (previous.nextDomain !== options.signingDomain) {
                throw signError(`DKIM2-Signature i=${previous.i} requires the next signing domain to be ${previous.nextDomain}`, 'ECUSTODY');
            }
            return;
        }

        let problem = custodyProblem(previous, options);
        if (problem) {
            throw signError(
                `The signature would break the chain of custody, its ${problem === 'mf' ? 'MAIL FROM' : 'signing'} domain does not match a RCPT TO of DKIM2-Signature i=${previous.i}`,
                'ECUSTODY'
            );
        }
    }

    /**
     * Section 12.4: when the original message is signed, or the From header field was changed,
     * the signing domain has to make the From Authentic (section 11). A subdomain of the From
     * domain does that unless the From domain has a Domain Policy Record with the "strict" flag
     *
     * @param {Object} current The message as it is signed
     * @param {Object} [previous] The message as it was before the change this signer made
     */
    async checkFrom(current: MessageState, previous: MessageState | undefined): Promise<void> {
        let fields = current.fields('from');
        if (this.signatures.size && (!previous || sameFields(previous.fields('from'), fields))) {
            // the From is still the one an earlier signature vouched for
            return;
        }

        let domain = this.options.signingDomain;
        let problem = await checkAuthentic(fields, domain, createPolicyLookup(this.options.resolver));
        if (problem?.result === 'fail') {
            throw signError(`The From header field can not be Authentic with the signing domain ${domain}: ${problem.message}`, 'EFROMNOTAUTHENTIC');
        }
        if (problem) {
            throw signError(`Can not tell if the From header field is Authentic with the signing domain ${domain}: ${problem.message}`, 'EFROMPOLICY');
        }
    }

    override async finalChunk(): Promise<void> {
        let options = this.options;

        let current = this.currentState();

        let instance = this.buildInstance(current);
        this.checkCustody();

        let i = this.signatures.size + 1;
        if (i === 1 && options.flags.includes('exploded')) {
            // section 12.5: the flag MUST NOT be set on the first signature
            throw signError('The exploded flag can not be set on the first DKIM2-Signature', 'EINVALIDOPTS');
        }

        await this.checkFrom(current, instance?.previous);

        let instanceHeader = instance ? formatMessageInstance(instance) : null;
        let signature: SignatureFields = {
            i,
            m: instance ? instance.m : this.instances.size,
            t: options.t,
            signingDomain: options.signingDomain,
            mailFrom: options.mailFrom,
            rcptTo: options.rcptTo,
            nextDomain: options.nextDomain,
            nonce: options.nonce,
            flags: options.flags,
            signatures: options.keys.map(({ selector, algorithm, group }) => ({ selector, algorithm, group, signature: '' }))
        };

        // section 12.8: every Message-Instance by m=, every DKIM2-Signature by i=, and the new
        // signature with empty signature values
        let inOrder = (map: Map<number, { line: Buffer }>): (Buffer | string)[] => Array.from({ length: map.size }, (v, index) => map.get(index + 1)!.line);
        let instanceLines = inOrder(this.instances).concat(instanceHeader || []);
        let signatureLines = inOrder(this.signatures);
        let unsignedHeader = formatSignature(signature);
        let input = buildSignatureInput(instanceLines, signatureLines, unsignedHeader);

        options.keys.forEach(({ algorithm, keyObject }, index) => {
            signature.signatures[index].signature = createSignature(algorithm, input, keyObject).toString('base64');
        });

        let signatureHeader = formatSignature(signature);
        if (!canonicalSignatureField(signatureHeader, true).equals(canonicalSignatureField(unsignedHeader, true))) {
            // the emitted header has to be the one that was signed
            throw signError('The signed and the emitted DKIM2-Signature differ', 'EINTERNAL');
        }

        this.signatureHeaders = [signatureHeader].concat(instanceHeader || []);
        this.i = signature.i;
        this.m = signature.m;
    }
}

export { Dkim2Signer };
