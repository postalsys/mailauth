'use strict';

// DKIM2 signer (draft-ietf-dkim-dkim2-spec-06 section 9)

const crypto = require('node:crypto');
const { getPrivateKey, getCurTime, isSameOrSubdomain } = require('../tools');
const {
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
    parsePath,
    continuesCustody,
    buildSignatureInput
} = require('./fields');
const { parseRecipe } = require('./recipe');
const { Dkim2Parser } = require('./dkim2-parser');
const { ALGORITHM_KEY_TYPES, rsaKeyProblem, signatureData } = require('./key');

// the signing algorithm of each key type
const KEY_ALGORITHMS = new Map(Array.from(ALGORITHM_KEY_TYPES, ([algorithm, keyType]) => [keyType, algorithm]));

const signError = (message, code) => {
    let err = new Error(message);
    err.code = code || 'EDKIM2SIGN';
    return err;
};

// Converts an address to an RFC 5321 path with the angle brackets (sections 8.5 and 8.6)
const toPath = (value, allowNull) => {
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
const loadKey = ({ selector, privateKey, algorithm }) => {
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

    return { selector: selector.toLowerCase(), algorithm: keyAlgorithm, keyObject };
};

const createSignature = (algorithm, input, keyObject) => crypto.sign(...signatureData(algorithm, input), keyObject);

// Validates the signing options and puts them into the form the signer uses
const normalizeOptions = options => {
    options = options || {};

    let signingDomain = (options.signingDomain || '').toString().trim().toLowerCase();
    if (!isDomain(signingDomain)) {
        throw signError(`Invalid signing domain ${JSON.stringify(options.signingDomain)}`, 'EINVALIDDOMAIN');
    }

    let keyList =
        options.signatureData || (options.privateKey ? [{ selector: options.selector, privateKey: options.privateKey, algorithm: options.algorithm }] : []);
    if (!keyList.length) {
        throw signError('No signing keys provided', 'ENOKEY');
    }
    let keys = keyList.map(loadKey);

    // section 8.9: no selector twice, at most two signatures with the same algorithm
    let selectors = new Set();
    let algorithmCounts = new Map();
    for (let { selector, algorithm } of keys) {
        if (selectors.has(selector)) {
            throw signError(`Selector ${selector} is listed more than once`, 'EINVALIDSELECTOR');
        }
        selectors.add(selector);
        algorithmCounts.set(algorithm, (algorithmCounts.get(algorithm) || 0) + 1);
        if (algorithmCounts.get(algorithm) > 2) {
            throw signError(`More than two signatures use ${algorithm}`, 'EINVALIDALGO');
        }
    }

    let result = { signingDomain, keys };

    if (options.nextDomain) {
        // section 8.7: nd= replaces both mf= and rt=
        if (options.mailFrom !== undefined || options.rcptTo !== undefined) {
            throw signError('nextDomain can not be used together with mailFrom or rcptTo', 'EINVALIDOPTS');
        }
        result.nextDomain = options.nextDomain.toString().trim().toLowerCase();
        if (!isDomain(result.nextDomain)) {
            throw signError(`Invalid next domain ${JSON.stringify(options.nextDomain)}`, 'EINVALIDDOMAIN');
        }
    } else {
        // section 9.2: the envelope MUST be available to the signer
        if (options.mailFrom === undefined || options.rcptTo === undefined) {
            throw signError('mailFrom and rcptTo are required, unless nextDomain is set', 'EINVALIDOPTS');
        }
        result.mailFrom = toPath(options.mailFrom, true);
        result.rcptTo = [].concat(options.rcptTo).map(value => toPath(value, false));
        if (!result.rcptTo.length) {
            throw signError('rcptTo needs at least one address', 'EINVALIDOPTS');
        }

        // section 8.8: the d= domain is the MAIL FROM domain or a parent of it
        if (result.mailFrom !== '<>' && !isSameOrSubdomain(parsePath(result.mailFrom).domain, signingDomain)) {
            throw signError(`The MAIL FROM domain does not match the signing domain ${signingDomain}`, 'EINVALIDDOMAIN');
        }
    }

    if (options.nonce !== undefined) {
        result.nonce = options.nonce.toString();
        if (!NONCE.test(result.nonce)) {
            throw signError('A nonce is at most 64 printable ASCII characters with no semicolon', 'EINVALIDOPTS');
        }
    }

    result.flags = [].concat(options.flags || []).map(flag => flag.toString());
    for (let flag of result.flags) {
        if (!TEXTSTRING.test(flag)) {
            throw signError(`Invalid flag ${JSON.stringify(flag)}`, 'EINVALIDOPTS');
        }
    }

    result.hashAlgorithms = Array.from(new Set([].concat(options.hashAlgorithms || ['sha256']).map(algorithm => algorithm.toString().toLowerCase())));
    for (let algorithm of result.hashAlgorithms) {
        if (!HASH_ALGORITHMS.has(algorithm)) {
            throw signError(`Unsupported hash algorithm ${algorithm}`, 'EINVALIDALGO');
        }
    }

    if (options.recipe !== undefined && options.recipe !== null) {
        let parsed = parseRecipe(JSON.stringify(options.recipe));
        if (parsed.error) {
            throw signError(`Invalid recipe: ${parsed.error}`, 'EINVALIDRECIPE');
        }
        result.recipe = options.recipe;
        result.parsedRecipe = parsed.value;
    }

    // section 8.4, the time is read once so that the signed and the emitted t= are the same
    result.t = Math.floor(getCurTime(options.signTime).getTime() / 1000);

    return result;
};

// Reads the DKIM2 header fields that are already on the message. They have to be valid and
// numbered without gaps, otherwise the next numbers are not known
const readChain = (rows, key, parser, label, field) => {
    let map = new Map();
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
    constructor(options) {
        super();
        this.options = normalizeOptions(options);

        // the header fields to put on top of the message, DKIM2-Signature first
        this.signatureHeaders = [];
    }

    async messageHeaders(headers) {
        this.instances = readChain(headers.parsed, MI_KEY, parseMessageInstance, 'Message-Instance', 'm');
        this.signatures = readChain(headers.parsed, SIG_KEY, parseSignature, 'DKIM2-Signature', 'i');

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

    // Section 9.1: a new Message-Instance when the message has no instance yet, or when it has
    // changed since the top one, with a Recipe that recreates the top one
    buildInstance(current) {
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
        } catch (err) {
            throw signError(`Invalid recipe: ${err.message}`, 'EINVALIDRECIPE');
        }

        for (let { algorithm, headerHash, bodyHash } of comparable) {
            let previousBodyHash = previous.bodyHash(algorithm);
            // a null body Recipe declares that the previous body can not be recreated
            if (previous.headerHash(algorithm) !== headerHash || (previousBodyHash !== null && previousBodyHash !== bodyHash)) {
                throw signError(`The recipe does not recreate Message-Instance m=${top.m}`, 'EINVALIDRECIPE');
            }
        }

        return { m: top.m + 1, hashes, recipe: options.recipe };
    }

    // Section 9.3: the new signature continues the chain of custody of the previous one
    checkCustody() {
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

        if (!continuesCustody(previous, options.mailFrom, options.signingDomain)) {
            throw signError(`The signature would break the chain of custody, it does not match a RCPT TO of DKIM2-Signature i=${previous.i}`, 'ECUSTODY');
        }
    }

    async finalChunk() {
        let options = this.options;

        let current = this.currentState();

        let instance = this.buildInstance(current);
        this.checkCustody();

        let instanceHeader = instance ? formatMessageInstance(instance) : null;
        let signature = {
            i: this.signatures.size + 1,
            m: instance ? instance.m : this.instances.size,
            t: options.t,
            signingDomain: options.signingDomain,
            mailFrom: options.mailFrom,
            rcptTo: options.rcptTo,
            nextDomain: options.nextDomain,
            nonce: options.nonce,
            flags: options.flags,
            signatures: options.keys.map(({ selector, algorithm }) => ({ selector, algorithm, signature: '' }))
        };

        // section 9.6: every Message-Instance by m=, every DKIM2-Signature by i=, and the new
        // signature with empty signature values
        let inOrder = map => Array.from({ length: map.size }, (v, index) => map.get(index + 1).line);
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

module.exports = { Dkim2Signer };
