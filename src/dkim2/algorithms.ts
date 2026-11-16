// DKIM2 signing algorithms (draft-ietf-dkim-dkim2-spec-09 section 3): RSA-SHA256, Ed25519-SHA256
// and ML-DSA-44, the key types of their key records, and signing and verifying with them

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { mlDsa44Verify } from './mldsa44.js';

// Section 3.4: the ML-DSA context string
const MLDSA_CONTEXT = Buffer.from('DKIM2');

// The key types of the key records (k= values): the Node.js asymmetricKeyType, and for a key
// type that publishes the bare key, its length (section 14.5) and the SubjectPublicKeyInfo prefix
// that turns it into a key Node.js reads (RFC 8410 for Ed25519, RFC 9881 for ML-DSA-44)
const KEY_TYPES = new Map<string, { nodeType: string; rawLength?: number; prefix?: Buffer }>([
    ['rsa', { nodeType: 'rsa' }],
    ['ed25519', { nodeType: 'ed25519', rawLength: 32, prefix: Buffer.from('302a300506032b6570032100', 'hex') }],
    ['mldsa44', { nodeType: 'ml-dsa-44', rawLength: 1312, prefix: Buffer.from('30820532300b06096086480165030403110382052100', 'hex') }]
]);

// The key type of each signing algorithm, section 10.9 has the k= value match the algorithm
const ALGORITHM_KEY_TYPES = new Map<string, string>([
    ['rsa-sha256', 'rsa'],
    ['ed25519-sha256', 'ed25519'],
    ['mldsa44', 'mldsa44']
]);

/**
 * Builds the public key of a bare Ed25519 or ML-DSA-44 key
 *
 * @param {String} keyType k= value
 * @param {Buffer} raw The bare key
 * @returns {KeyObject}
 * @throws {Error} When the key can not be read
 */
const rawPublicKey = (keyType: string, raw: Buffer): crypto.KeyObject =>
    crypto.createPublicKey({ key: Buffer.concat([KEY_TYPES.get(keyType)!.prefix!, raw]), format: 'der', type: 'spki' });

let mlDsaSupport: boolean | undefined;

/**
 * Whether this Node.js version implements ML-DSA-44. Node.js 24 does, earlier versions do not
 *
 * @returns {Boolean}
 */
const supportsMlDsa = (): boolean => {
    if (mlDsaSupport === undefined) {
        try {
            mlDsaSupport =
                rawPublicKey('mldsa44', Buffer.alloc(KEY_TYPES.get('mldsa44')!.rawLength!)).asymmetricKeyType ===
                (KEY_TYPES.get('mldsa44')!.nodeType as crypto.KeyObject['asymmetricKeyType']);
        } catch {
            mlDsaSupport = false;
        }
    }
    return mlDsaSupport;
};

/**
 * Whether a signing algorithm can be verified. Section 3 has verifiers implement all of them:
 * ML-DSA-44 is verified with node:crypto where Node.js has it, and with mldsa44.ts where it does
 * not. An algorithm that is not implemented is a PERMERROR for its signature (section 14.6 step 4)
 *
 * @param {String} algorithm sig-name, case-sensitive
 * @returns {Boolean}
 */
const isSupportedAlgorithm = (algorithm: string): boolean => ALGORITHM_KEY_TYPES.has(algorithm);

// Sections 3.2 to 3.4: the hash name and the data for crypto.sign() and crypto.verify(). RSA
// PKCS#1 v1.5 hashes the input itself, Ed25519 (PureEdDSA) signs the SHA-256 hash of it, ML-DSA-44
// signs the input itself
const signatureData = (algorithm: string, input: Buffer): [string | null, Buffer] => {
    switch (algorithm) {
        case 'ed25519-sha256':
            return [null, crypto.createHash('sha256').update(input).digest()];
        case 'mldsa44':
            return [null, input];
        default:
            return ['sha256', input];
    }
};

// The key argument of crypto.sign() and crypto.verify(), with the "DKIM2" context for ML-DSA-44
const keyInput = (algorithm: string, key: crypto.KeyObject): crypto.KeyObject | crypto.SignKeyObjectInput =>
    // @types/node does not know the context option yet
    algorithm === 'mldsa44' ? ({ key, context: MLDSA_CONTEXT } as crypto.SignKeyObjectInput) : key;

/**
 * Signs the signature input of section 12.8
 *
 * @param {String} algorithm Signing algorithm
 * @param {Buffer} input Signature input
 * @param {KeyObject} privateKey Private key of the algorithm
 * @returns {Buffer} Signature
 */
const createSignature = (algorithm: string, input: Buffer, privateKey: crypto.KeyObject): Buffer =>
    crypto.sign(...signatureData(algorithm, input), keyInput(algorithm, privateKey));

/**
 * Checks a signature over the signature input of section 12.8
 *
 * @param {String} algorithm Signing algorithm
 * @param {Buffer} input Signature input
 * @param {KeyObject|Buffer} publicKey Public key of the algorithm, or the bare ML-DSA-44 key where
 *        Node.js has no ML-DSA
 * @param {Buffer} signature Signature value
 * @returns {Boolean}
 */
const verifySignature = (algorithm: string, input: Buffer, publicKey: crypto.KeyObject | Buffer, signature: Buffer): boolean => {
    if (Buffer.isBuffer(publicKey)) {
        // the bare ML-DSA-44 key, on a Node.js version without ML-DSA
        return algorithm === 'mldsa44' && mlDsa44Verify(publicKey, input, signature, MLDSA_CONTEXT);
    }
    try {
        return crypto.verify(...signatureData(algorithm, input), keyInput(algorithm, publicKey), signature);
    } catch {
        return false;
    }
};

export { ALGORITHM_KEY_TYPES, KEY_TYPES, rawPublicKey, supportsMlDsa, isSupportedAlgorithm, signatureData, createSignature, verifySignature };
