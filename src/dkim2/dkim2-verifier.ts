// DKIM2 verifier (draft-ietf-dkim-dkim2-spec-06 sections 10 and 11)

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { formatAuthHeaderRow, getCurTime, isSameOrSubdomain } from '../tools.js';
import { MI_KEY, SIG_KEY, HASH_ALGORITHMS, parseMessageInstance, parseSignature, parsePath, continuesCustody, buildSignatureInput } from './fields.js';
import { Dkim2Parser } from './dkim2-parser.js';
import { createKeyLookup, KeyError, ALGORITHM_KEY_TYPES, signatureData } from './key.js';
import type { ChainInstance, ChainSignature, ParsedMessageInstance, ParsedSignature } from './fields.js';
import type { DKIM2Key, KeyLookup } from './key.js';
import type { MessageState } from './message-state.js';
import type { ParsedHeaders } from '../dkim/message-parser.js';
import type {
    DKIM2Error,
    DKIM2InstanceResult,
    DKIM2Result,
    DKIM2SignatureResult,
    DKIM2SignatureValueResult,
    DKIM2VerifyOptions,
    DKIM2VerifyResult,
    DKIM2Warning
} from '../types.js';

// A Message-Instance or DKIM2-Signature header field, parsed in messageHeaders() unless there is
// nothing to verify
interface InstanceRow {
    line: Buffer;
    parsed?: ParsedMessageInstance;
}

interface SignatureRow {
    line: Buffer;
    parsed?: ParsedSignature;
}

// The outcome of one DKIM2-Signature, every result other than PASS has a comment
type HopStatus = { result: 'pass'; comment?: undefined } | { result: Exclude<DKIM2Result, 'pass'>; comment: string };

interface HopResult {
    status: HopStatus;
    values: DKIM2SignatureValueResult[];
}

type Replay = NonNullable<DKIM2VerifyResult['replay']>;

type AddError = (result: DKIM2Result, message: string, ref?: { i?: number | undefined; m?: number | undefined }) => void;

type FormatInput =
    | { none: true; errors?: undefined; signatures?: undefined; signatureResults?: undefined; instanceResults?: undefined; replay?: undefined }
    | {
          none?: undefined;
          errors: DKIM2Error[];
          signatures: Map<number, ChainSignature>;
          signatureResults: Map<number, HopResult>;
          instanceResults: DKIM2InstanceResult[];
          replay?: Replay | undefined;
      };

// draft-ietf-dkim-dkim2-bcp-01 section 7.5 recommends a local ceiling on the number of
// Message-Instance and DKIM2-Signature header fields, with a PERMERROR above it
const DEFAULT_MAX_INSTANCES = 20;
// section 11.3: a failure when a signature is more than 14 days old
const DEFAULT_MAX_SIGNATURE_AGE = 14 * 24 * 3600;
// section 8.4: signatures from the future MAY be ignored. Five minutes allows for clock skew
const DEFAULT_MAX_FUTURE_TIME = 5 * 60;

// the order in which a result wins over the others, FAIL first so that a cryptographic failure is
// never reported as a TEMPERROR (section 10.4)
const RESULT_ORDER: DKIM2Result[] = ['fail', 'permerror', 'temperror', 'pass'];

const pickResult = (results: readonly string[]): DKIM2Result => RESULT_ORDER.find(result => results.includes(result)) || 'pass';

// a number from a header field for an error string, "?" when it could not be read
const ordinal = (value: number): number | '?' => (Number.isSafeInteger(value) ? value : '?');

const verifySignature = (algorithm: string, input: Buffer, publicKey: crypto.KeyObject, signature: Buffer): boolean => {
    try {
        return crypto.verify(...signatureData(algorithm, input), publicKey, signature);
    } catch {
        return false;
    }
};

// the first index from 1 that is missing from a map keyed by numbers
const firstGap = (map: Map<number, unknown>): number => {
    let pos = 1;
    while (map.has(pos)) {
        pos++;
    }
    return pos;
};

class Dkim2Verifier extends Dkim2Parser {
    declare options: DKIM2VerifyOptions;
    declare result: DKIM2VerifyResult | null;
    declare maxInstances: number;
    declare instanceRows: InstanceRow[];
    declare signatureRows: SignatureRow[];

    /**
     * @param {Object} [options]
     * @param {Function} [options.resolver] DNS resolver
     * @param {String} [options.mailFrom] SMTP MAIL FROM of the delivery, "" for the null path. When
     *        set, it is checked against the mf= of the highest DKIM2-Signature (section 11.4)
     * @param {String|String[]} [options.rcptTo] SMTP RCPT TO addresses of the delivery, each of
     *        which has to be listed in rt= of the highest DKIM2-Signature
     * @param {Number|Boolean} [options.maxSignatureAge=1209600] Seconds after t= when a signature
     *        expires (section 11.3), false to not check
     * @param {Number|Boolean} [options.maxFutureTime=300] Seconds a t= may be ahead of the current
     *        time (section 8.4), false to not check
     * @param {Date|Number|String} [options.curTime] Time to verify against, defaults to now
     * @param {Number} [options.maxInstances=20] Most Message-Instance, and most DKIM2-Signature,
     *        header fields processed for one message
     * @param {Function} [options.checkReplay] async ({ key, exploded }) => true when a message with
     *        the same m=1 hashes was seen before (section 11.9)
     */
    constructor(options?: DKIM2VerifyOptions | undefined) {
        super();
        this.options = options || {};
        this.result = null;

        this.maxInstances = this.options.maxInstances || DEFAULT_MAX_INSTANCES;
        this.instanceRows = [];
        this.signatureRows = [];
    }

    // too many DKIM2 header fields to process, which verify() reports
    get overLimit(): boolean {
        return this.instanceRows.length > this.maxInstances || this.signatureRows.length > this.maxInstances;
    }

    override async messageHeaders(headers: ParsedHeaders): Promise<void> {
        let rows = headers.parsed;
        this.instanceRows = rows.filter(row => row.key === MI_KEY).map(row => ({ line: row.line }));
        this.signatureRows = rows.filter(row => row.key === SIG_KEY).map(row => ({ line: row.line }));

        if ((!this.instanceRows.length && !this.signatureRows.length) || this.overLimit) {
            // nothing to verify, or nothing that will be verified, so the body is not hashed at all
            return;
        }

        for (let row of this.signatureRows) {
            row.parsed = parseSignature(row.line);
        }

        for (let row of this.instanceRows) {
            row.parsed = parseMessageInstance(row.line);
            // hash the body with every algorithm a Message-Instance uses
            for (let { algorithm } of row.parsed.hashes) {
                if (HASH_ALGORITHMS.has(algorithm)) {
                    this.hashBodyWith(algorithm);
                }
            }
            if (Array.isArray(row.parsed.recipe?.b)) {
                // a body Recipe copies lines from the body, so the body has to be kept
                this.keepBody();
            }
        }
    }

    override async finalChunk(): Promise<void> {
        this.result = await this.verify();
    }

    async verify(): Promise<DKIM2VerifyResult> {
        let errors: DKIM2Error[] = [];
        let instances = new Map<number, ChainInstance>();
        let signatures = new Map<number, ChainSignature>();
        let instanceResults: DKIM2InstanceResult[] = [];
        let signatureResults = new Map<number, HopResult>();

        // the DKIM2-Signature a failure of a Message-Instance is reported against, the one with
        // the lowest i= that covers it (draft-gondwana-dkim2-authres-00 section 3.2.2)
        const signatureFor = (m: number): number | undefined => {
            for (let i = 1; signatures.has(i); i++) {
                if (signatures.get(i)!.m === m) {
                    return i;
                }
            }
            return undefined;
        };

        const addError: AddError = (result, message, ref) => {
            let entry: DKIM2Error = { result, message };
            if (Number.isSafeInteger(ref?.i)) {
                entry.i = ref!.i!;
            }
            if (Number.isSafeInteger(ref?.m)) {
                entry.m = ref!.m!;
                let i = signatureFor(ref!.m!);
                if (i) {
                    entry.i = i;
                }
            }
            errors.push(entry);
        };

        const finish = (replay?: Replay) => this.formatResult({ errors, signatures, signatureResults, instanceResults, replay });

        if (!this.instanceRows.length && !this.signatureRows.length) {
            return this.formatResult({ none: true });
        }

        if (this.overLimit) {
            addError('permerror', `Message has more than ${this.maxInstances} Message-Instance or DKIM2-Signature header fields`);
            return finish();
        }

        // section 11.2: every field is valid, numbered without gaps, and every instance is signed
        for (let { line, parsed } of this.instanceRows as Required<InstanceRow>[]) {
            if (parsed.error) {
                addError('permerror', `Message-Instance m=${ordinal(parsed.m)} ${parsed.error}`);
            } else if (instances.has(parsed.m)) {
                addError('permerror', `Message-Instance m=${parsed.m} appears more than once`);
            } else {
                instances.set(parsed.m, Object.assign({ line }, parsed));
            }
        }

        for (let { line, parsed } of this.signatureRows as Required<SignatureRow>[]) {
            if (parsed.error) {
                addError('permerror', `DKIM2-Signature i=${ordinal(parsed.i)} ${parsed.error}`, { i: parsed.i });
            } else if (signatures.has(parsed.i)) {
                addError('permerror', `DKIM2-Signature i=${parsed.i} appears more than once`, { i: parsed.i });
            } else {
                signatures.set(parsed.i, Object.assign({ line }, parsed) as ChainSignature);
            }
        }

        if (errors.length) {
            return finish();
        }

        let maxM = Math.max(0, ...instances.keys());
        let maxI = Math.max(0, ...signatures.keys());

        let missingM = firstGap(instances);
        if (missingM <= maxM || !maxM) {
            addError('permerror', `Message-Instance m=${missingM} missing`);
        }

        let missingI = firstGap(signatures);
        if (missingI <= maxI || !maxI) {
            addError('permerror', `DKIM2-Signature i=${missingI} missing`);
        }

        if (errors.length) {
            return finish();
        }

        for (let [i, signature] of signatures) {
            if (signature.m > maxM) {
                addError('permerror', `Message-Instance m=${signature.m} missing`, { i });
                return finish();
            }
        }

        let maxSignedM = Math.max(...Array.from(signatures.values()).map(signature => signature.m));
        if (maxM > maxSignedM) {
            addError('permerror', `Message-Instance m=${maxM} is not signed`);
            return finish();
        }

        // recreate every instance of the message by applying the Recipes from the top down
        let current = this.currentState();

        let states = new Map<number, MessageState>([[maxM, current]]);
        for (let m = maxM; m > 1; m--) {
            let state = states.get(m)!;
            let recipe = instances.get(m)!.recipe;
            if (recipe) {
                try {
                    state = state.previous(recipe);
                } catch (err: any) {
                    addError('permerror', `Message-Instance m=${m} contains invalid JSON: ${err.message}`, { m });
                    return finish();
                }
            }
            states.set(m - 1, state);
        }

        // section 11.7: the hashes of every instance
        for (let m = 1; m <= maxM; m++) {
            let instance = instances.get(m)!;
            let state = states.get(m)!;
            let hashResults: DKIM2InstanceResult['hashes'] = [];

            for (let { algorithm, headerHash, bodyHash } of instance.hashes) {
                if (!HASH_ALGORITHMS.has(algorithm)) {
                    // section 3.4: hashes with an unknown algorithm are ignored
                    continue;
                }

                let headerResult: 'pass' | 'fail' = state.headerHash(algorithm) === headerHash ? 'pass' : 'fail';
                if (headerResult === 'fail') {
                    addError('fail', `Message Instance m=${m} header hash ${algorithm} mismatch`, { m });
                }

                // a body before a null body Recipe can not be checked
                let computedBodyHash = state.bodyHash(algorithm);
                let bodyResult: 'pass' | 'fail' | 'unknown' = computedBodyHash === null ? 'unknown' : computedBodyHash === bodyHash ? 'pass' : 'fail';
                if (bodyResult === 'fail') {
                    addError('fail', `Message Instance m=${m} body hash ${algorithm} mismatch`, { m });
                }

                hashResults.push({ algorithm, header: headerResult, body: bodyResult });
            }

            if (!hashResults.length) {
                addError('permerror', `Message-Instance m=${m} has no supported hash algorithm`, { m });
            }

            let entry: DKIM2InstanceResult = { m, hashes: hashResults };
            if (instance.recipe) {
                entry.recipe = {
                    headers: Array.from(instance.recipe.h.keys()),
                    body: instance.recipe.b === undefined ? 'unchanged' : instance.recipe.b === null ? 'unrecoverable' : 'recipe'
                };
            }
            instanceResults.push(entry);
        }

        // section 11.3
        let maxAge = this.options.maxSignatureAge === undefined ? DEFAULT_MAX_SIGNATURE_AGE : this.options.maxSignatureAge;
        let now = Math.floor(getCurTime(this.options.curTime).getTime() / 1000);
        let maxFuture = this.options.maxFutureTime === undefined ? DEFAULT_MAX_FUTURE_TIME : this.options.maxFutureTime;
        for (let [i, signature] of signatures) {
            if (maxAge && now - signature.t > maxAge) {
                addError('permerror', `DKIM2-Signature i=${i} signature expired`, { i });
            }
            // section 8.4: signatures from the future MAY be ignored, and draft-ietf-dkim-dkim2-bcp-01
            // section 3.6 lets verifiers treat them with suspicion
            if (typeof maxFuture === 'number' && signature.t - now > maxFuture) {
                addError('permerror', `DKIM2-Signature i=${i} signature timestamp is in the future`, { i });
            }
        }

        this.checkCustody(signatures, maxI, addError);

        // sections 11.5 and 11.6, from the most recent signature down (section 10.1)
        // the key lookups of every hop run at the same time, the results are recorded in order
        let keyLookup = createKeyLookup(this.options.resolver);
        let hopOrder = Array.from({ length: maxI }, (v, index) => maxI - index);
        let hopResults = await Promise.all(hopOrder.map(i => this.verifyHop(signatures.get(i)!, instances, signatures, keyLookup)));
        hopOrder.forEach((i, index) => {
            let result = hopResults[index];
            signatureResults.set(i, result);
            if (result.status.result !== 'pass') {
                addError(result.status.result, result.status.comment, { i });
            }
        });

        // section 11.8
        let compareAlgorithm = this.bodyHashers.keys().next().value;
        let lastExploded = 0;
        for (let [i, signature] of signatures) {
            if (signature.flags.includes('exploded')) {
                lastExploded = Math.max(lastExploded, i);
            }
        }

        let donotmodify = Array.from(signatures.values()).filter(signature => signature.flags.includes('donotmodify'));
        if (compareAlgorithm && donotmodify.some(signature => !states.get(signature.m)!.isPreservedIn(current, compareAlgorithm))) {
            addError('fail', 'Message has been modified despite a donotmodify request');
        }

        if (Array.from(signatures.values()).some(signature => signature.flags.includes('donotexplode') && signature.i < lastExploded)) {
            addError('fail', 'Message has been exploded despite a donotexplode request');
        }

        // section 11.9: the m=1 hashes identify the message, the exploded flag allows copies
        let firstHashes = instances.get(1)!.hashes;
        let replayHash = firstHashes.find(hash => HASH_ALGORITHMS.has(hash.algorithm)) || firstHashes[0];
        let replay: Replay = {
            key: `${replayHash.algorithm}:${replayHash.headerHash}:${replayHash.bodyHash}`,
            exploded: lastExploded > 0
        };

        if (typeof this.options.checkReplay === 'function') {
            let duplicate = await this.options.checkReplay(Object.assign({}, replay));
            if (duplicate && !replay.exploded) {
                addError('fail', 'Duplicate message with no exploded flag');
            }
        }

        return finish(replay);
    }

    // Section 11.4 and the links between the signatures described in section 9.4
    checkCustody(signatures: Map<number, ChainSignature>, maxI: number, addError: AddError): void {
        for (let i = 1; i <= maxI; i++) {
            let signature = signatures.get(i)!;

            // section 8.8: the d= domain is the mf= domain or a parent of it, unless mf= is null
            if (signature.mailFrom && signature.mailFrom !== '<>' && !isSameOrSubdomain(parsePath(signature.mailFrom).domain, signature.signingDomain)) {
                addError('permerror', `DKIM2-Signature i=${i} MAIL FROM and d= do not match`, { i });
            }

            // section 8.7: nd= names the d= of the next signature exactly
            let next = signatures.get(i + 1);
            if (signature.nextDomain && next && next.signingDomain !== signature.nextDomain) {
                addError('permerror', `DKIM2-Signature i=${i} MAIL nd= does not match`, { i });
            }

            // section 9.4: the MAIL FROM of every hop matches a RCPT TO of the hop before it
            if (!continuesCustody(signatures.get(i - 1), signature.mailFrom, signature.signingDomain)) {
                addError(
                    'permerror',
                    `DKIM2-Signature i=${i} MAIL FROM ${signature.mailFrom && signature.mailFrom !== '<>' ? signature.mailFrom : signature.signingDomain} did not match`,
                    { i }
                );
            }
        }

        let { mailFrom, rcptList, hasMailFrom } = this.envelope();
        if (!hasMailFrom && !rcptList.length) {
            // the delivery is not known, so it can not be compared
            return;
        }

        let top = signatures.get(maxI)!;
        if (top.nextDomain) {
            // section 9.3: without mf= and rt= the delivery can only be accepted on out-of-band information
            addError('permerror', `DKIM2-Signature i=${maxI} unexpected nd= tag`, { i: maxI });
            return;
        }

        // section 11.4: an exact match, domains in lower case, local parts as they are
        if (hasMailFrom && parsePath(mailFrom).address !== parsePath(top.mailFrom).address) {
            addError('permerror', `DKIM2-Signature i=${maxI} MAIL FROM ${mailFrom} did not match`, { i: maxI });
        }

        let listed = new Set(top.rcptTo!.map(path => parsePath(path).address));
        for (let rcpt of rcptList) {
            if (!listed.has(parsePath(rcpt).address)) {
                addError('permerror', `DKIM2-Signature i=${maxI} RCPT TO ${rcpt} did not match`, { i: maxI });
            }
        }
    }

    // the SMTP envelope of the delivery, as far as the caller gave it
    envelope(): { mailFrom: string | undefined; hasMailFrom: boolean; rcptList: string[] } {
        let { mailFrom, rcptTo } = this.options;
        return {
            mailFrom,
            hasMailFrom: typeof mailFrom === 'string',
            rcptList: ([] as string[]).concat(rcptTo || []).filter(value => typeof value === 'string')
        };
    }

    // Without the envelope the highest DKIM2-Signature can not be compared with the delivery
    // (section 11.4), and an unchanged copy of the message sent to anyone else passes as well
    envelopeWarnings(): DKIM2Warning[] {
        let { hasMailFrom, rcptList } = this.envelope();
        let warnings: DKIM2Warning[] = [];
        if (!hasMailFrom) {
            warnings.push('mail-from-not-checked');
        }
        if (!rcptList.length) {
            warnings.push('rcpt-to-not-checked');
        }
        return warnings;
    }

    // Sections 9.6, 11.5 and 11.6 for one DKIM2-Signature
    async verifyHop(
        signature: ChainSignature,
        instances: Map<number, ChainInstance>,
        signatures: Map<number, ChainSignature>,
        keyLookup: KeyLookup
    ): Promise<HopResult> {
        let i = signature.i;

        // the instances it covers, the signatures before it, and itself with the values emptied
        let input = buildSignatureInput(
            Array.from({ length: signature.m }, (v, index) => instances.get(index + 1)!.line),
            Array.from({ length: i - 1 }, (v, index) => signatures.get(index + 1)!.line),
            signature.line
        );

        // start every key lookup before waiting for any of them
        let lookups = signature.signatures.map(({ selector, algorithm }) =>
            ALGORITHM_KEY_TYPES.has(algorithm) ? keyLookup(signature.signingDomain, selector, algorithm) : null
        );
        for (let lookup of lookups) {
            void lookup?.catch(() => false);
        }

        let values: DKIM2SignatureValueResult[] = [];
        for (let [index, { selector, algorithm, signature: value }] of signature.signatures.entries()) {
            let entry: DKIM2SignatureValueResult = { selector, algorithm };
            values.push(entry);

            if (!lookups[index]) {
                // section 3.4: unknown algorithms are ignored
                entry.result = 'none';
                continue;
            }

            let key: DKIM2Key;
            try {
                key = await lookups[index];
            } catch (err) {
                if (!(err instanceof KeyError)) {
                    throw err;
                }
                entry.result = err.result;
                entry.comment = `public key ${selector} ${err.message}`;
                if (err.rr) {
                    entry.rr = err.rr;
                }
                continue;
            }

            entry.result = verifySignature(algorithm, input, key.publicKey!, Buffer.from(value, 'base64')) ? 'pass' : 'fail';
            entry.rr = key.rr;
            if (key.modulusLength) {
                entry.modulusLength = key.modulusLength;
            }
            if (key.testing) {
                // draft-ietf-dkim-dkim2-dns-00 section 3.4.1 t=y: the signer is testing DKIM2
                entry.testing = true;
            }
        }

        let selectorsWith = (result: string): string =>
            values
                .filter(entry => entry.result === result)
                .map(entry => entry.selector)
                .join(', ');

        let status: HopStatus;
        let passed = selectorsWith('pass');
        let failed = selectorsWith('fail');
        let keyErrors = values.filter(entry => (['permerror', 'temperror'] as (string | undefined)[]).includes(entry.result));

        if (failed) {
            // section 11.6: every signature that can be checked is checked, and any failure fails
            status = {
                result: 'fail',
                comment: passed
                    ? `DKIM2-Signature i=${i} ${passed} signature passed, ${failed} signature failed`
                    : `DKIM2-Signature i=${i} ${failed} incorrect signature`
            };
        } else if (passed) {
            status = { result: 'pass' };
        } else if (keyErrors.length) {
            // a TEMPERROR may pass on a later attempt, so it is reported before a PERMERROR
            let keyError = keyErrors.find(entry => entry.result === 'temperror') || keyErrors[0];
            status = { result: keyError.result as 'permerror' | 'temperror', comment: `DKIM2-Signature i=${i} ${keyError.comment}` };
        } else {
            // Section 3.4 has the unknown algorithms ignored, so nothing could be verified and nothing
            // was found incorrect: a PERMERROR by the definitions of section 11.1. The FAIL of section
            // 11.6 step 3 is about the signatures that can be checked
            status = { result: 'permerror', comment: `DKIM2-Signature i=${i} has no supported signature algorithm` };
        }

        return { status, values };
    }

    formatResult({ none, errors, signatures, signatureResults, instanceResults, replay }: FormatInput): DKIM2VerifyResult {
        if (none) {
            let status: DKIM2VerifyResult['status'] = { result: 'none' };
            return { status, info: formatAuthHeaderRow('dkim2', status), errors: [], instances: [], signatures: [] };
        }

        let result = pickResult(errors.map(error => error.result));
        let reported = errors.find(error => error.result === result);

        let signatureList: DKIM2SignatureResult[] = [];
        let hops: string[] = [];
        for (let i = 1; signatures.has(i); i++) {
            let signature = signatures.get(i)!;
            let hop = signatureResults.get(i);

            // the outcome of a hop includes the errors that are reported against it
            let hopResult: DKIM2Result | 'skipped' = hop
                ? pickResult([hop.status.result, ...errors.filter(error => error.i === i).map(error => error.result)])
                : 'skipped';
            hops.push(`i=${i} ${signature.signingDomain} ${hopResult}`);

            let entry: DKIM2SignatureResult = {
                i,
                m: signature.m,
                signingDomain: signature.signingDomain,
                timestamp: signature.t,
                signTime: new Date(signature.t * 1000).toISOString(),
                flags: signature.flags,
                status: hop ? { result: hopResult, comment: hop.status.comment } : { result: 'skipped' },
                values: hop ? hop.values : signature.signatures.map(({ selector, algorithm }) => ({ selector, algorithm }))
            };
            for (let key of ['mailFrom', 'rcptTo', 'nextDomain', 'nonce'] as const) {
                if (signature[key] !== undefined) {
                    // the property of `entry` has the type of the property of `signature`
                    entry[key] = signature[key] as never;
                }
            }
            signatureList.push(entry);
        }

        let status: DKIM2VerifyResult['status'] = { result };
        if (reported) {
            status.comment = reported.message;
        }

        let warnings = this.envelopeWarnings();
        if (warnings.length) {
            // like the DKIM1 warnings, only present when there is something to report and never
            // written into the Authentication-Results text
            status.warnings = warnings;
        }

        // draft-gondwana-dkim2-authres-00 section 3: one resinfo for the message, the hops and the
        // diagnostic in a comment, header.d of the originator, header.i of the failing signature
        let header: { d?: string | undefined; i?: number | undefined } = {};
        if (signatures.has(1)) {
            header.d = signatures.get(1)!.signingDomain;
        }
        if (result !== 'pass' && typeof reported?.i === 'number') {
            header.i = reported.i;
        }
        status.header = header;

        let comment = [hops.join(', '), reported?.message].filter(value => value).join('; ');
        let info = formatAuthHeaderRow('dkim2', { result, comment, header });

        let output: DKIM2VerifyResult = { status, info, errors, instances: instanceResults, signatures: signatureList };
        if (replay) {
            output.replay = replay;
        }
        return output;
    }
}

export { Dkim2Verifier };
