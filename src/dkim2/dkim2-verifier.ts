// DKIM2 verifier (draft-ietf-dkim-dkim2-spec-09 sections 13 and 14)

import { Buffer } from 'node:buffer';
import { formatAuthHeaderRow, getCurTime } from '../tools.js';
import { MI_KEY, SIG_KEY, HASH_ALGORITHMS, parseMessageInstance, parseSignature, buildSignatureInput } from './fields.js';
import { parsePath, relaxedMatch, custodyProblem } from './domains.js';
import { Dkim2Parser } from './dkim2-parser.js';
import { createKeyLookup, KeyError } from './key.js';
import { isSupportedAlgorithm, verifySignature } from './algorithms.js';
import { createPolicyLookup } from './records.js';
import { checkAuthentic, sameFields } from './from.js';
import type { ChainInstance, ChainSignature, InstanceHash, ParsedMessageInstance, ParsedSignature } from './fields.js';
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

// The intermediate result of one hash-set or signature, with the text that explains it
interface Intermediate {
    result: DKIM2Result;
    group: number;
    messages: string[];
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
// section 14.3: not Fully Verified when a signature is more than 14 days old
const DEFAULT_MAX_SIGNATURE_AGE = 14 * 24 * 3600;
// section 14.3: nor when a timestamp is more than one day ahead
const DEFAULT_MAX_FUTURE_TIME = 24 * 3600;

// The order in which the result of one check wins over the others when all of them have to
// pass, the "sig-all" rule of section 14.6 step 6: FAIL, then PERMERROR, and TEMPERROR only when
// every result that is not a PASS is a TEMPERROR, so that a failure is never reported as temporary
const ALL_ORDER: DKIM2Result[] = ['fail', 'permerror', 'temperror', 'pass'];
// The "sig-any" rule of section 14.6 step 7, when one group has to pass: a PASS, then a
// TEMPERROR that a later attempt may turn into a PASS, then FAIL
const ANY_ORDER: DKIM2Result[] = ['pass', 'temperror', 'fail', 'permerror'];

const pickResult = (results: readonly string[]): DKIM2Result => ALL_ORDER.find(result => results.includes(result)) || 'pass';

/**
 * Combines intermediate results with the AND/OR rules of sections 14.6 and 14.7: the entries of
 * a group all have to pass, and one group has to pass. Hash-sets never have a TEMPERROR, so the
 * same rules give the result of section 14.7
 *
 * @param {Object[]} entries [{ result, group, messages }]
 * @param {String} noGroup The message for a FAIL when there are several groups and none passed
 * @returns {Object} { result, messages } where `messages` explain a result other than PASS
 */
const combine = (entries: Intermediate[], noGroup: string): { result: DKIM2Result; messages: string[] } => {
    let groups = new Map<number, Intermediate[]>();
    for (let entry of entries) {
        groups.set(entry.group, (groups.get(entry.group) || []).concat(entry));
    }

    let groupResults = Array.from(groups.values(), list => ({ result: pickResult(list.map(entry => entry.result)), list }));
    let result = ANY_ORDER.find(candidate => groupResults.some(group => group.result === candidate))!;
    if (result === 'pass') {
        return { result, messages: [] };
    }

    if (result === 'fail' && groupResults.length > 1) {
        return { result, messages: [noGroup] };
    }

    // the entries that gave the result, in the groups that have it
    let messages = groupResults
        .filter(group => group.result === result)
        .flatMap(group => group.list.filter(entry => entry.result === result))
        .flatMap(entry => entry.messages);
    return { result, messages };
};

// t= as an ISO 8601 string, empty for a time a Date can not hold
const signTime = (t: number): string => {
    let date = new Date(t * 1000);
    return Number.isNaN(date.getTime()) ? '' : date.toISOString();
};

// a number from a header field for an error string, "?" when it could not be read
const ordinal = (value: number): number | '?' => (Number.isSafeInteger(value) ? value : '?');

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
     *        set, it is checked against the mf= of the highest DKIM2-Signature (section 14.4)
     * @param {String|String[]} [options.rcptTo] SMTP RCPT TO addresses of the delivery, each of
     *        which has to be listed in rt= of the highest DKIM2-Signature
     * @param {Number|Boolean} [options.maxSignatureAge=1209600] Seconds after t= when a signature
     *        expires (section 14.3), false to not check
     * @param {Number|Boolean} [options.maxFutureTime=86400] Seconds a t= may be ahead of the
     *        current time (section 14.3), false to not check
     * @param {Date|Number|String} [options.curTime] Time to verify against, defaults to now
     * @param {Number} [options.maxInstances=20] Most Message-Instance, and most DKIM2-Signature,
     *        header fields processed for one message
     * @param {Function} [options.checkReplay] async ({ key, exploded, intermediary }) => true when
     *        a message with the same m=1 hashes was seen before (section 15.1)
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
        // the lowest i= that covers it (draft-gondwana-dkim2-authres-01 section 3.2.2)
        const signatureFor = (m: number): number | undefined => {
            for (let i = 1; signatures.has(i); i++) {
                if (signatures.get(i)!.m >= m) {
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

        // section 14.2: every field is valid, numbered without gaps, and every instance is signed
        for (let { line, parsed } of this.instanceRows as Required<InstanceRow>[]) {
            if (parsed.error) {
                addError('permerror', `Message-Instance m=${ordinal(parsed.m)} ${parsed.error}`);
            } else if (instances.has(parsed.m)) {
                addError('permerror', `Message-Instance m=${parsed.m} is duplicated`);
            } else {
                instances.set(parsed.m, Object.assign({ line }, parsed));
            }
        }

        for (let { line, parsed } of this.signatureRows as Required<SignatureRow>[]) {
            if (parsed.error) {
                addError('permerror', `DKIM2-Signature i=${ordinal(parsed.i)} ${parsed.error}`, { i: parsed.i });
            } else if (signatures.has(parsed.i)) {
                addError('permerror', `DKIM2-Signature i=${parsed.i} is duplicated`, { i: parsed.i });
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

        // section 13.2 item 1: the highest signature covers the highest instance
        if (signatures.get(maxI)!.m !== maxM) {
            addError('permerror', `Message-Instance m=${maxM} is not signed`);
            return finish();
        }

        let states = this.recreateStates(instances, maxM, addError);
        if (!states) {
            return finish();
        }

        // section 14.7: the hashes of every instance
        for (let m = 1; m <= maxM; m++) {
            instanceResults.push(this.checkInstance(m, instances.get(m)!, states.get(m)!, addError));
        }

        this.checkTimestamps(signatures, addError);
        this.checkCustody(signatures, maxI, addError);

        // sections 14.5 and 14.6, from the most recent signature down. The key lookups of every
        // hop run at the same time, the results are recorded in order
        let keyLookup = createKeyLookup(this.options.resolver);
        let hopOrder = Array.from({ length: maxI }, (v, index) => maxI - index);
        // the From checks and the replay hook do not depend on the signatures, so they run
        // alongside them
        let [hopResults, fromErrors, replay] = await Promise.all([
            Promise.all(hopOrder.map(i => this.verifyHop(signatures.get(i)!, instances, signatures, keyLookup))),
            this.checkFrom(states, signatures, maxM),
            this.replayInfo(instances, signatures)
        ]);
        hopOrder.forEach((i, index) => {
            let result = hopResults[index];
            signatureResults.set(i, result);
            if (result.status.result !== 'pass') {
                addError(result.status.result, result.status.comment, { i });
            }
        });

        for (let error of fromErrors) {
            addError(error.result, error.message, { i: error.i });
        }

        return finish(replay);
    }

    /**
     * Recreates every instance of the message by applying the Recipes from the top down
     *
     * @returns {Map|null} m to message state, null when a Recipe could not be applied
     */
    recreateStates(instances: Map<number, ChainInstance>, maxM: number, addError: AddError): Map<number, MessageState> | null {
        let states = new Map<number, MessageState>([[maxM, this.currentState()]]);
        for (let m = maxM; m > 1; m--) {
            let state = states.get(m)!;
            let recipe = instances.get(m)!.recipe;
            if (recipe) {
                if (recipe.b === null) {
                    // section 14.2: the body hashes below a null Recipe can not be checked
                    addError('permerror', `Message-Instance m=${m} has a null recipe`, { m });
                }
                try {
                    state = state.previous(recipe);
                } catch (err: any) {
                    addError('permerror', `Message-Instance m=${m} ${err.message}`, { m });
                    return null;
                }
            }
            states.set(m - 1, state);
        }
        return states;
    }

    // Section 14.7 for one Message-Instance
    checkInstance(m: number, instance: ChainInstance, state: MessageState, addError: AddError): DKIM2InstanceResult {
        let hashResults: DKIM2InstanceResult['hashes'] = [];
        let entries = instance.hashes.map((hash: InstanceHash): Intermediate => {
            let group = hash.group || 0;
            if (!HASH_ALGORITHMS.has(hash.algorithm)) {
                // section 14.7 step 2: an algorithm that is not implemented is a PERMERROR
                return { result: 'permerror', group, messages: [`algorithm ${hash.algorithm} unknown`] };
            }

            let header: 'pass' | 'fail' = state.headerHash(hash.algorithm) === hash.headerHash ? 'pass' : 'fail';
            // a body below a null Recipe can not be checked, which is reported once for the Recipe
            let computedBodyHash = state.bodyHash(hash.algorithm);
            let body: 'pass' | 'fail' | 'unknown' = computedBodyHash === null ? 'unknown' : computedBodyHash === hash.bodyHash ? 'pass' : 'fail';
            hashResults.push({ algorithm: hash.algorithm, header, body, group: group + 1 });

            let messages: string[] = [];
            if (header === 'fail') {
                messages.push(`header hash ${hash.algorithm} mismatch`);
            }
            if (body === 'fail') {
                messages.push(`body hash ${hash.algorithm} mismatch`);
            }
            return { result: messages.length ? 'fail' : 'pass', group, messages };
        });

        let { messages, result } = combine(entries, 'no group of hashes passed');
        for (let message of messages) {
            addError(result, `Message-Instance m=${m} ${message}`, { m });
        }

        let entry: DKIM2InstanceResult = { m, hashes: hashResults };
        if (instance.recipe) {
            entry.recipe = {
                headers: Array.from(instance.recipe.h.keys()),
                body: instance.recipe.b === undefined ? 'unchanged' : instance.recipe.b === null ? 'unrecoverable' : 'recipe'
            };
        }
        return entry;
    }

    // Section 14.3
    checkTimestamps(signatures: Map<number, ChainSignature>, addError: AddError): void {
        let maxAge = this.options.maxSignatureAge === undefined ? DEFAULT_MAX_SIGNATURE_AGE : this.options.maxSignatureAge;
        let maxFuture = this.options.maxFutureTime === undefined ? DEFAULT_MAX_FUTURE_TIME : this.options.maxFutureTime;
        let now = Math.floor(getCurTime(this.options.curTime).getTime() / 1000);
        for (let [i, signature] of signatures) {
            if (typeof maxAge === 'number' && now - signature.t > maxAge) {
                addError('fail', `DKIM2-Signature i=${i} signature expired`, { i });
            }
            if (typeof maxFuture === 'number' && signature.t - now > maxFuture) {
                addError('fail', `DKIM2-Signature i=${i} signature is from the future`, { i });
            }
        }
    }

    // Section 14.4, with the relaxed domain matches of section 7.1 items 1 and 2
    checkCustody(signatures: Map<number, ChainSignature>, maxI: number, addError: AddError): void {
        for (let i = 1; i <= maxI; i++) {
            let signature = signatures.get(i)!;

            // section 7.1 item 2: the mf= domain is the d= domain or one of its subdomains, unless
            // mf= is null or there is nd= instead
            if (signature.mailFrom && signature.mailFrom !== '<>' && !relaxedMatch(parsePath(signature.mailFrom).domain, signature.signingDomain)) {
                addError('fail', `DKIM2-Signature i=${i} mf= and d= do not match`, { i });
            }

            let previous = signatures.get(i - 1);
            if (previous?.nextDomain) {
                // section 10.7: nd= names the d= of the next signature exactly
                if (signature.signingDomain !== previous.nextDomain) {
                    addError('fail', `DKIM2-Signature i=${i - 1} nd= does not match`, { i: i - 1 });
                }
                continue;
            }

            // section 7.1 item 1
            let problem = custodyProblem(previous, signature);
            if (problem) {
                addError('fail', `DKIM2-Signature i=${i} ${problem}= does not match the rt= of i=${i - 1}`, { i });
            }
        }

        let top = signatures.get(maxI)!;
        if (top.nextDomain) {
            // sections 12.3 and 13.2: a message whose highest signature has nd= is not verified
            // unless out-of-band arrangements are in place, and the signature that completes it,
            // which the receiving system adds, is not there yet
            addError('fail', `DKIM2-Signature i=${maxI} unexpected nd= tag`, { i: maxI });
            return;
        }

        let { mailFrom, rcptList, hasMailFrom } = this.envelope();

        // section 14.4: an exact match, domains without regard to case, local parts as they are
        if (hasMailFrom && parsePath(mailFrom).address !== parsePath(top.mailFrom).address) {
            addError('fail', `DKIM2-Signature i=${maxI} MAIL FROM ${mailFrom} did not match`, { i: maxI });
        }

        let listed = new Set(top.rcptTo!.map(path => parsePath(path).address));
        for (let rcpt of rcptList) {
            if (!listed.has(parsePath(rcpt).address)) {
                addError('fail', `DKIM2-Signature i=${maxI} RCPT TO ${rcpt} did not match`, { i: maxI });
            }
        }
    }

    /**
     * Section 14.8: the From of the first instance, and every From that a later Recipe shows was
     * put into the message, matches the signing domain of the lowest DKIM2-Signature that covers
     * the instance where that From first appears (section 11)
     */
    async checkFrom(states: Map<number, MessageState>, signatures: Map<number, ChainSignature>, maxM: number): Promise<DKIM2Error[]> {
        // one Domain Policy Record query per domain
        let policyLookup = createPolicyLookup(this.options.resolver);
        let checks: Promise<DKIM2Error | null>[] = [];
        let previous: Buffer[] | null = null;
        for (let m = 1; m <= maxM; m++) {
            let fields = states.get(m)!.fields('from');
            if (previous && sameFields(previous, fields)) {
                continue;
            }
            previous = fields;

            // the highest signature covers maxM, so there always is one
            let i = 1;
            while (signatures.get(i)!.m < m) {
                i++;
            }

            checks.push(
                checkAuthentic(fields, signatures.get(i)!.signingDomain, policyLookup).then(problem =>
                    problem ? { result: problem.result, message: `DKIM2-Signature i=${i} ${problem.message}`, i } : null
                )
            );
        }
        return (await Promise.all(checks)).filter(error => error !== null);
    }

    /**
     * Section 15.1: the m=1 hashes identify the message. A message seen before that came through
     * an intermediary (more than one DKIM2-Signature) without an exploded flag may be a DKIM
     * Replay. That is for the receiver to judge, it does not change the result
     */
    async replayInfo(instances: Map<number, ChainInstance>, signatures: Map<number, ChainSignature>): Promise<Replay> {
        let firstHashes = instances.get(1)!.hashes;
        let replayHash = firstHashes.find(hash => HASH_ALGORITHMS.has(hash.algorithm)) || firstHashes[0];
        let replay: Replay = {
            key: `${replayHash.algorithm}:${replayHash.headerHash}:${replayHash.bodyHash}`,
            exploded: Array.from(signatures.values()).some(signature => signature.flags.includes('exploded')),
            intermediary: signatures.size > 1
        };

        if (typeof this.options.checkReplay === 'function') {
            replay.duplicate = !!(await this.options.checkReplay(Object.assign({}, replay)));
        }
        return replay;
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
    // (section 14.4), and an unchanged copy of the message sent to anyone else passes as well
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

    // Sections 12.8, 14.5 and 14.6 for one DKIM2-Signature
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
            isSupportedAlgorithm(algorithm) ? keyLookup(signature.signingDomain, selector, algorithm) : null
        );
        for (let lookup of lookups) {
            void lookup?.catch(() => false);
        }

        let values: DKIM2SignatureValueResult[] = [];
        let entries: Intermediate[] = [];
        for (let [index, { selector, algorithm, signature: value, group = 0 }] of signature.signatures.entries()) {
            let entry: DKIM2SignatureValueResult = { selector, algorithm, group: group + 1 };
            values.push(entry);

            if (!lookups[index]) {
                // section 14.6 step 4: an algorithm that is not implemented is a PERMERROR
                entry.result = 'permerror';
                entry.comment = `selector ${selector} algorithm unknown`;
            } else {
                await this.checkValue(entry, lookups[index], algorithm, input, value);
            }

            entries.push({ result: entry.result as DKIM2Result, group, messages: [entry.comment || ''] });
        }

        let { result, messages } = combine(entries, 'no group of signatures passed');
        let status: HopStatus = result === 'pass' ? { result } : { result, comment: `DKIM2-Signature i=${i} ${messages[0]}` };
        return { status, values };
    }

    // Checks one signature value with its key and records the outcome in `entry`
    async checkValue(entry: DKIM2SignatureValueResult, lookup: Promise<DKIM2Key>, algorithm: string, input: Buffer, value: string): Promise<void> {
        let key: DKIM2Key;
        try {
            key = await lookup;
        } catch (err) {
            if (!(err instanceof KeyError)) {
                throw err;
            }
            entry.result = err.result;
            entry.comment = `public key ${entry.selector} ${err.message}`;
            if (err.rr) {
                entry.rr = err.rr;
            }
            return;
        }

        entry.rr = key.rr;
        if (key.modulusLength) {
            entry.modulusLength = key.modulusLength;
        }
        if (verifySignature(algorithm, input, key.publicKey!, Buffer.from(value, 'base64'))) {
            entry.result = 'pass';
        } else {
            entry.result = 'fail';
            entry.comment = `selector ${entry.selector} incorrect signature`;
        }
    }

    formatResult({ none, errors, signatures, signatureResults, instanceResults, replay }: FormatInput): DKIM2VerifyResult {
        if (none) {
            // section 14.2 "NONE: No DKIM2 header fields found". The Authentication-Results
            // resinfo is a plain dkim2=none (draft-gondwana-dkim2-authres-01 section 3.1)
            let status: DKIM2VerifyResult['status'] = { result: 'none' };
            let info = formatAuthHeaderRow('dkim2', status);
            status.comment = 'No DKIM2 header fields found';
            return { status, info, errors: [], instances: [], signatures: [] };
        }

        let result = pickResult(errors.map(error => error.result));
        let reported = errors.find(error => error.result === result);

        let signatureList: DKIM2SignatureResult[] = [];
        let hops: string[] = [];
        for (let i = 1; signatures.has(i); i++) {
            let signature = signatures.get(i)!;
            let hop = signatureResults.get(i);

            // the outcome of a hop includes the errors that are reported against it
            let hopErrors = errors.filter(error => error.i === i);
            let hopResult: DKIM2Result | 'skipped' = hop ? pickResult([hop.status.result, ...hopErrors.map(error => error.result)]) : 'skipped';
            hops.push(`i=${i} ${signature.signingDomain} ${hopResult}`);

            let status: DKIM2SignatureResult['status'] = { result: hopResult };
            if (hop && hopResult !== 'pass') {
                status.comment = hop.status.result === hopResult ? hop.status.comment : hopErrors.find(error => error.result === hopResult)?.message;
            }

            let entry: DKIM2SignatureResult = {
                i,
                m: signature.m,
                signingDomain: signature.signingDomain,
                timestamp: signature.t,
                signTime: signTime(signature.t),
                flags: signature.flags,
                status,
                values: hop ? hop.values : signature.signatures.map(({ selector, algorithm, group = 0 }) => ({ selector, algorithm, group: group + 1 }))
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

        // draft-gondwana-dkim2-authres-01 section 3: one resinfo for the message, the hops and the
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
