// DKIM2 Recipes (draft-ietf-dkim-dkim2-spec-09 section 5): JSON instructions in the r= tag of a
// Message-Instance header field that recreate the previous instance of the message from the
// current one. This module validates a Recipe and applies its steps.

import { Buffer } from 'node:buffer';
import { isHashedField } from './signed-fields.js';

// A validated Recipe step: "c" copies a range, "lines" are the bytes of a "d" or "u" step as
// 'binary' strings. `source` is the step as it is in the JSON, for error messages
type RecipeStep = { c: [number, number]; lines?: undefined; source: unknown } | { c?: undefined; lines: string[]; source: unknown };

// A validated Recipe. `h` maps lower case header field names to their steps, `b` is the body
// steps, null for a body that can not be recreated, or undefined when the body did not change
interface ParsedRecipe {
    h: Map<string, RecipeStep[]>;
    b: RecipeStep[] | null | undefined;
}

type ParseRecipeResult = { value: ParsedRecipe; error?: undefined } | { value?: undefined; error: string };

// RFC 5322 field-name, the keys of the "h" object
const FIELD_NAME = /^[\x21-\x39\x3b-\x7e]+$/;

// The "base64-line" of the schema in section 5: canonical base64 with its padding bits zero
const BASE64_LINE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$/;

// a lone UTF-16 surrogate, which a JSON string can hold through a \u escape but which is not
// valid UTF-8 (section 5: "d" values MUST be valid UTF-8)
const LONE_SURROGATE = /\p{Cs}/u;

// the longest piece of Recipe JSON quoted in an error message
const MAX_QUOTE = 100;

const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

const isPlainObject = (value: unknown): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value);
const own = (obj: object, key: string): boolean => Object.prototype.hasOwnProperty.call(obj, key);

// Section 14.2 "Message-Instance m=<x> recipe <value> is invalid", with the invalid part of the
// Recipe as the value
const quote = (text: string): string => (text.length > MAX_QUOTE ? `${text.substring(0, MAX_QUOTE)}...` : text);
const invalid = (value: unknown): string => `recipe ${quote(JSON.stringify(value))} is invalid`;

/**
 * Checks the two rules of section 5 that the JSON schema can not express: every key of every
 * object is in lower case and unique within its object. JSON.parse() keeps the last of two
 * equal keys without telling, so the text is scanned. It has to be valid JSON already
 *
 * @param {String} json JSON text
 * @returns {Object|null} { duplicate } or { upper } with the key that breaks a rule, or null
 */
const checkKeys = (json: string): { duplicate?: string; upper?: string } | null => {
    // a Set of the keys of each open object, null for an open array
    let stack: (Set<string> | null)[] = [];
    let expectKey = false;
    for (let i = 0; i < json.length; i++) {
        let c = json.charAt(i);
        if (c === '"') {
            let start = i;
            for (i++; json.charAt(i) !== '"'; i++) {
                if (json.charAt(i) === '\\') {
                    i++;
                }
            }
            if (expectKey) {
                // the key as JSON.parse() sees it, so that "a" and "a" are the same key
                let key = JSON.parse(json.substring(start, i + 1)) as string;
                let keys = stack[stack.length - 1]!;
                if (keys.has(key)) {
                    return { duplicate: key };
                }
                if (key !== key.toLowerCase()) {
                    return { upper: key };
                }
                keys.add(key);
                expectKey = false;
            }
        } else if (c === '{') {
            stack.push(new Set());
            expectKey = true;
        } else if (c === '[') {
            stack.push(null);
        } else if (c === '}' || c === ']') {
            stack.pop();
        } else if (c === ',') {
            expectKey = !!stack[stack.length - 1];
        }
    }
    return null;
};

// Validates one "d" or "u" step value and returns its lines as 'binary' strings, or null
const readLines = (key: 'd' | 'u', values: unknown): string[] | null => {
    if (!Array.isArray(values) || !values.length || !values.every(value => typeof value === 'string')) {
        return null;
    }
    let lines: string[] = [];
    for (let value of values) {
        let bytes: Buffer;
        if (key === 'd') {
            if (LONE_SURROGATE.test(value)) {
                return null;
            }
            bytes = Buffer.from(value, 'utf8');
        } else {
            if (!BASE64_LINE.test(value)) {
                return null;
            }
            bytes = Buffer.from(value, 'base64');
        }
        let line = bytes.toString('binary');
        // section 5: no CR or LF, for a "u" step once it is decoded
        if (/[\r\n]/.test(line)) {
            return null;
        }
        lines.push(line);
    }
    return lines;
};

/**
 * Validates the steps of a header or body Recipe (sections 5, 5.1 and 5.2). Every step is an
 * object with exactly one key: "c" (copy a range), "d" (UTF-8 data) or "u" (base64 data)
 *
 * @param {*} steps Value from the JSON
 * @returns {Object} { steps } or { error }
 */
const validateSteps = (steps: unknown): { steps: RecipeStep[]; error?: undefined } | { steps?: undefined; error: string } => {
    if (!Array.isArray(steps)) {
        return { error: invalid(steps) };
    }

    let result: RecipeStep[] = [];
    let lastEnd = 0;
    for (let step of steps) {
        let keys = isPlainObject(step) ? Object.keys(step) : [];
        if (keys.length !== 1) {
            return { error: invalid(step) };
        }

        if (keys[0] === 'c') {
            let range = step.c;
            if (!Array.isArray(range) || range.length !== 2 || !range.every(value => Number.isSafeInteger(value) && value >= 1)) {
                return { error: invalid(step) };
            }
            // the start of every "c" step is after the end of all the earlier ones, and the end
            // is not before the start
            if (range[0] > range[1] || range[0] <= lastEnd) {
                return { error: invalid(step) };
            }
            lastEnd = range[1];
            result.push({ c: [range[0], range[1]], source: step });
        } else if (keys[0] === 'd' || keys[0] === 'u') {
            let lines = readLines(keys[0], step[keys[0]]);
            if (!lines) {
                return { error: invalid(step) };
            }
            result.push({ lines, source: step });
        } else {
            return { error: invalid(step) };
        }
    }

    return { steps: result };
};

/**
 * Parses and validates a Recipe (section 5)
 *
 * @param {Buffer|String} input Decoded r= value, the bytes of the JSON
 * @returns {Object} { value, error }. `value.h` is a Map of lower case header field name to its
 *          steps, `value.b` is the body steps, null for a body that can not be recreated, or
 *          undefined when the body did not change. `error` is the end of a section 14.2 error
 *          string, after "Message-Instance m=<x>"
 */
const parseRecipe = (input: Buffer | string): ParseRecipeResult => {
    let json: string;
    let recipe: any;
    try {
        json = typeof input === 'string' ? input : UTF8.decode(input);
        recipe = JSON.parse(json);
    } catch {
        return { error: 'contains invalid JSON' };
    }

    if (!isPlainObject(recipe)) {
        return { error: 'contains invalid JSON: not a JSON object' };
    }

    let keyProblem = checkKeys(json);
    if (keyProblem?.duplicate !== undefined) {
        return { error: `contains invalid JSON: duplicate key ${quote(JSON.stringify(keyProblem.duplicate))}` };
    }
    if (keyProblem?.upper !== undefined) {
        // the keys MUST be in lower case
        return { error: invalid(keyProblem.upper) };
    }

    if (!own(recipe, 'h') && !own(recipe, 'b')) {
        return { error: invalid(recipe) };
    }

    let value: ParsedRecipe = { h: new Map(), b: undefined };

    if (own(recipe, 'h')) {
        if (!isPlainObject(recipe.h) || !Object.keys(recipe.h).length) {
            return { error: invalid({ h: recipe.h }) };
        }
        for (let name of Object.keys(recipe.h)) {
            // section 5.1: no Recipe for a header field that is not signed
            if (!FIELD_NAME.test(name) || !isHashedField(name)) {
                return { error: invalid(name) };
            }
            let { steps, error } = validateSteps(recipe.h[name]);
            if (error) {
                return { error };
            }
            value.h.set(name, steps!);
        }
    }

    if (own(recipe, 'b')) {
        if (recipe.b === null) {
            value.b = null;
        } else {
            let { steps, error } = validateSteps(recipe.b);
            if (error) {
                return { error };
            }
            value.b = steps!;
        }
    }

    return { value };
};

/**
 * Runs the steps of a Recipe against a list of items: header fields of one name numbered
 * bottom up, or body lines numbered top down. The output keeps the same direction
 *
 * @param {Array} items Current items
 * @param {Object[]} steps Validated Recipe steps
 * @param {Function} fromData Converts a line of a "d" or "u" step to an item
 * @returns {Array} Items of the previous instance
 * @throws {Error} When a "c" range goes past the last item
 */
const applySteps = <T>(items: T[], steps: RecipeStep[], fromData: (data: string) => T): T[] => {
    let output: T[] = [];
    for (let step of steps) {
        if (step.c) {
            let [start, end] = step.c;
            if (end > items.length) {
                throw new Error(invalid(step.source));
            }
            for (let pos = start - 1; pos < end; pos++) {
                output.push(items[pos]);
            }
        } else {
            for (let line of step.lines) {
                output.push(fromData(line));
            }
        }
    }
    return output;
};

export { parseRecipe, applySteps };
export type { RecipeStep, ParsedRecipe, ParseRecipeResult };
