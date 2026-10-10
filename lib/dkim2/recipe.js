'use strict';

// DKIM2 Recipes (draft-ietf-dkim-dkim2-spec-06 section 5): JSON instructions in the r= tag of a
// Message-Instance header field that recreate the previous instance of the message from the
// current one. This module validates a Recipe and applies it to a message state.

// RFC 5322 field-name, the keys of the "h" object
const FIELD_NAME = /^[\x21-\x39\x3b-\x7e]+$/;

const isPlainObject = value => !!value && typeof value === 'object' && !Array.isArray(value);
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

// Validates the steps of a header or body Recipe. Every step is an object with exactly one of
// "c" (copy a range) or "d" (literal data). Other keys are ignored, as section 2 requires for
// unrecognised JSON fields, although the schema of section 5 does not allow them
const validateSteps = (steps, label) => {
    if (!Array.isArray(steps)) {
        return `${label} is not an array`;
    }

    let lastEnd = 0;
    for (let step of steps) {
        if (!isPlainObject(step) || own(step, 'c') === own(step, 'd')) {
            return `${label} has a step that is not a "c" or a "d" step`;
        }

        if (own(step, 'c')) {
            let range = step.c;
            if (!Array.isArray(range) || range.length !== 2 || !range.every(value => Number.isSafeInteger(value) && value >= 1)) {
                return `${label} has an invalid "c" range`;
            }
            // the start of every "c" step is after the end of all the earlier ones
            if (range[0] > range[1] || range[0] <= lastEnd) {
                return `${label} has "c" ranges out of order`;
            }
            lastEnd = range[1];
        } else {
            let data = step.d;
            if (!Array.isArray(data) || !data.length || !data.every(value => typeof value === 'string' && !/[\r\n]/.test(value))) {
                return `${label} has an invalid "d" step`;
            }
        }
    }

    return null;
};

/**
 * Parses and validates the JSON of a Recipe
 *
 * @param {String} json Decoded r= value
 * @returns {Object} { value, error }. `value.h` is a Map of lower case header field name to its
 *          steps, `value.b` is the body steps, null for a body that can not be recreated, or
 *          undefined when the body did not change
 */
const parseRecipe = json => {
    let recipe;
    try {
        recipe = JSON.parse(json);
    } catch (err) {
        return { error: 'not valid JSON' };
    }

    if (!isPlainObject(recipe)) {
        return { error: 'not a JSON object' };
    }

    if (!own(recipe, 'h') && !own(recipe, 'b')) {
        return { error: 'neither "h" nor "b" is present' };
    }

    let value = { h: new Map(), b: undefined };

    if (own(recipe, 'h')) {
        if (!isPlainObject(recipe.h) || !Object.keys(recipe.h).length) {
            return { error: '"h" is not an object with header field names' };
        }
        for (let name of Object.keys(recipe.h)) {
            // section 5.1: header field names in the JSON keys MUST be in lower case
            if (!FIELD_NAME.test(name) || name !== name.toLowerCase()) {
                return { error: `invalid header field name ${JSON.stringify(name)}` };
            }
            let error = validateSteps(recipe.h[name], `"h" Recipe for ${name}`);
            if (error) {
                return { error };
            }
            value.h.set(name, recipe.h[name]);
        }
    }

    if (own(recipe, 'b')) {
        if (recipe.b !== null) {
            let error = validateSteps(recipe.b, '"b" Recipe');
            if (error) {
                return { error };
            }
        }
        value.b = recipe.b;
    }

    return { value };
};

/**
 * Runs the steps of a Recipe against a list of items: header fields of one name numbered
 * bottom up, or body lines numbered top down. The output keeps the same direction
 *
 * @param {Array} items Current items
 * @param {Object[]} steps Validated Recipe steps
 * @param {Function} fromData Converts a "d" string to an item
 * @returns {Array} Items of the previous instance
 * @throws {Error} When a "c" range goes past the last item
 */
const applySteps = (items, steps, fromData) => {
    let output = [];
    for (let step of steps) {
        if (step.c) {
            let [start, end] = step.c;
            if (end > items.length) {
                throw new Error(`"c" range ${start}-${end} is past the last of ${items.length}`);
            }
            for (let pos = start - 1; pos < end; pos++) {
                output.push(items[pos]);
            }
        } else {
            for (let data of step.d) {
                output.push(fromData(data));
            }
        }
    }
    return output;
};

module.exports = { parseRecipe, applySteps };
