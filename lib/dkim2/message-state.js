'use strict';

// One instance of a message as DKIM2 hashes it: the hashed header fields grouped by name, and
// the body. Applying the Recipe of a Message-Instance gives the previous instance
// (draft-ietf-dkim-dkim2-spec-06 sections 5, 6 and 11)

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const { SimpleHash } = require('../dkim/body/simple');
const { isHashedField, canonicalHeaderField } = require('./fields');
const { applySteps } = require('./recipe');

// how much body text is handed to the hash at a time when a body is hashed from its lines
const HASH_CHUNK_SIZE = 64 * 1024;

// "d" values are JSON strings, the message is handled as 'binary' strings of its bytes
const utf8ToBinary = value => Buffer.from(value, 'utf8').toString('binary');

/**
 * Splits a body into lines numbered top down (section 5.2), without the line terminators
 *
 * @param {Buffer} body Message body with CRLF line endings
 * @returns {String[]} Lines as 'binary' strings
 */
const splitBodyLines = body => {
    let str = body.toString('binary');
    if (!str) {
        return [];
    }
    let lines = str.split('\r\n');
    if (str.endsWith('\r\n')) {
        // the terminator of the last line, not an empty line after it
        lines.pop();
    }
    return lines;
};

// Section 6.1: the body hash of a list of lines, each ending with CRLF
const hashBodyLines = (lines, algorithm) => {
    let hasher = new SimpleHash(algorithm);
    let chunk = '';
    for (let line of lines) {
        chunk += line + '\r\n';
        if (chunk.length >= HASH_CHUNK_SIZE) {
            hasher.update(Buffer.from(chunk, 'binary'));
            chunk = '';
        }
    }
    if (chunk) {
        hasher.update(Buffer.from(chunk, 'binary'));
    }
    return hasher.digest('base64');
};

class MessageState {
    /**
     * @param {Map} headers Lower case field name to the canonicalized fields, numbered bottom up
     * @param {Object|null} body { lines, hashes } where `lines` may be null when the body was not
     *        kept and `hashes` is a Map of algorithm to base64 hash. null for a body that can not
     *        be recreated (a null body Recipe)
     */
    constructor(headers, body) {
        this.headers = headers;
        this.body = body;
        this.headerHashes = new Map();
    }

    /**
     * Builds the state of the message as it is
     *
     * @param {Object[]} parsedHeaders Rows from parseHeaders(), top down
     * @param {Object} body { lines, hashes }
     * @returns {MessageState}
     */
    static fromMessage(parsedHeaders, body) {
        let headers = new Map();
        for (let i = parsedHeaders.length - 1; i >= 0; i--) {
            let row = parsedHeaders[i];
            if (!isHashedField(row.key)) {
                continue;
            }
            if (!headers.has(row.key)) {
                headers.set(row.key, []);
            }
            headers.get(row.key).push(canonicalHeaderField(row.line));
        }
        return new MessageState(headers, body);
    }

    // Section 6.2: the fields in alphabetical order of their names, fields with the same name
    // from the bottom up
    headerHash(algorithm) {
        if (!this.headerHashes.has(algorithm)) {
            let hash = crypto.createHash(algorithm);
            for (let name of Array.from(this.headers.keys()).sort()) {
                for (let line of this.headers.get(name)) {
                    hash.update(line);
                }
            }
            this.headerHashes.set(algorithm, hash.digest('base64'));
        }
        return this.headerHashes.get(algorithm);
    }

    // the body hash, or null when the body of this instance can not be recreated
    bodyHash(algorithm) {
        if (!this.body) {
            return null;
        }
        if (!this.body.hashes.has(algorithm)) {
            this.body.hashes.set(algorithm, hashBodyLines(this.body.lines, algorithm));
        }
        return this.body.hashes.get(algorithm);
    }

    /**
     * Applies a Recipe to get the previous instance of the message
     *
     * @param {Object} recipe Parsed Recipe ({ h: Map, b })
     * @returns {MessageState}
     * @throws {Error} When the Recipe does not fit this instance
     */
    previous(recipe) {
        let headers = new Map(this.headers);
        for (let [name, steps] of recipe.h) {
            // section 5.1: Recipes SHOULD NOT name the fields that are not signed, and the
            // hash does not see them anyway
            if (!isHashedField(name)) {
                continue;
            }
            let fields = applySteps(this.headers.get(name) || [], steps, value => canonicalHeaderField(Buffer.from(`${name}:${value}`, 'utf8')));
            headers.set(name, fields);
        }

        let body = this.body;
        if (recipe.b === null || (Array.isArray(recipe.b) && !body)) {
            // the previous body can not be recreated, or it was built from one that can not
            body = null;
        } else if (Array.isArray(recipe.b)) {
            if (!body.lines) {
                throw new Error('The message body was not kept for the body Recipe');
            }
            body = { lines: applySteps(body.lines, recipe.b, utf8ToBinary), hashes: new Map() };
        }

        return new MessageState(headers, body);
    }

    /**
     * Whether `later` only added header fields to this instance and kept the body, which is what a
     * donotmodify request allows (section 8.10)
     *
     * @param {MessageState} later A later instance of the message
     * @param {String} algorithm Hash algorithm for comparing the bodies
     * @returns {Boolean}
     */
    isPreservedIn(later, algorithm) {
        let bodyHash = this.bodyHash(algorithm);
        if (!bodyHash || bodyHash !== later.bodyHash(algorithm)) {
            return false;
        }

        for (let [name, fields] of this.headers) {
            // every field of this instance is still there, in the same order
            let laterFields = later.headers.get(name) || [];
            let pos = 0;
            for (let field of fields) {
                while (pos < laterFields.length && !laterFields[pos].equals(field)) {
                    pos++;
                }
                if (pos >= laterFields.length) {
                    return false;
                }
                pos++;
            }
        }
        return true;
    }
}

module.exports = { MessageState, splitBodyLines };
