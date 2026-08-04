'use strict';

// Property names that must never be used as parsed keys. Assigning "__proto__" replaces the
// prototype of the parsed object instead of adding a property to it, and assigning any other
// inherited Object.prototype member shadows that method, so later string coercion of the
// object (or a hasOwnProperty call on it) throws instead of returning a value.
// "prototype" is the only name here that is not already an own property of Object.prototype.
const DANGEROUS_KEYS = new Set(['prototype', ...Object.getOwnPropertyNames(Object.prototype)]);

module.exports = { DANGEROUS_KEYS };
