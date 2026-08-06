'use strict';

// Preloaded with `node -r` in CLI tests to detect DNS lookups. Only active when
// DENY_DNS is set, so this file is a no-op when picked up by the mocha test glob.
if (process.env.DENY_DNS) {
    const dns = require('node:dns');

    const deny = name => {
        process.stderr.write(`DNS_LOOKUP_ATTEMPTED ${name}\n`);
        let err = new Error(`DNS lookup attempted for ${name}`);
        err.code = 'ENOTFOUND';
        throw err;
    };

    for (let key of Object.keys(dns.promises)) {
        if (typeof dns.promises[key] === 'function' && /^(resolve|lookup|reverse)/.test(key)) {
            dns.promises[key] = async name => deny(name);
        }
    }
}
