'use strict';

// Declarative DNS mock for DMARC tests. Builds a resolver matching the
// dns.promises.resolve(name, type) contract from a static zone, so tree-walk
// and domain-existence behaviour (RFC 9989 §4.10, §3.2.13) can be exercised
// without real DNS.
//
// zone shape:
//   {
//     '_dmarc.example.com': { TXT: [['v=DMARC1; p=reject']] },
//     'example.com':        { A: ['192.0.2.1'] },          // name exists
//     'mail.example.com':   { MX: [{ priority: 1, exchange: 'mx.example.com' }] }
//   }
//
// Lookup semantics:
//   - name present with the queried RR type -> return the records
//   - name present without that RR type     -> NODATA  (err.code = 'ENODATA')
//   - name absent                           -> NXDOMAIN (err.code = 'ENOTFOUND')
//   - name with a CNAME, other RR type      -> the answer for the CNAME target, like a recursive
//                                              resolver (RFC 1034 §3.6.2), so a missing target
//                                              gives NXDOMAIN (RFC 6604 §3), and a chain of more
//                                              than 8 CNAMEs, a loop, gives SERVFAIL
//
// The returned resolver exposes a `calls` array ([{ name, type }, ...]) so tests
// can assert the query sequence and the 8-query tree-walk cap.
const zoneResolver = zone => {
    const normalized = new Map();
    for (const [name, records] of Object.entries(zone || {})) {
        normalized.set(name.toLowerCase().replace(/\.$/, ''), records);
    }

    const lookup = (name, type, hops) => {
        const key = String(name).toLowerCase().replace(/\.$/, '');
        const node = normalized.get(key);

        if (!node) {
            const err = new Error(`NXDOMAIN: ${name}`);
            err.code = 'ENOTFOUND';
            throw err;
        }

        if (node.CNAME && node.CNAME.length && type !== 'CNAME') {
            if (hops >= 8) {
                const err = new Error(`SERVFAIL: ${name}`);
                err.code = 'ESERVFAIL';
                throw err;
            }
            return lookup(node.CNAME[0], type, hops + 1);
        }

        if (node[type] && node[type].length) {
            return node[type];
        }

        const err = new Error(`NODATA: ${name} ${type}`);
        err.code = 'ENODATA';
        throw err;
    };

    const resolver = async (name, type) => {
        resolver.calls.push({ name, type });
        return lookup(name, type, 0);
    };

    resolver.calls = [];
    return resolver;
};

module.exports = { zoneResolver };
