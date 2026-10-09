'use strict';

// Independent reference parser for an RFC 5322 address-list (section 3.4, with the obsolete
// syntax of section 4.4 that a parser has to accept, and the UTF-8 of RFC 6532 section 3.2). It
// shares no code with mailauth and is written straight from the ABNF as a backtracking parser
// over characters, so it is slow but easy to check against the RFC.
//
// parseAddressList(value) returns the addr-spec of every mailbox in order, with CFWS removed
// and any obs-route dropped, or null when the value is not an address-list. A quoted string
// and a domain literal are returned as they are written. Differences from the RFC, to match
// what the From header parsing of mailauth is expected to report:
//   - a value that has no address at all (only CFWS and commas) gives an empty list
//   - obs-dtext quoted-pairs inside a domain literal are not accepted

const isWSP = c => c === ' ' || c === '\t';
const isNonAscii = c => c > '\x7f';
// obs-NO-WS-CTL
const isObsCtl = c => /^[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]$/.test(c);
const isAtext = c => /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]$/.test(c) || isNonAscii(c);
// ctext, qtext and dtext with their obs- extensions where accepted
const isCtext = c => /^[\x21-\x27\x2a-\x5b\x5d-\x7e]$/.test(c) || isObsCtl(c) || isNonAscii(c);
const isQtext = c => /^[\x21\x23-\x5b\x5d-\x7e]$/.test(c) || isObsCtl(c) || isNonAscii(c);
const isDtext = c => /^[\x21-\x5a\x5e-\x7e]$/.test(c) || isObsCtl(c) || isNonAscii(c);

const parseAddressList = value => {
    const s = (value || '').toString();

    // Every rule takes a position and returns the position after it, or -1. Rules that carry a
    // value return { pos, value } or null

    // FWS = ([*WSP CRLF] 1*WSP) / obs-FWS, obs-FWS = 1*WSP *(CRLF 1*WSP)
    const fws = p => {
        let q = p;
        let any = false;
        for (;;) {
            if (isWSP(s.charAt(q))) {
                q++;
                any = true;
            } else if (s.startsWith('\r\n', q) && isWSP(s.charAt(q + 2))) {
                q += 3;
                any = true;
            } else {
                break;
            }
        }
        return any ? q : -1;
    };
    const optFws = p => {
        let q = fws(p);
        return q < 0 ? p : q;
    };

    // quoted-pair = ("\" (VCHAR / WSP)) / obs-qp
    const quotedPair = p => {
        if (s.charAt(p) !== '\\' || p + 1 >= s.length) {
            return -1;
        }
        let c = s.charAt(p + 1);
        if (/^[\x21-\x7e]$/.test(c) || isWSP(c) || isNonAscii(c) || c === '\x00' || isObsCtl(c) || c === '\r' || c === '\n') {
            return p + 2;
        }
        return -1;
    };

    // comment = "(" *([FWS] ccontent) [FWS] ")"
    const comment = p => {
        if (s.charAt(p) !== '(') {
            return -1;
        }
        let q = p + 1;
        for (;;) {
            let r = optFws(q);
            let c = s.charAt(r);
            if (c === ')') {
                return r + 1;
            }
            if (isCtext(c)) {
                q = r + 1;
                continue;
            }
            let next = quotedPair(r);
            if (next < 0) {
                next = comment(r);
            }
            if (next < 0) {
                return -1;
            }
            q = next;
        }
    };

    // CFWS = (1*([FWS] comment) [FWS]) / FWS
    const optCfws = p => {
        let q = p;
        for (;;) {
            let r = optFws(q);
            let next = comment(r);
            if (next < 0) {
                return r;
            }
            q = next;
        }
    };

    // atom = [CFWS] 1*atext [CFWS]
    const atom = p => {
        let q = optCfws(p);
        let start = q;
        while (q < s.length && isAtext(s.charAt(q))) {
            q++;
        }
        if (q === start) {
            return null;
        }
        return { pos: optCfws(q), value: s.slice(start, q) };
    };

    // quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]
    const quotedString = p => {
        let q = optCfws(p);
        if (s.charAt(q) !== '"') {
            return null;
        }
        let start = q;
        q++;
        for (;;) {
            let r = optFws(q);
            let c = s.charAt(r);
            if (c === '"') {
                return { pos: optCfws(r + 1), value: s.slice(start, r + 1) };
            }
            if (isQtext(c)) {
                q = r + 1;
                continue;
            }
            let next = quotedPair(r);
            if (next < 0) {
                return null;
            }
            q = next;
        }
    };

    // word = atom / quoted-string
    const word = p => atom(p) || quotedString(p);

    // obs-local-part = word *("." word), which also covers dot-atom and quoted-string
    const localPart = p => {
        let first = word(p);
        if (!first) {
            return null;
        }
        let parts = [first.value];
        let q = first.pos;
        while (s.charAt(q) === '.') {
            let next = word(q + 1);
            if (!next) {
                return null;
            }
            parts.push(next.value);
            q = next.pos;
        }
        return { pos: q, value: parts.join('.') };
    };

    // domain-literal = [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
    const domainLiteral = p => {
        let q = optCfws(p);
        if (s.charAt(q) !== '[') {
            return null;
        }
        let start = q;
        q++;
        for (;;) {
            let r = optFws(q);
            let c = s.charAt(r);
            if (c === ']') {
                return { pos: optCfws(r + 1), value: s.slice(start, r + 1) };
            }
            if (!isDtext(c) || r >= s.length) {
                return null;
            }
            q = r + 1;
        }
    };

    // domain = dot-atom / domain-literal / obs-domain, obs-domain = atom *("." atom)
    const domain = p => {
        let literal = domainLiteral(p);
        if (literal) {
            return literal;
        }
        let first = atom(p);
        if (!first) {
            return null;
        }
        let parts = [first.value];
        let q = first.pos;
        while (s.charAt(q) === '.') {
            let next = atom(q + 1);
            if (!next) {
                return null;
            }
            parts.push(next.value);
            q = next.pos;
        }
        return { pos: q, value: parts.join('.') };
    };

    // addr-spec = local-part "@" domain
    const addrSpec = p => {
        let local = localPart(p);
        if (!local || s.charAt(local.pos) !== '@') {
            return null;
        }
        let dom = domain(local.pos + 1);
        if (!dom) {
            return null;
        }
        return { pos: dom.pos, value: `${local.value}@${dom.value}` };
    };

    // obs-route = obs-domain-list ":"
    // obs-domain-list = *(CFWS / ",") "@" domain *("," [CFWS] ["@" domain])
    const obsRoute = p => {
        let q = p;
        for (;;) {
            let r = optCfws(q);
            if (s.charAt(r) === ',') {
                q = r + 1;
                continue;
            }
            q = r;
            break;
        }
        if (s.charAt(q) !== '@') {
            return -1;
        }
        let dom = domain(q + 1);
        if (!dom) {
            return -1;
        }
        q = dom.pos;
        while (s.charAt(q) === ',') {
            q = optCfws(q + 1);
            if (s.charAt(q) === '@') {
                let next = domain(q + 1);
                if (!next) {
                    return -1;
                }
                q = next.pos;
            }
        }
        return s.charAt(q) === ':' ? q + 1 : -1;
    };

    // angle-addr = [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
    // obs-angle-addr = [CFWS] "<" obs-route addr-spec ">" [CFWS]
    const angleAddr = p => {
        let q = optCfws(p);
        if (s.charAt(q) !== '<') {
            return null;
        }
        q++;
        let routed = obsRoute(q);
        let spec = addrSpec(routed >= 0 ? routed : q);
        if (!spec && routed >= 0) {
            spec = addrSpec(q);
        }
        if (!spec || s.charAt(spec.pos) !== '>') {
            return null;
        }
        return { pos: optCfws(spec.pos + 1), value: spec.value };
    };

    // display-name = phrase, phrase = 1*word / obs-phrase, obs-phrase = word *(word / "." / CFWS)
    const phrase = p => {
        let first = word(p);
        if (!first) {
            return -1;
        }
        let q = first.pos;
        for (;;) {
            let next = word(q);
            if (next) {
                q = next.pos;
                continue;
            }
            if (s.charAt(q) === '.') {
                q++;
                continue;
            }
            let r = optCfws(q);
            if (r > q) {
                q = r;
                continue;
            }
            return q;
        }
    };

    // mailbox = name-addr / addr-spec, name-addr = [display-name] angle-addr
    const mailbox = p => {
        let named = phrase(p);
        if (named >= 0) {
            let addr = angleAddr(named);
            if (addr) {
                return addr;
            }
        }
        return angleAddr(p) || addrSpec(p);
    };

    // mailbox-list = (mailbox *("," mailbox)) / obs-mbox-list
    // obs-mbox-list = *([CFWS] ",") mailbox *("," [mailbox / CFWS])
    // The same shape is used for address-list / obs-addr-list with `item` = address
    const list = (p, item) => {
        let q = p;
        for (;;) {
            let r = optCfws(q);
            if (s.charAt(r) === ',') {
                q = r + 1;
                continue;
            }
            break;
        }
        let first = item(q);
        if (!first) {
            return null;
        }
        let values = [...first.value];
        q = first.pos;
        while (s.charAt(q) === ',') {
            let next = item(q + 1);
            if (next) {
                values.push(...next.value);
                q = next.pos;
            } else {
                q = optCfws(q + 1);
            }
        }
        return { pos: q, value: values };
    };

    const mailboxItem = p => {
        let box = mailbox(p);
        return box && { pos: box.pos, value: [box.value] };
    };

    // group = display-name ":" [group-list] ";" [CFWS]
    // group-list = mailbox-list / CFWS / obs-group-list, obs-group-list = 1*([CFWS] ",") [CFWS]
    const group = p => {
        let q = phrase(p);
        if (q < 0 || s.charAt(q) !== ':') {
            return null;
        }
        q++;
        let members = list(q, mailboxItem);
        let values = [];
        if (members && s.charAt(members.pos) === ';') {
            values = members.value;
            q = members.pos;
        } else {
            // CFWS or obs-group-list, no mailboxes
            for (;;) {
                let r = optCfws(q);
                if (s.charAt(r) === ',') {
                    q = r + 1;
                    continue;
                }
                q = r;
                break;
            }
        }
        if (s.charAt(q) !== ';') {
            return null;
        }
        return { pos: optCfws(q + 1), value: values };
    };

    // address = mailbox / group
    const address = p => {
        let box = mailbox(p);
        if (box) {
            // a mailbox that a group would continue, as in "a: b@c;", is not the whole address
            let grp = group(p);
            if (grp && grp.pos > box.pos) {
                return grp;
            }
            return { pos: box.pos, value: [box.value] };
        }
        return group(p);
    };

    let result = list(0, address);
    if (result && result.pos === s.length) {
        return result.value;
    }

    // nothing but CFWS and commas
    let q = 0;
    for (;;) {
        let r = optCfws(q);
        if (s.charAt(r) === ',') {
            q = r + 1;
            continue;
        }
        return r === s.length ? [] : null;
    }
};

module.exports = { parseAddressList };
