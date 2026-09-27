# DMARC Verification Result Reference

This document describes the result object returned by DMARC verification.

## Overview

DMARC (Domain-based Message Authentication, Reporting, and Conformance) is verified during the authentication process. The DMARC result depends on both SPF and DKIM verification results.

Policy discovery and Organizational Domains follow the DNS Tree Walk of RFC 9989 section 4.10, not the Public Suffix List. The policy is taken from the record of the author domain, or else from the record of its Organizational Domain, or else from a record published with `psd=y` above it. Relaxed alignment compares the Organizational Domains of the author domain and of each authenticated identifier, which can take further walks. A walk makes at most eight queries, lookups are shared within a message, only identifiers at or below the author's Organizational Domain are walked, and at most ten identifiers per message are walked. An identifier past that limit is treated like one whose walk failed: it gives `temperror` unless another identifier aligns, never a definite `fail`.

```javascript
const { authenticate } = require('mailauth');

const { dmarc } = await authenticate(message, {
    ip: '192.0.2.1',
    helo: 'mail.example.com',
    sender: 'user@example.com'
});
```

The author domain is the domain of the addr-spec in the From header (RFC 9989 5.3.1, RFC 5322 3.4.1). An "@" inside a quoted local-part (`"ceo@x"@bank.example`) or an obsolete source route (`<@relay.example:ceo@bank.example>`) does not change it. It is lower-cased, converted to an A-label, and a trailing dot is ignored. Several From addresses are evaluated when they all have the same domain. When there is no domain, or more than one, or a mailbox has no usable domain, or the message has more than one From header field, DMARC validation is not possible: `dmarc()` returns `false` and `authenticate()` returns `dmarc: false`, as for a message without a From address. The lower level `evaluateDmarc()` from `mailauth/lib/dmarc` also returns `reason` (`"no-author-domain"`, `"multiple-author-domains"`, `"invalid-author-domain"` or `"multiple-from-fields"`) and `authorDomains` in that case. RFC 9989 11.5 warns that such messages are often abusive, so a receiver should handle them by local policy instead of treating them as mail without DMARC.

```javascript
const { dmarc } = require('mailauth/lib/dmarc');

const result = await dmarc({
    headerFrom: 'user@example.com', // or a list of From addresses
    spfDomains: ['example.com'], // the MAIL FROM domain, if SPF passed
    dkimDomains: [{ domain: 'example.com' }], // signing domains of passing DKIM signatures
    strict: false, // true for the RFC tag-list rules and no header.d, see below
    resolver // optional, defaults to dns.promises.resolve
});
```

### Strict mode

With `strict: true`, which `authenticate(message, { strict: true })` passes on:

- Records are parsed by the tag-list rules of RFC 6376 3.2 that DMARC uses (RFC 9989 4.7). Tag names are case sensitive, so `P=reject` is an unknown tag (only the version tag may be `V`, which the DMARC ABNF allows), and a record with a duplicated tag is invalid and ignored, as if it was not published. By default tag names are case-folded and the last of duplicated tags wins, and the result lists `"tag-case"` or `"duplicate-tag"` in `warnings`.
- `status.header.d` is not set and `header.d` is left out of the Authentication-Results entry, because it is not a registered property for `dmarc` (RFC 9989 9.1). `policyDomain` still has the domain.

## Result Object Fields

| Field          | Type       | Presence     | Description                                                                      |
| -------------- | ---------- | ------------ | -------------------------------------------------------------------------------- |
| `status`       | `object`   | Always       | Verification status object (see below)                                           |
| `domain`       | `string`   | Always       | Organizational Domain of the author domain (Tree Walk)                           |
| `policy`       | `string`   | Record found | Effective policy (`"reject"`, `"quarantine"`, or `"none"`), see below            |
| `p`            | `string`   | Record found | Policy from `p=` tag                                                             |
| `sp`           | `string`   | Record found | Subdomain policy from `sp=` tag (defaults to `p` value)                          |
| `np`           | `string`   | Record found | Non-existent subdomain policy from `np=` tag, if published                       |
| `testMode`     | `boolean`  | Record found | `true` when the record has `t=y`                                                 |
| `rr`           | `string`   | Record found | Raw DMARC DNS TXT record                                                         |
| `policyDomain` | `string`   | Record found | The DMARC Policy Domain (RFC 9989 3.2.5), where the applied record was published |
| `alignment`    | `object`   | Record found | SPF and DKIM alignment details (see below)                                       |
| `error`        | `string`   | On temperror | Error message                                                                    |
| `warnings`     | `string[]` | Lax parsing  | What the default mode accepted that `strict` would not (see Strict mode)         |
| `info`         | `string`   | Always       | Formatted Authentication-Results header value                                    |

On a `temperror` that happens after a record was found, `policy`, `p`, `sp`, `rr` and `alignment` are still set. That is the case when a Tree Walk needed for relaxed alignment failed or was over the limit and no other identifier aligned, or when the existence query that chooses between `sp` and `np` failed and nothing aligned.

`policyDomain` is the domain an RFC 9990 aggregate report lists as the domain of the published policy. By default it is also in `status.header.d`. `domain` is the Organizational Domain, which is a different domain when the policy came from the author domain's own record below it, or from a PSD above it.

`policy` is `p` for the author domain's own record. For a record inherited from the Organizational Domain or a PSD it is `np` when the author domain does not exist (NXDOMAIN, RFC 9989 A.4), otherwise `sp`, both falling back to `p`. The existence query is only made when the record has `np`. When it fails and `np` differs from the other policy, a message that passes still passes, `policy` is the weaker of the two and `policy.dmarc` is left out, and a message that does not pass gets `temperror`. With `t=y` the policy is one level below that, so `reject` becomes `quarantine` and `quarantine` becomes `none`, while `p`, `sp` and `np` stay as published.

A record without a valid `p`, or with an invalid `sp` or `np`, is applied as `p=none` when its `rua` lists a syntactically valid URI (RFC 3986, so `mailto:` counts and a bare address does not), and otherwise gets no DMARC processing (result `none`). `pct` is historic in RFC 9989 and is ignored.

## status Object

| Field     | Type     | Description                                             |
| --------- | -------- | ------------------------------------------------------- |
| `result`  | `string` | DMARC result code (see below)                           |
| `header`  | `object` | Header information                                      |
| `policy`  | `object` | `{ dmarc }`, the evaluated policy, on `pass` and `fail` |
| `comment` | `string` | Policy and ARC information                              |

`policy.dmarc` (RFC 9989 9.1) is the `policy` value, so after `sp`, `np` and `t=y` were applied. It is only set when the result is `pass` or `fail` and the policy is known.

### status.header Object

| Field  | Type     | Description                                                                                                     |
| ------ | -------- | --------------------------------------------------------------------------------------------------------------- |
| `from` | `string` | Domain of the From header address                                                                               |
| `d`    | `string` | Domain where the applied DMARC record was found (author, Organizational Domain, or PSD). Not set in strict mode |

## alignment Object

| Field  | Type     | Description            |
| ------ | -------- | ---------------------- |
| `spf`  | `object` | SPF alignment details  |
| `dkim` | `object` | DKIM alignment details |

### alignment.spf Object

| Field    | Type                | Description                                                     |
| -------- | ------------------- | --------------------------------------------------------------- |
| `result` | `string\|undefined` | Aligned domain if SPF passed and aligned, otherwise `undefined` |
| `strict` | `boolean`           | Whether strict alignment is required (`aspf=s`)                 |

### alignment.dkim Object

| Field        | Type                | Description                                                      |
| ------------ | ------------------- | ---------------------------------------------------------------- |
| `result`     | `string\|undefined` | Aligned domain if DKIM passed and aligned, otherwise `undefined` |
| `strict`     | `boolean`           | Whether strict alignment is required (`adkim=s`)                 |
| `underSized` | `number`            | Number of unsigned body bytes (if `l=` tag limited body)         |

`underSized` is reported for a signature that aligns at the organizational domain even when `adkim=s` rejected it, so that it stays a reliable content-integrity warning regardless of the alignment mode the domain publishes.

## Result Values

| Result      | Description                                                                                                                               |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `pass`      | Message passed DMARC (SPF or DKIM aligned and passed)                                                                                     |
| `fail`      | Message failed DMARC (neither SPF nor DKIM aligned)                                                                                       |
| `none`      | No DMARC record found                                                                                                                     |
| `temperror` | Temporary error during a DNS lookup that the result depends on, or an identifier that could not be checked because of the Tree Walk limit |

## Policy Values

| Policy       | Description                                 |
| ------------ | ------------------------------------------- |
| `none`       | No specific action requested (monitor mode) |
| `quarantine` | Suspicious messages should be quarantined   |
| `reject`     | Failed messages should be rejected          |

## Comment Format

The `status.comment` field contains policy information in the format:

```
p=POLICY sp=SUBDOMAIN_POLICY arc=ARC_RESULT
```

For example: `"p=REJECT sp=REJECT arc=pass"`

## Example Output

### DMARC Pass

```json
{
    "status": {
        "result": "pass",
        "comment": "p=REJECT",
        "header": {
            "from": "example.com",
            "d": "example.com"
        },
        "policy": {
            "dmarc": "reject"
        }
    },
    "domain": "example.com",
    "policyDomain": "example.com",
    "policy": "reject",
    "p": "reject",
    "sp": "reject",
    "testMode": false,
    "rr": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "alignment": {
        "spf": {
            "strict": false
        },
        "dkim": {
            "result": "example.com",
            "strict": false
        }
    },
    "info": "dmarc=pass (p=REJECT) policy.dmarc=reject header.from=example.com header.d=example.com"
}
```

### DMARC Fail

```json
{
    "status": {
        "result": "fail",
        "comment": "p=REJECT",
        "header": {
            "from": "example.com",
            "d": "example.com"
        },
        "policy": {
            "dmarc": "reject"
        }
    },
    "domain": "example.com",
    "policyDomain": "example.com",
    "policy": "reject",
    "p": "reject",
    "sp": "reject",
    "testMode": false,
    "rr": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "alignment": {
        "spf": {
            "strict": false
        },
        "dkim": {
            "strict": false
        }
    },
    "info": "dmarc=fail (p=REJECT) policy.dmarc=reject header.from=example.com header.d=example.com"
}
```

### DMARC None (No Record)

```json
{
    "status": {
        "result": "none",
        "header": {
            "from": "no-dmarc.example.com"
        }
    },
    "domain": "no-dmarc.example.com",
    "info": "dmarc=none header.from=no-dmarc.example.com"
}
```

### DMARC with Subdomain Policy

```json
{
    "status": {
        "result": "pass",
        "comment": "p=NONE sp=QUARANTINE",
        "header": {
            "from": "sub.example.com",
            "d": "example.com"
        },
        "policy": {
            "dmarc": "quarantine"
        }
    },
    "domain": "example.com",
    "policyDomain": "example.com",
    "policy": "quarantine",
    "p": "none",
    "sp": "quarantine",
    "rr": "v=DMARC1; p=none; sp=quarantine; rua=mailto:dmarc@example.com",
    "alignment": {
        "spf": {
            "result": "sub.example.com",
            "strict": false
        },
        "dkim": {
            "strict": false
        }
    },
    "info": "dmarc=pass (p=NONE sp=QUARANTINE) policy.dmarc=quarantine header.from=sub.example.com header.d=example.com"
}
```

### DMARC Temperror

```json
{
    "status": {
        "result": "temperror",
        "header": {
            "from": "example.com"
        }
    },
    "domain": "example.com",
    "error": "DNS timeout",
    "info": "dmarc=temperror header.from=example.com"
}
```
