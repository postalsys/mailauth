# DMARC Verification Result Reference

This document describes the result object returned by DMARC verification.

## Overview

DMARC (Domain-based Message Authentication, Reporting, and Conformance) is verified during the authentication process. The DMARC result depends on both SPF and DKIM verification results.

Policy discovery and Organizational Domains follow the DNS Tree Walk of RFC 9989 section 4.10, not the Public Suffix List. The policy is taken from the record of the author domain, or else from the record of its Organizational Domain, or else from a record published with `psd=y` above it. Relaxed alignment compares the Organizational Domains of the author domain and of each authenticated identifier, which can take further walks. A walk makes at most eight queries, lookups are shared within a message, only identifiers at or below the author's Organizational Domain are walked, and at most ten identifiers per message are walked.

```javascript
const { authenticate } = require('mailauth');

const { dmarc } = await authenticate(message, {
    ip: '192.0.2.1',
    helo: 'mail.example.com',
    sender: 'user@example.com'
});
```

## Result Object Fields

| Field       | Type      | Presence     | Description                                                           |
| ----------- | --------- | ------------ | --------------------------------------------------------------------- |
| `status`    | `object`  | Always       | Verification status object (see below)                                |
| `domain`    | `string`  | Always       | Organizational Domain of the author domain (Tree Walk)                |
| `policy`    | `string`  | Record found | Effective policy (`"reject"`, `"quarantine"`, or `"none"`), see below |
| `p`         | `string`  | Record found | Policy from `p=` tag                                                  |
| `sp`        | `string`  | Record found | Subdomain policy from `sp=` tag (defaults to `p` value)               |
| `np`        | `string`  | Record found | Non-existent subdomain policy from `np=` tag, if published            |
| `testMode`  | `boolean` | Record found | `true` when the record has `t=y`                                      |
| `rr`        | `string`  | Record found | Raw DMARC DNS TXT record                                              |
| `alignment` | `object`  | Record found | SPF and DKIM alignment details (see below)                            |
| `error`     | `string`  | On temperror | Error message                                                         |

On a `temperror` that happens after a record was found, because a Tree Walk needed for relaxed alignment failed and no other identifier aligned, `policy`, `p`, `sp`, `rr` and `alignment` are still set.
| `info` | `string` | Always | Formatted Authentication-Results header value |

`policy` is `p` for the author domain's own record. For a record inherited from the Organizational Domain or a PSD it is `np` when the author domain does not exist (NXDOMAIN, RFC 9989 A.4), otherwise `sp`, both falling back to `p`. The existence query is only made when the record has `np`. With `t=y` the policy is one level below that, so `reject` becomes `quarantine` and `quarantine` becomes `none`, while `p`, `sp` and `np` stay as published.

A record without a valid `p`, or with an invalid `sp` or `np`, is applied as `p=none` when its `rua` lists a valid URI, and otherwise gets no DMARC processing (result `none`). `pct` is historic in RFC 9989 and is ignored.

## status Object

| Field     | Type     | Description                   |
| --------- | -------- | ----------------------------- |
| `result`  | `string` | DMARC result code (see below) |
| `header`  | `object` | Header information            |
| `comment` | `string` | Policy and ARC information    |

### status.header Object

| Field  | Type     | Description                                                                             |
| ------ | -------- | --------------------------------------------------------------------------------------- |
| `from` | `string` | Domain of the From header address                                                       |
| `d`    | `string` | Domain where the applied DMARC record was found (author, Organizational Domain, or PSD) |

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

| Result      | Description                                                    |
| ----------- | -------------------------------------------------------------- |
| `pass`      | Message passed DMARC (SPF or DKIM aligned and passed)          |
| `fail`      | Message failed DMARC (neither SPF nor DKIM aligned)            |
| `none`      | No DMARC record found                                          |
| `temperror` | Temporary error during a DNS lookup that the result depends on |

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
        }
    },
    "domain": "example.com",
    "policy": "reject",
    "p": "reject",
    "sp": "reject",
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
    "info": "dmarc=pass (p=REJECT) header.from=example.com header.d=example.com"
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
        }
    },
    "domain": "example.com",
    "policy": "reject",
    "p": "reject",
    "sp": "reject",
    "rr": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "alignment": {
        "spf": {
            "strict": false
        },
        "dkim": {
            "strict": false
        }
    },
    "info": "dmarc=fail (p=REJECT) header.from=example.com header.d=example.com"
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
        }
    },
    "domain": "example.com",
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
    "info": "dmarc=pass (p=NONE sp=QUARANTINE) header.from=sub.example.com header.d=example.com"
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
