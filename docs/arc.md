# ARC Validation Result Reference

This document describes the result object returned by ARC (Authenticated Received Chain) validation and sealing.

## Overview

ARC validation is performed automatically during the authentication step. ARC allows intermediate mail handlers to sign messages, preserving authentication results across forwarding.

```javascript
const { authenticate } = require('mailauth');

const { arc } = await authenticate(message, {
    trustReceived: true
});
```

With `strict: true` the validation and sealing follow RFC 8617 exactly, see [Strict Mode](#strict-mode). The default mode is lenient about tag syntax, and marks what it accepted in the `warnings` array of the result (see [Warnings](#warnings)).

## Validation Result Object Fields

| Field                   | Type            | Presence          | Description                                                                                                                        |
| ----------------------- | --------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `status`                | `object`        | Always            | Validation status object (see below)                                                                                               |
| `chain`                 | `array`         | Non-enumerable    | Array of ARC chain entries (hidden from JSON serialization)                                                                        |
| `i`                     | `number\|false` | Always            | Last instance number in chain, or `false` if no chain                                                                              |
| `signature`             | `object`        | Chain exists      | Verification result for last ARC-Message-Signature                                                                                 |
| `authenticationResults` | `object`        | Chain exists      | Parsed last ARC-Authentication-Results                                                                                             |
| `info`                  | `string`        | Result not "none" | Formatted Authentication-Results header value. In strict mode also for "none"                                                      |
| `warnings`              | `string[]`      | Default mode      | What was accepted that strict mode would reject, see [Warnings](#warnings). Not set for a failing chain, never written into `info` |
| `sealErrors`            | `array`         | Sealing failed    | Why the message was not sealed when `authenticate()` was asked to seal it (see [Sealing](#sealing))                                |

## status Object

| Field        | Type      | Presence     | Description                                                                                              |
| ------------ | --------- | ------------ | -------------------------------------------------------------------------------------------------------- |
| `result`     | `string`  | Always       | ARC result code (see below)                                                                              |
| `comment`    | `string`  | On pass/fail | Description or error message                                                                             |
| `shouldSeal` | `boolean` | On fail      | Whether the failed chain is sealed with `cv=fail`, false when its newest ARC-Seal already says `cv=fail` |
| `policy`     | `object`  | Policy issue | Policy violation details (e.g., `{"dkim-rules": "weak-key"}`)                                            |
| `smtp`       | `object`  | Strict mode  | `{"remote-ip": "192.0.2.1"}`, the client IP (RFC 8617 section 6)                                         |

## authenticationResults Object

When ARC validation passes, the `authenticationResults` object contains parsed results from the last ARC-Authentication-Results header:

| Field   | Type     | Description                                                  |
| ------- | -------- | ------------------------------------------------------------ |
| `mta`   | `string` | Hostname of the MTA that added this ARC set                  |
| `arc`   | `object` | ARC result (`{result: "pass\|fail\|none", ...}`)             |
| `spf`   | `object` | SPF result (`{result: "pass\|fail\|...", ...}`)              |
| `dmarc` | `object` | DMARC result (`{result: "pass\|fail\|none", header: {...}}`) |
| `dkim`  | `array`  | Array of DKIM results                                        |

## Result Values

| Result | Description                      |
| ------ | -------------------------------- |
| `none` | No ARC chain present in message  |
| `pass` | ARC chain validated successfully |
| `fail` | ARC chain validation failed      |

## Comment Values (on failure)

| Comment Pattern                                                             | Description                                                                                                          |
| --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `"i={n} seal signature validation failed"`                                  | ARC-Seal cryptographic verification failed                                                                           |
| `"i={n} no valid signature"`                                                | ARC-Message-Signature verification failed                                                                            |
| `"i={n} multiple {header} values"`                                          | Duplicate ARC headers for same instance                                                                              |
| `"chain-length={n}"`                                                        | Chain exceeds 50 instances                                                                                           |
| `"i={n} expected={m}"`                                                      | Missing or out-of-order instance numbers                                                                             |
| `"i={n} no {header} set"`                                                   | Missing required ARC header                                                                                          |
| `"i=1 cv={value}"`                                                          | First instance must have `cv=none`                                                                                   |
| `"i={n} cv={value}"`                                                        | Non-first instance must have `cv=pass`, and a newest seal with `cv=fail` fails the chain                             |
| `"i={n} unexpected as h"`                                                   | ARC-Seal has an `h=` tag                                                                                             |
| `"i={n} invalid ams h"`                                                     | ARC-Message-Signature signed arc-seal (forbidden)                                                                    |
| `"i={n} as {problem}"`, `"i={n} ams {problem}"`                             | Strict mode: a tag-list syntax error, a missing required tag or a malformed `t=`/`x=`/`l=`                           |
| `"invalid as instance"`, `"invalid ams instance"`, `"invalid aar instance"` | Strict mode: an ARC header field whose `i=` is not 1 to 50 written as 1*2DIGIT (first in ARC-Authentication-Results) |
| `"no key for {domain}"`                                                     | DNS key not found                                                                                                    |
| `"unknown key version for {domain}"`                                        | Key record `v=` is not `DKIM1`                                                                                       |
| `"unknown key type for {domain}"`                                           | Unsupported key type                                                                                                 |
| `"invalid public key for {domain}"`                                         | Malformed public key                                                                                                 |
| `"inappropriate hash algorithm for {domain}"`                               | Key record `h=` does not list sha256                                                                                 |
| `"key not for email for {domain}"`                                          | Key record `s=` does not list email                                                                                  |
| `"inappropriate key algorithm for {domain}"`                                | The key type does not match the seal's `a=` algorithm                                                                |
| `"weak key for {domain}"`                                                   | RSA key too short                                                                                                    |

An ARC-Message-Signature that does not sign the From header field is not valid (RFC 6376 section 6.1.1), which fails the chain with `"i={n} no valid signature"` in both modes. An ARC-Seal `c=` tag is not defined by RFC 8617, so it is ignored like any other unknown tag.

## Strict Mode

These rules apply in both modes:

- `cv` values are compared case-insensitively (`cv=Pass` is `pass`), and every seal of the chain is validated.
- An Ed25519 seal signs the SHA-256 hash of the canonicalized data (RFC 8463).
- The seal's `a=` algorithm has to match the key type, and the key record's `v=`, `h=` and `s=` tags are honored.
- An ARC-Message-Signature without `c=` uses `simple/simple`, the DKIM-Signature default.

Differences between the modes:

| Input                                                                                                | Default                                                       | `strict: true`                                     |
| ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | -------------------------------------------------- |
| Duplicate tags, empty tag-specs, invalid tag names in ARC-Seal or the newest ARC-Message-Signature   | accepted, warning `arc-tag-syntax`                            | `fail`                                             |
| Upper case tag names (`S=` for `s=`)                                                                 | read as lower case, warning `arc-tag-syntax`                  | unknown tag, so usually `fail` for the missing tag |
| Missing required tags, malformed `t=`, `x=` or `l=`                                                  | warning `arc-tag-syntax` (a missing tag usually fails anyway) | `fail`                                             |
| `i=` written as `0x1`, `+1`, `1e0` or `1.0`                                                          | read as a number, warning `arc-instance-syntax`               | `fail`                                             |
| ARC header field with an `i=` that is missing or not a number from 1 to 50                           | ignored, warning `arc-instance-syntax`                        | `fail`                                             |
| ARC-Authentication-Results whose `i=` is not first                                                   | accepted, warning `arc-instance-syntax`                       | `fail`                                             |
| ARC-Message-Signature without `c=` that only verifies as `relaxed/relaxed` (the ARC drafts' default) | accepted, warning `ams-c-default`                             | `fail`                                             |
| No ARC chain                                                                                         | no `arc=` entry in Authentication-Results                     | `arc=none`                                         |
| Client IP                                                                                            | not reported                                                  | `smtp.remote-ip`                                   |

The position of `i=` in an ARC-Seal or ARC-Message-Signature is not checked in either mode. The RFC 8617 ABNF puts it first, but a tag-list is unordered (RFC 6376 section 3.2) and the ARC test suite places it elsewhere in all of its valid chains.

## Warnings

In the default mode `warnings` lists what was accepted although strict mode would have rejected it. It is only present when there is something to report and the chain did not fail, and it is never written into the Authentication-Results text.

| Warning                                           | Meaning                                                                                               |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `arc-tag-syntax`                                  | An ARC-Seal or the newest ARC-Message-Signature has a tag-list syntax error or an upper case tag name |
| `arc-instance-syntax`                             | An `i=` value is not valid RFC 8617 syntax, or an ARC header field was ignored because of its `i=`    |
| `ams-c-default`                                   | The ARC-Message-Signature has no `c=` and only verified with `relaxed/relaxed`                        |
| `key-syntax`, `key-v-syntax`, `key-type-inferred` | Key record leniencies, see the [DKIM result reference](dkim.md#warnings)                              |

## Sealing

`sealMessage(message, seal)` returns the ARC headers to prepend as a Buffer, and an empty Buffer when no ARC set was created. `createSeal(message, { seal, strict })` returns the reason as well:

| Field      | Type       | Description                                                                                       |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------- |
| `headers`  | `string[]` | ARC headers to prepend: `[ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results]`, or empty |
| `errors`   | `array`    | `{ err, type, selector, signingDomain }` entries saying why no set was created                    |
| `warnings` | `string[]` | What the default mode sealed that strict mode would have refused                                  |

Seal options:

| Option          | Type               | Description                                                                                                               |
| --------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `signingDomain` | `string`           | `d=` value                                                                                                                |
| `selector`      | `string`           | `s=` value                                                                                                                |
| `privateKey`    | `string\|Buffer`   | RSA or Ed25519 private key                                                                                                |
| `algorithm`     | `string`           | `rsa-sha256` or `ed25519-sha256`, follows the key type when not set                                                       |
| `authResults`   | `string`           | The Authentication-Results payload for the ARC-Authentication-Results header (required). Line breaks only as CRLF folding |
| `cv`            | `string`           | `none`, `pass` or `fail`. Defaults to `none` for the first set, required for later ones                                   |
| `i`             | `number`           | Instance, defaults to one more than the highest instance on the message                                                   |
| `headerList`    | `string\|string[]` | Header fields for the ARC-Message-Signature. ARC header fields and Authentication-Results are never signed                |
| `signTime`      | `Date`             | Signing time                                                                                                              |
| `strict`        | `boolean`          | Follow the RFCs exactly                                                                                                   |

`authenticate()` always computes `authResults`, `cv` and `i` for the message it seals and ignores these values in its `seal` option. The seal options object is never modified, so one object can be shared by concurrent calls.

No ARC set is created (in either mode) when:

| Error code            | Reason                                                                                                                                    |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `EARCCHAINFAILED`     | The newest ARC-Seal on the message already has `cv=fail` (RFC 8617 section 5.1 step 2)                                                    |
| `EINVALIDINSTANCE`    | The instance is not 1 to 50, already exists on the message, or the chain already has 50 sets                                              |
| `EINVALIDCV`          | `cv` is not `none`, `pass` or `fail`, is missing for an instance above 1, or is `pass` while the chain on the message could not be parsed |
| `EINVALIDALGO`        | The algorithm is not `rsa-sha256` or `ed25519-sha256`                                                                                     |
| `EINVALIDAUTHRESULTS` | `authResults` is missing or empty, or has a line break that is not folding (CRLF followed by a space or tab and more text)                |
| `EINVALIDTYPE`        | The algorithm does not match the key type                                                                                                 |

What only strict mode refuses (the default mode seals and adds the warning):

| Input                                                        | Warning            |
| ------------------------------------------------------------ | ------------------ |
| An explicit `i` that leaves a gap after the highest instance | `arc-instance-gap` |
| `cv=none` for an instance above 1, or not `none` for `i=1`   | `arc-cv-instance`  |
| An RSA key shorter than 1024 bits                            | `weak-key`         |

## Example Output

### ARC Pass

```json
{
    "status": {
        "result": "pass",
        "comment": "i=2 spf=pass dkim=pass dkdomain=example.com dmarc=pass fromdomain=example.com"
    },
    "i": 2,
    "signature": {
        "id": "abc123...",
        "signingDomain": "forwarder.example.net",
        "selector": "arc",
        "status": {
            "result": "pass"
        }
    },
    "authenticationResults": {
        "mta": "mx.forwarder.example.net",
        "spf": {
            "result": "pass",
            "smtp": {
                "mailfrom": "user@example.com"
            }
        },
        "dkim": [
            {
                "result": "pass",
                "header": {
                    "i": "@example.com",
                    "s": "selector1"
                }
            }
        ],
        "dmarc": {
            "result": "pass",
            "header": {
                "from": "example.com"
            }
        }
    },
    "info": "arc=pass (i=2 spf=pass dkim=pass dkdomain=example.com dmarc=pass fromdomain=example.com)"
}
```

### ARC Fail

```json
{
    "status": {
        "result": "fail",
        "comment": "i=2 seal signature validation failed",
        "shouldSeal": true
    },
    "i": 2,
    "info": "arc=fail (i=2 seal signature validation failed)"
}
```

### ARC None

```json
{
    "status": {
        "result": "none"
    },
    "i": 0
}
```

### Seal Headers Output

When using `sealMessage()`:

```javascript
const { sealMessage } = require('mailauth');

const sealHeaders = await sealMessage(message, {
    signingDomain: 'example.com',
    selector: 'arc',
    privateKey: privateKey,
    authResults: 'mx.example.com; spf=pass; dkim=pass',
    cv: 'pass'
});

// sealHeaders is a Buffer containing, for a message that already had one ARC set:
// ARC-Seal: i=2; a=rsa-sha256; cv=pass; d=example.com; s=arc; ...
// ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; ...
// ARC-Authentication-Results: i=2; mx.example.com; spf=pass; dkim=pass
```
