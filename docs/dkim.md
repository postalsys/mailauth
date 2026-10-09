# DKIM Verification Result Reference

This document describes the result object returned by `dkimVerify()`.

## Overview

The `dkimVerify` function verifies all DKIM-Signature headers in an email message and returns an object containing verification results for each signature.

```javascript
const { dkimVerify } = require('mailauth/lib/dkim/verify');

const result = await dkimVerify(message, { strict: false });
// result.results is an array of signature verification results
```

With `strict: true` the verification follows RFC 6376, RFC 8301 and RFC 8463 exactly. The default mode is lenient about weak and non-conforming signatures, and marks what it accepted in `status.warnings` (see [Warnings](#warnings)).

## Top-Level Result Object

| Field          | Type            | Description                                                                                          |
| -------------- | --------------- | ---------------------------------------------------------------------------------------------------- |
| `headerFrom`   | `string[]`      | Addresses from the From header, as full addr-specs. The mailboxes of a group (RFC 6854) are included |
| `envelopeFrom` | `string\|false` | Email address from Return-Path header or sender option                                               |
| `results`      | `object[]`      | Array of verification results for each DKIM signature                                                |

## Signature Result Object

Each entry in the `results` array has the following structure:

| Field                    | Type           | Presence         | Description                                                       |
| ------------------------ | -------------- | ---------------- | ----------------------------------------------------------------- |
| `id`                     | `string`       | Always           | SHA256 hash of signature value, or UUID if no signature           |
| `signingDomain`          | `string`       | Signature exists | Domain from `d=` tag                                              |
| `selector`               | `string`       | Signature exists | DKIM selector from `s=` tag                                       |
| `signature`              | `string`       | Signature exists | Base64-encoded signature value from `b=` tag                      |
| `algo`                   | `string`       | Signature exists | Signing algorithm (e.g., `"rsa-sha256"`, `"ed25519-sha256"`)      |
| `format`                 | `string`       | Signature exists | Canonicalization format from `c=` tag (e.g., `"relaxed/relaxed"`) |
| `bodyHash`               | `string`       | Signature exists | Calculated body hash (base64)                                     |
| `bodyHashExpecting`      | `string`       | Signature exists | Expected body hash from `bh=` tag                                 |
| `signingHeaders`         | `object`       | Signature exists | Signing header details (see below)                                |
| `status`                 | `object`       | Always           | Verification status (see below)                                   |
| `signTime`               | `string\|null` | Always           | ISO 8601 timestamp from `t=` tag, or null                         |
| `expiresAfter`           | `string\|null` | Always           | ISO 8601 expiration from `x=` tag, or null                        |
| `signatureTimeValid`     | `boolean`      | Always           | Whether signature is within validity window                       |
| `sourceBodyLength`       | `number`       | Body processed   | Original body length in bytes                                     |
| `canonBodyLength`        | `number`       | Body processed   | Canonicalized bytes actually hashed                               |
| `canonBodyLengthTotal`   | `number`       | Body processed   | Total canonicalized body length                                   |
| `canonBodyLengthLimited` | `boolean`      | Signature exists | Whether body length is limited by `l=` tag                        |
| `canonBodyLengthLimit`   | `number`       | `l=` tag present | Maximum body length from `l=` tag                                 |
| `mimeStructureStart`     | `number`       | MIME detected    | Position where MIME boundary structure starts                     |
| `publicKey`              | `string`       | Key retrieved    | PEM-formatted public key                                          |
| `modulusLength`          | `number`       | RSA key          | RSA key length in bits                                            |
| `rr`                     | `string`       | DNS lookup done  | Raw DNS TXT record value                                          |
| `info`                   | `string`       | Always           | Formatted Authentication-Results header value                     |

### signingHeaders Object

| Field                 | Type       | Description                                 |
| --------------------- | ---------- | ------------------------------------------- |
| `keys`                | `string[]` | List of header field names that were signed |
| `headers`             | `string[]` | Raw header lines that were signed           |
| `canonicalizedHeader` | `string`   | Base64-encoded canonicalized header data    |

### status Object

| Field        | Type            | Presence        | Description                                                                                           |
| ------------ | --------------- | --------------- | ----------------------------------------------------------------------------------------------------- |
| `result`     | `string`        | Always          | Verification result code (see below)                                                                  |
| `comment`    | `string`        | On error/info   | Human-readable explanation                                                                            |
| `aligned`    | `string\|false` | DKIM signatures | DMARC-aligned domain, or false (also when From does not yield a single Author Domain)                 |
| `header`     | `object`        | Always          | Signature header info                                                                                 |
| `policy`     | `object`        | Policy result   | Policy violation details                                                                              |
| `underSized` | `number`        | Body limited    | Number of unsigned bytes                                                                              |
| `testing`    | `boolean`       | Key has `t=y`   | The signing domain is testing DKIM (RFC 6376 section 3.6.1)                                           |
| `warnings`   | `string[]`      | Default mode    | What was accepted that strict mode would reject, see [Warnings](#warnings). Never written into `info` |

#### status.header Object

| Field | Type            | Description                                                                                                                                                                  |
| ----- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `d`   | `string`        | Strict mode only: the signing domain (`d=` tag)                                                                                                                              |
| `i`   | `string\|false` | Signing domain with @ prefix (e.g., `"@example.com"`). In strict mode the AUID: the `i=` value, or `@` and the signing domain when there is no `i=` (RFC 8601 section 2.7.1) |
| `s`   | `string`        | DKIM selector                                                                                                                                                                |
| `a`   | `string`        | Algorithm                                                                                                                                                                    |
| `b`   | `string`        | First 8 characters of signature value                                                                                                                                        |

## Result Values

| Result      | Description                                                                                                                                                                                |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pass`      | Signature verified successfully                                                                                                                                                            |
| `fail`      | Signature verification failed (bad signature). In strict mode also a body hash mismatch                                                                                                    |
| `neutral`   | Signature could not be verified (missing key, expired, body hash mismatch in the default mode, invalid signature)                                                                          |
| `policy`    | Signature failed policy check (a key shorter than `minBitLength`, or rsa-sha1 in strict mode or with `rejectRsaSha1`)                                                                      |
| `temperror` | Temporary error (DNS failure)                                                                                                                                                              |
| `none`      | Message not signed. In the default mode also a message whose only signatures use an unknown algorithm or canonicalization, or have no `d=` or `s=`. Strict mode reports those as `neutral` |

## Comment Values

Common values for `status.comment`:

| Comment                                             | Description                                                                                                                                                        |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `"body hash did not verify"`                        | Calculated body hash does not match `bh=` tag                                                                                                                      |
| `"bad signature"`                                   | Cryptographic signature verification failed                                                                                                                        |
| `"invalid expiration"`                              | Expiration timestamp is before signing timestamp                                                                                                                   |
| `"expired"`                                         | Signature has expired (past `x=` timestamp)                                                                                                                        |
| `"no key"`                                          | No DKIM key found in DNS, or the key record name can not exist in the DNS (an empty label, a label over 63 octets or a name over 253 octets), which is not queried |
| `"unknown key version"`                             | Unsupported key version in DNS record                                                                                                                              |
| `"unknown key type"`                                | Unsupported key type in DNS record                                                                                                                                 |
| `"invalid public key"`                              | Public key in DNS record is malformed, or revoked (empty `p=`)                                                                                                     |
| `"inappropriate hash algorithm"`                    | The key record `h=` tag does not list the hash algorithm of the signature (both modes)                                                                             |
| `"key not for email"`                               | The key record `s=` tag does not list `email` or `*` (both modes)                                                                                                  |
| `"From field not signed"`                           | The `h=` tag does not include From (both modes, RFC 6376 section 6.1.1)                                                                                            |
| `"weak algorithm"`                                  | Strict mode or `rejectRsaSha1`: rsa-sha1 signature (RFC 8301)                                                                                                      |
| `"signature syntax error"`                          | Strict mode: the signature is not valid RFC 6376 syntax. Both modes: `d=` has a character that can not be in a host name, such as `/`, `?`, `#`, `@` or `:`        |
| `"signature missing required tag"`                  | Strict mode: `v=`, `a=`, `b=`, `bh=`, `d=`, `h=` or `s=` is missing                                                                                                |
| `"incompatible version"`                            | Strict mode: `v=` is not 1                                                                                                                                         |
| `"domain mismatch"`                                 | Strict mode: the `i=` domain is not `d=` or its subdomain, or is a subdomain while the key has `t=s`                                                               |
| `"unsupported query method"`                        | Strict mode: `q=` does not list `dns/txt`                                                                                                                          |
| `"inappropriate key algorithm"`                     | The key type does not match the signature algorithm (both modes)                                                                                                   |
| `"unknown algorithm"`, `"unknown canonicalization"` | Strict mode: the signature can not be processed                                                                                                                    |
| `"DNS failure: {code}"`                             | DNS lookup failed with error code                                                                                                                                  |
| `"message not signed"`                              | No DKIM-Signature headers found                                                                                                                                    |

## Warnings

In the default mode `status.warnings` lists what was accepted although strict mode would have rejected it. The array is only present when there is something to report, and it is never written into the Authentication-Results text.

| Warning                                              | Meaning                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rsa-sha1`                                           | The signature uses rsa-sha1, which RFC 8301 section 3.1 does not allow. A domain can refuse it with `h=sha256` in its key record, which applies in both modes                                                                                                                                                                                   |
| `tag-syntax`                                         | Duplicate tags, upper case tag names, a malformed `c=`, `t=`, `x=` or `l=` value, an `l=` larger than the canonicalized body, or a `d=` or `s=` that is not a domain name, or that makes the key record name longer than 253 octets. A `d=` with a character that can not be in a host name is `neutral (signature syntax error)` in both modes |
| `missing-v`, `missing-h` (and the other `missing-*`) | A required tag is missing. Without `h=` the default header list is used, which includes From                                                                                                                                                                                                                                                    |
| `invalid-v`                                          | `v=` is not `1`                                                                                                                                                                                                                                                                                                                                 |
| `identity-domain`                                    | The `i=` domain is not `d=` or its subdomain, or it is a subdomain while the key record has `t=s`                                                                                                                                                                                                                                               |
| `invalid-expiration`                                 | `x=` is equal to `t=`. An `x=` before `t=` is `neutral (invalid expiration)` in both modes                                                                                                                                                                                                                                                      |
| `query-method`                                       | `q=` does not list `dns/txt`                                                                                                                                                                                                                                                                                                                    |
| `key-syntax`                                         | The key record is not valid tag-list syntax, or a `k=`, `s=` or `t=` value has whitespace inside it, which is removed                                                                                                                                                                                                                           |
| `key-v-syntax`                                       | The key record `v=` is not the first tag, or not exactly `DKIM1`                                                                                                                                                                                                                                                                                |
| `key-type-inferred`                                  | An Ed25519 key was recognized from its length, the key record has no `k=ed25519`                                                                                                                                                                                                                                                                |
| `key-ed25519-spki`                                   | An Ed25519 key record has the key as a SubjectPublicKeyInfo structure instead of the bare 32 octet key (RFC 8463 section 4.2). Strict mode reports `invalid public key`                                                                                                                                                                         |

A negative `l=` value is read as no limit in the default mode, so the whole body is covered and nothing is left unsigned. Strict mode reports it as a syntax error.

## Tag parsing

DKIM-Signature headers and key records are tag-lists (RFC 6376 section 3.2): semicolons separate the tags, and quotes, parentheses and backslashes are ordinary value characters. A note such as `n=it's` or a copied header in `z=` with a parenthesis in it does not affect the other tags. When the signature is hashed, only the value of its own `b=` tag is emptied, even when another tag contains the text `b=`.

## Example Output

### Successful Verification

```json
{
    "headerFrom": ["sender@example.com"],
    "envelopeFrom": "sender@example.com",
    "results": [
        {
            "id": "a1b2c3d4e5f6...",
            "signingDomain": "example.com",
            "selector": "selector1",
            "signature": "dGhpcyBpcyBhIHNpZ25hdHVyZQ==",
            "algo": "rsa-sha256",
            "format": "relaxed/relaxed",
            "bodyHash": "YWJjZGVmZ2hpamtsbW5vcA==",
            "bodyHashExpecting": "YWJjZGVmZ2hpamtsbW5vcA==",
            "signingHeaders": {
                "keys": ["from", "to", "subject", "date"],
                "headers": ["From: sender@example.com", "..."],
                "canonicalizedHeader": "..."
            },
            "status": {
                "result": "pass",
                "aligned": "example.com",
                "header": {
                    "i": "@example.com",
                    "s": "selector1",
                    "a": "rsa-sha256",
                    "b": "dGhpcyBp"
                }
            },
            "signTime": "2024-01-15T10:30:00.000Z",
            "expiresAfter": null,
            "signatureTimeValid": true,
            "sourceBodyLength": 1024,
            "canonBodyLength": 1020,
            "canonBodyLengthTotal": 1020,
            "canonBodyLengthLimited": false,
            "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
            "modulusLength": 2048,
            "rr": "v=DKIM1; k=rsa; p=...",
            "info": "dkim=pass header.i=@example.com header.s=selector1 header.a=rsa-sha256 header.b=\"dGhpcyBp\""
        }
    ]
}
```

### Failed Verification

```json
{
    "headerFrom": ["sender@example.com"],
    "envelopeFrom": "sender@example.com",
    "results": [
        {
            "id": "a1b2c3d4e5f6...",
            "signingDomain": "example.com",
            "selector": "selector1",
            "status": {
                "result": "neutral",
                "comment": "no key",
                "header": {
                    "i": "@example.com",
                    "s": "selector1",
                    "a": "rsa-sha256",
                    "b": "dGhpcyBp"
                }
            },
            "info": "dkim=neutral (no key) header.i=@example.com header.s=selector1 header.a=rsa-sha256 header.b=\"dGhpcyBp\""
        }
    ]
}
```

### Unsigned Message

```json
{
    "headerFrom": ["sender@example.com"],
    "envelopeFrom": "sender@example.com",
    "results": [
        {
            "status": {
                "result": "none",
                "comment": "message not signed"
            },
            "info": "dkim=none (message not signed)"
        }
    ]
}
```
