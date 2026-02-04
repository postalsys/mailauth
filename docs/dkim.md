# DKIM Verification Result Reference

This document describes the result object returned by `dkimVerify()`.

## Overview

The `dkimVerify` function verifies all DKIM-Signature headers in an email message and returns an object containing verification results for each signature.

```javascript
const { dkimVerify } = require('mailauth/lib/dkim/verify');

const result = await dkimVerify(message);
// result.results is an array of signature verification results
```

## Top-Level Result Object

| Field | Type | Description |
|-------|------|-------------|
| `headerFrom` | `string[]` | Array of email addresses from the From header |
| `envelopeFrom` | `string\|false` | Email address from Return-Path header or sender option |
| `results` | `object[]` | Array of verification results for each DKIM signature |

## Signature Result Object

Each entry in the `results` array has the following structure:

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `id` | `string` | Always | SHA256 hash of signature value, or UUID if no signature |
| `signingDomain` | `string` | Signature exists | Domain from `d=` tag |
| `selector` | `string` | Signature exists | DKIM selector from `s=` tag |
| `signature` | `string` | Signature exists | Base64-encoded signature value from `b=` tag |
| `algo` | `string` | Signature exists | Signing algorithm (e.g., `"rsa-sha256"`, `"ed25519-sha256"`) |
| `format` | `string` | Signature exists | Canonicalization format from `c=` tag (e.g., `"relaxed/relaxed"`) |
| `bodyHash` | `string` | Signature exists | Calculated body hash (base64) |
| `bodyHashExpecting` | `string` | Signature exists | Expected body hash from `bh=` tag |
| `signingHeaders` | `object` | Signature exists | Signing header details (see below) |
| `status` | `object` | Always | Verification status (see below) |
| `signTime` | `string\|null` | Always | ISO 8601 timestamp from `t=` tag, or null |
| `expiresAfter` | `string\|null` | Always | ISO 8601 expiration from `x=` tag, or null |
| `signatureTimeValid` | `boolean` | Always | Whether signature is within validity window |
| `sourceBodyLength` | `number` | Body processed | Original body length in bytes |
| `canonBodyLength` | `number` | Body processed | Canonicalized bytes actually hashed |
| `canonBodyLengthTotal` | `number` | Body processed | Total canonicalized body length |
| `canonBodyLengthLimited` | `boolean` | Signature exists | Whether body length is limited by `l=` tag |
| `canonBodyLengthLimit` | `number` | `l=` tag present | Maximum body length from `l=` tag |
| `mimeStructureStart` | `number` | MIME detected | Position where MIME boundary structure starts |
| `publicKey` | `string` | Key retrieved | PEM-formatted public key |
| `modulusLength` | `number` | RSA key | RSA key length in bits |
| `rr` | `string` | DNS lookup done | Raw DNS TXT record value |
| `info` | `string` | Always | Formatted Authentication-Results header value |

### signingHeaders Object

| Field | Type | Description |
|-------|------|-------------|
| `keys` | `string[]` | List of header field names that were signed |
| `headers` | `string[]` | Raw header lines that were signed |
| `canonicalizedHeader` | `string` | Base64-encoded canonicalized header data |

### status Object

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `result` | `string` | Always | Verification result code (see below) |
| `comment` | `string` | On error/info | Human-readable explanation |
| `aligned` | `string\|false` | DKIM signatures | DMARC-aligned domain, or false |
| `header` | `object` | Always | Signature header info |
| `policy` | `object` | Policy result | Policy violation details |
| `underSized` | `number` | Body limited | Number of unsigned bytes |

#### status.header Object

| Field | Type | Description |
|-------|------|-------------|
| `i` | `string\|false` | Signing domain with @ prefix (e.g., `"@example.com"`) |
| `s` | `string` | DKIM selector |
| `a` | `string` | Algorithm |
| `b` | `string` | First 8 characters of signature value |

## Result Values

| Result | Description |
|--------|-------------|
| `pass` | Signature verified successfully |
| `fail` | Signature verification failed (bad signature) |
| `neutral` | Signature could not be verified (missing key, expired, body hash mismatch) |
| `policy` | Signature failed policy check (e.g., weak key) |
| `temperror` | Temporary error (DNS failure) |
| `none` | Message not signed |

## Comment Values

Common values for `status.comment`:

| Comment | Description |
|---------|-------------|
| `"body hash did not verify"` | Calculated body hash does not match `bh=` tag |
| `"bad signature"` | Cryptographic signature verification failed |
| `"invalid expiration"` | Expiration timestamp is before signing timestamp |
| `"expired"` | Signature has expired (past `x=` timestamp) |
| `"no key"` | No DKIM key found in DNS |
| `"unknown key version"` | Unsupported key version in DNS record |
| `"unknown key type"` | Unsupported key type in DNS record |
| `"invalid public key"` | Public key in DNS record is malformed |
| `"DNS failure: {code}"` | DNS lookup failed with error code |
| `"message not signed"` | No DKIM-Signature headers found |

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
