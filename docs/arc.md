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

## Validation Result Object Fields

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `status` | `object` | Always | Validation status object (see below) |
| `chain` | `array` | Non-enumerable | Array of ARC chain entries (hidden from JSON serialization) |
| `i` | `number\|false` | Always | Last instance number in chain, or `false` if no chain |
| `signature` | `object` | Chain exists | Verification result for last ARC-Message-Signature |
| `authenticationResults` | `object` | Chain exists | Parsed last ARC-Authentication-Results |
| `info` | `string` | Result not "none" | Formatted Authentication-Results header value |

## status Object

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `result` | `string` | Always | ARC result code (see below) |
| `comment` | `string` | On pass/fail | Description or error message |
| `shouldSeal` | `boolean` | On fail | Whether to continue sealing despite failure |
| `policy` | `object` | Policy issue | Policy violation details (e.g., `{"dkim-rules": "weak-key"}`) |

## authenticationResults Object

When ARC validation passes, the `authenticationResults` object contains parsed results from the last ARC-Authentication-Results header:

| Field | Type | Description |
|-------|------|-------------|
| `mta` | `string` | Hostname of the MTA that added this ARC set |
| `arc` | `object` | ARC result (`{result: "pass\|fail\|none", ...}`) |
| `spf` | `object` | SPF result (`{result: "pass\|fail\|...", ...}`) |
| `dmarc` | `object` | DMARC result (`{result: "pass\|fail\|none", header: {...}}`) |
| `dkim` | `array` | Array of DKIM results |

## Result Values

| Result | Description |
|--------|-------------|
| `none` | No ARC chain present in message |
| `pass` | ARC chain validated successfully |
| `fail` | ARC chain validation failed |

## Comment Values (on failure)

| Comment Pattern | Description |
|-----------------|-------------|
| `"i={n} seal signature validation failed"` | ARC-Seal cryptographic verification failed |
| `"i={n} no valid signature"` | ARC-Message-Signature verification failed |
| `"i={n} multiple {header} values"` | Duplicate ARC headers for same instance |
| `"chain-length={n}"` | Chain exceeds 50 instances |
| `"i={n} expected={m}"` | Missing or out-of-order instance numbers |
| `"i={n} no {header} set"` | Missing required ARC header |
| `"i=1 cv={value}"` | First instance must have `cv=none` |
| `"i={n} cv={value}"` | Non-first instance must have `cv=pass` |
| `"i={n} invalid as c"` | Invalid canonicalization for ARC-Seal |
| `"i={n} invalid ams h"` | ARC-Message-Signature signed arc-seal (forbidden) |
| `"no key for {domain}"` | DNS key not found |
| `"unknown key version for {domain}"` | Unsupported key version |
| `"unknown key type for {domain}"` | Unsupported key type |
| `"invalid public key for {domain}"` | Malformed public key |
| `"weak key for {domain}"` | RSA key too short |

## Seal Result Object

When sealing a message with `sealMessage()`, the result contains:

| Field | Type | Description |
|-------|------|-------------|
| `headers` | `string[]` | Array of ARC headers to prepend: `[ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results]` |

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

// sealHeaders is a Buffer containing:
// ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=example.com; s=arc; ...
// ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; ...
// ARC-Authentication-Results: i=1; mx.example.com; spf=pass; dkim=pass
```
