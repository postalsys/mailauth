# BIMI Result Reference

This document describes the result object returned by BIMI (Brand Indicators for Message Identification) resolution.

## Overview

BIMI allows organizations to display brand logos in email clients. BIMI information is resolved during the authentication step, provided the message passes DMARC validation with a policy other than "none".

```javascript
const { authenticate } = require('mailauth');

const { bimi } = await authenticate(message, {
    ip: '192.0.2.1',
    helo: 'mail.example.com',
    sender: 'user@example.com'
});
```

## Result Object Fields

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `status` | `object` | Always | Resolution status object (see below) |
| `location` | `string` | Found | HTTPS URL for the logo SVG file (from `l=` tag) |
| `authority` | `string` | Found | HTTPS URL for the VMC/CMC certificate (from `a=` tag) |
| `preference` | `string` | When `p=` present | Logo preference value from DNS record |
| `rr` | `string` | Found | Raw BIMI DNS TXT record |
| `info` | `string` | Always | Formatted Authentication-Results header value |

## status Object

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `result` | `string` | Always | BIMI result code (see below) |
| `comment` | `string` | On skip/fail | Reason for skip or failure |
| `header` | `object` | Always | Header information |
| `policy` | `object` | VMC found | Authority policy details |

### status.header Object

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `selector` | `string` | Record found | BIMI selector used (e.g., `"default"`) |
| `d` | `string` | Record found | Domain where BIMI record was found |

### status.policy Object

| Field | Type | Description |
|-------|------|-------------|
| `authority` | `string` | VMC validation status (`"none"` before validation) |
| `authority-uri` | `string` | URL of the authority evidence document |

## Result Values

| Result | Description |
|--------|-------------|
| `pass` | BIMI record found and valid |
| `skipped` | BIMI lookup skipped (see skip reasons below) |
| `fail` | BIMI record found but invalid |
| `none` | No BIMI record found |
| `temperr` | Temporary error during DNS lookup |

## Skip Reasons

The `status.comment` field explains why BIMI was skipped:

| Comment | Description |
|---------|-------------|
| `"DMARC not enabled"` | DMARC result was `none` |
| `"message failed DMARC"` | DMARC result was not `pass` |
| `"too lax DMARC policy"` | DMARC policy is `none` or `quarantine` with `pct < 100` |
| `"Aligned DKIM signature required"` | `bimiWithAlignedDkim` option set but no aligned DKIM |
| `"undersized DKIM signature"` | DKIM signature has unsigned body bytes (due to `l=` tag) |
| `"could not determine domain"` | Unable to extract domain from headers |

## Fail Reasons

| Comment | Description |
|---------|-------------|
| `"multiple BIMI-Selector headers"` | Message has more than one BIMI-Selector header |
| `"missing bimi version in selector header"` | BIMI-Selector header missing `v=BIMI1` |
| `"missing bimi version in dns record"` | DNS record missing `v=BIMI1` |
| `"missing location value in dns record"` | Record has neither `l=` nor `a=` tag |
| `"invalid location value in dns record"` | `l=` value is not a valid HTTPS URL |
| `"invalid authority value in dns record"` | `a=` value is not a valid HTTPS URL |
| `"failed to resolve {domain}"` | DNS lookup error |
| `"invalid BIMI response for {domain}"` | DNS response format invalid |

## VMC Validation Result

When using `validateVMC()` to validate the authority evidence document:

```javascript
const { bimi, validateVMC } = require('mailauth/lib/bimi');

const bimiResult = await bimi(data);
const vmcResult = await validateVMC(bimiResult, options);
```

### VMC Result Object

| Field | Type | Description |
|-------|------|-------------|
| `location` | `object` | Logo file fetch result |
| `authority` | `object` | VMC/CMC fetch and validation result |
| `headers` | `object` | Ready-to-use email headers (only on validation success) |

### location Object

| Field | Type | Description |
|-------|------|-------------|
| `url` | `string` | Logo URL |
| `success` | `boolean` | Whether fetch succeeded |
| `logoFile` | `string` | Base64-encoded logo SVG (on success) |
| `error` | `object` | Error details (on failure) |
| `hashAlgo` | `string` | Hash algorithm used for verification |
| `hashValue` | `string` | Calculated hash of the logo file |

### authority Object

| Field | Type | Description |
|-------|------|-------------|
| `url` | `string` | VMC/CMC URL |
| `success` | `boolean` | Whether fetch and validation succeeded |
| `vmc` | `object` | Parsed VMC data (on success) |
| `domainVerified` | `boolean` | Whether domain matches certificate |
| `hashMatch` | `boolean` | Whether logo hash matches certificate |
| `error` | `object` | Error details (on failure) |

### headers Object

Present only when VMC validation succeeds. Contains ready-to-use email headers.

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `indicator` | `string` | Always | BIMI-Indicator header with base64-encoded SVG logo |
| `location` | `string` | Always | BIMI-Location header with logo URL |
| `preference` | `string` | `p=` tag present | BIMI-Logo-Preference header |

These headers should be added to messages after successful BIMI validation. The MTA should:
1. Remove any existing BIMI-* headers from incoming messages
2. Add these headers after successful validation

### VMC Error Codes

| Code | Description |
|------|-------------|
| `HTTP_REQUEST_FAILED` | HTTP request failed |
| `MISSING_VMC_LOGO` | VMC does not contain a logo file |
| `INVALID_MEDIATYPE` | Logo media type is not `image/svg+xml` |
| `INVALID_LOGO_HASH` | Logo hash does not match certificate |
| `SVG_VALIDATION_FAILED` | SVG file failed validation |
| `VMC_DOMAIN_MISMATCH` | Domain not found in certificate SAN |

## Example Output

### BIMI Pass

```json
{
  "status": {
    "result": "pass",
    "header": {
      "selector": "default",
      "d": "example.com"
    },
    "policy": {
      "authority": "none",
      "authority-uri": "https://example.com/bimi/vmc.pem"
    }
  },
  "location": "https://example.com/bimi/logo.svg",
  "authority": "https://example.com/bimi/vmc.pem",
  "preference": "self",
  "rr": "v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/vmc.pem; p=self",
  "info": "bimi=pass header.selector=default header.d=example.com policy.authority=none policy.authority-uri=https://example.com/bimi/vmc.pem"
}
```

### BIMI Skipped (DMARC Failed)

```json
{
  "status": {
    "result": "skipped",
    "comment": "message failed DMARC",
    "header": {}
  },
  "info": "bimi=skipped (message failed DMARC)"
}
```

### BIMI Skipped (Policy Too Lax)

```json
{
  "status": {
    "result": "skipped",
    "comment": "too lax DMARC policy",
    "header": {}
  },
  "info": "bimi=skipped (too lax DMARC policy)"
}
```

### BIMI None (No Record)

```json
{
  "status": {
    "result": "none",
    "header": {
      "selector": "default",
      "d": "example.com"
    }
  },
  "info": "bimi=none header.selector=default header.d=example.com"
}
```

### BIMI Fail (Invalid Record)

```json
{
  "status": {
    "result": "fail",
    "comment": "missing location value in dns record",
    "header": {
      "selector": "default",
      "d": "example.com"
    }
  },
  "rr": "v=BIMI1;",
  "info": "bimi=fail (missing location value in dns record) header.selector=default header.d=example.com"
}
```

### VMC Validation Result

```json
{
  "location": {
    "url": "https://example.com/bimi/logo.svg",
    "success": true,
    "logoFile": "PHN2ZyB4bWxucz0i...",
    "hashAlgo": "sha256",
    "hashValue": "abc123..."
  },
  "authority": {
    "url": "https://example.com/bimi/vmc.pem",
    "success": true,
    "domainVerified": true,
    "hashMatch": true,
    "vmc": {
      "type": "VMC",
      "mediaType": "image/svg+xml",
      "logoFile": "PHN2ZyB4bWxucz0i...",
      "hashAlgo": "sha256",
      "hashValue": "abc123...",
      "validHash": true,
      "certificate": {
        "subjectAltName": ["example.com", "*.example.com"]
      }
    }
  },
  "headers": {
    "indicator": "BIMI-Indicator: PHN2ZyB4bWxucz0i...",
    "location": "BIMI-Location: v=BIMI1; l=https://example.com/bimi/logo.svg",
    "preference": "BIMI-Logo-Preference: self"
  }
}
```
