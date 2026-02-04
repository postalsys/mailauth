# MTA-STS Result Reference

This document describes the result objects returned by MTA-STS (Mail Transfer Agent Strict Transport Security) functions.

## Overview

MTA-STS allows domain owners to declare that their mail servers support TLS and specify policies for message delivery. mailauth provides functions to fetch, parse, and validate MTA-STS policies.

```javascript
const { getPolicy, validateMx } = require('mailauth/lib/mta-sts');
```

## getPolicy Result

The `getPolicy` function fetches and returns the MTA-STS policy for a domain.

```javascript
const { policy, status } = await getPolicy('example.com', knownPolicy);
```

### Result Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `policy` | `object` | The MTA-STS policy object (see below) |
| `status` | `string` | Policy retrieval status (see below) |

### Status Values

| Status | Description |
|--------|-------------|
| `found` | New or updated policy was fetched successfully |
| `not_found` | No MTA-STS policy exists for the domain |
| `renewed` | Existing policy is still valid (ID unchanged, not expired) |
| `errored` | Policy discovery failed due to an error |

### Policy Object Fields

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `id` | `string\|false` | Always | Policy ID from DNS TXT record, or `false` if not found |
| `version` | `string` | Policy found | Always `"STSv1"` for valid policies |
| `mode` | `string` | Always | Policy mode (see below) |
| `mx` | `string[]` | Mode not "none" | Array of allowed MX hostnames (may include wildcards) |
| `maxAge` | `number` | Policy found | Policy validity period in seconds |
| `expires` | `string` | Policy found | ISO 8601 expiration timestamp |
| `error` | `Error` | On error | Error object if discovery failed |

### Mode Values

| Mode | Description |
|------|-------------|
| `testing` | Policy is in test mode; report violations but don't enforce |
| `enforce` | Strictly enforce TLS and MX restrictions |
| `none` | No policy in effect |

## validateMx Result

The `validateMx` function checks if an MX hostname is valid according to the MTA-STS policy.

```javascript
const result = validateMx('alt1.mx.example.com', policy);
```

### Result Object Fields

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `valid` | `boolean` | Always | Whether the MX hostname is allowed |
| `mode` | `string` | Always | Policy mode (`"testing"`, `"enforce"`, or `"none"`) |
| `match` | `string` | Valid match | The pattern that matched (exact hostname or wildcard) |
| `testing` | `boolean` | Always | Whether policy is in testing mode |

## Example Output

### Policy Found

```json
{
  "policy": {
    "id": "20240115T120000",
    "version": "STSv1",
    "mode": "enforce",
    "mx": [
      "mx1.example.com",
      "mx2.example.com",
      "*.mail.example.com"
    ],
    "maxAge": 86400,
    "expires": "2024-01-16T12:00:00.000Z"
  },
  "status": "found"
}
```

### Policy Not Found

```json
{
  "policy": {
    "id": false,
    "mode": "none"
  },
  "status": "not_found"
}
```

### Policy Renewed (Cached)

```json
{
  "policy": {
    "id": "20240115T120000",
    "version": "STSv1",
    "mode": "enforce",
    "mx": [
      "mx1.example.com",
      "mx2.example.com"
    ],
    "maxAge": 86400,
    "expires": "2024-01-16T12:00:00.000Z"
  },
  "status": "renewed"
}
```

### Policy Error

```json
{
  "policy": {
    "id": "20240115T120000",
    "mode": "none",
    "expires": "2024-01-15T13:00:00.000Z",
    "error": {
      "message": "Request timeout for https://mta-sts.example.com/.well-known/mta-sts.txt",
      "code": "HTTP_SOCKET_TIMEOUT"
    }
  },
  "status": "errored"
}
```

### MX Validation - Valid Match

```json
{
  "valid": true,
  "mode": "enforce",
  "match": "mx1.example.com",
  "testing": false
}
```

### MX Validation - Wildcard Match

```json
{
  "valid": true,
  "mode": "enforce",
  "match": ".mail.example.com",
  "testing": false
}
```

### MX Validation - Invalid

```json
{
  "valid": false,
  "mode": "enforce",
  "testing": false
}
```

### MX Validation - Testing Mode

```json
{
  "valid": true,
  "mode": "testing",
  "match": "mx1.example.com",
  "testing": true
}
```

### MX Validation - No Policy

```json
{
  "valid": true,
  "mode": "none",
  "testing": false
}
```

## Error Codes

Errors that may appear in `policy.error`:

| Code | Description |
|------|-------------|
| `multi_sts_records` | Multiple TXT records found for `_mta-sts.{domain}` |
| `invalid_sts_version` | Policy file has invalid or missing version field |
| `invalid_sts_mode` | Policy file has invalid mode value |
| `invalid_sts_max_age` | Policy file has invalid max_age value |
| `invalid_sts_mx` | Policy file missing mx field in enforce/testing mode |
| `HTTP_SOCKET_TIMEOUT` | HTTP request timed out |
| `http_status_{code}` | HTTP request returned non-2xx status |
| `ENOTFOUND` | DNS lookup failed (domain not found) |
| `ENODATA` | DNS lookup returned no data |

## Usage Example

```javascript
const { getPolicy, validateMx } = require('mailauth/lib/mta-sts');

// Fetch policy
const { policy, status } = await getPolicy('gmail.com');

console.log(`Policy status: ${status}`);
console.log(`Policy mode: ${policy.mode}`);

if (policy.mode !== 'none') {
    // Validate MX hostname
    const mx = 'alt1.gmail-smtp-in.l.google.com';
    const validation = validateMx(mx, policy);

    if (!validation.valid && !validation.testing) {
        console.error(`MX ${mx} is not allowed by MTA-STS policy`);
        // Reject delivery attempt
    } else if (!validation.valid && validation.testing) {
        console.warn(`MX ${mx} violates MTA-STS policy (testing mode)`);
        // Report violation but continue
    } else {
        console.log(`MX ${mx} is allowed`);
    }
}
```
