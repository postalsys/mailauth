# DMARC Verification Result Reference

This document describes the result object returned by DMARC verification.

## Overview

DMARC (Domain-based Message Authentication, Reporting, and Conformance) is verified during the authentication process. The DMARC result depends on both SPF and DKIM verification results.

```javascript
const { authenticate } = require('mailauth');

const { dmarc } = await authenticate(message, {
    ip: '192.0.2.1',
    helo: 'mail.example.com',
    sender: 'user@example.com'
});
```

## Result Object Fields

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `status` | `object` | Always | Verification status object (see below) |
| `domain` | `string` | Always | Organizational domain used for DMARC lookup |
| `policy` | `string` | Record found | Effective policy (`"reject"`, `"quarantine"`, or `"none"`) |
| `p` | `string` | Record found | Policy from `p=` tag |
| `sp` | `string` | Record found | Subdomain policy from `sp=` tag (defaults to `p` value) |
| `pct` | `number` | Record found | Percentage of messages to apply policy (0-100) |
| `rr` | `string` | Record found | Raw DMARC DNS TXT record |
| `alignment` | `object` | Record found | SPF and DKIM alignment details (see below) |
| `error` | `string` | On temperror | Error message |
| `info` | `string` | Always | Formatted Authentication-Results header value |

## status Object

| Field | Type | Description |
|-------|------|-------------|
| `result` | `string` | DMARC result code (see below) |
| `header` | `object` | Header information |
| `comment` | `string` | Policy and ARC information |

### status.header Object

| Field | Type | Description |
|-------|------|-------------|
| `from` | `string` | Organizational domain from the From header |
| `d` | `string` | Domain where DMARC record was found |

## alignment Object

| Field | Type | Description |
|-------|------|-------------|
| `spf` | `object` | SPF alignment details |
| `dkim` | `object` | DKIM alignment details |

### alignment.spf Object

| Field | Type | Description |
|-------|------|-------------|
| `result` | `string\|false` | Aligned domain if SPF passed and aligned, otherwise `false` |
| `strict` | `boolean` | Whether strict alignment is required (`aspf=s`) |

### alignment.dkim Object

| Field | Type | Description |
|-------|------|-------------|
| `result` | `string\|false` | Aligned domain if DKIM passed and aligned, otherwise `false` |
| `strict` | `boolean` | Whether strict alignment is required (`adkim=s`) |
| `underSized` | `number` | Number of unsigned body bytes (if `l=` tag limited body) |

## Result Values

| Result | Description |
|--------|-------------|
| `pass` | Message passed DMARC (SPF or DKIM aligned and passed) |
| `fail` | Message failed DMARC (neither SPF nor DKIM aligned) |
| `none` | No DMARC record found |
| `temperror` | Temporary error during DNS lookup |

## Policy Values

| Policy | Description |
|--------|-------------|
| `none` | No specific action requested (monitor mode) |
| `quarantine` | Suspicious messages should be quarantined |
| `reject` | Failed messages should be rejected |

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
    "header": {
      "from": "example.com",
      "d": "example.com"
    },
    "comment": "p=REJECT arc=none"
  },
  "domain": "example.com",
  "policy": "reject",
  "p": "reject",
  "sp": "reject",
  "pct": 100,
  "rr": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
  "alignment": {
    "spf": {
      "result": false,
      "strict": false
    },
    "dkim": {
      "result": "example.com",
      "strict": false
    }
  },
  "info": "dmarc=pass (p=REJECT arc=none) header.from=example.com"
}
```

### DMARC Fail

```json
{
  "status": {
    "result": "fail",
    "header": {
      "from": "example.com",
      "d": "example.com"
    },
    "comment": "p=REJECT"
  },
  "domain": "example.com",
  "policy": "reject",
  "p": "reject",
  "sp": "reject",
  "pct": 100,
  "rr": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
  "alignment": {
    "spf": {
      "result": false,
      "strict": false
    },
    "dkim": {
      "result": false,
      "strict": false
    }
  },
  "info": "dmarc=fail (p=REJECT) header.from=example.com"
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
    "header": {
      "from": "example.com",
      "d": "sub.example.com"
    },
    "comment": "p=NONE sp=QUARANTINE"
  },
  "domain": "example.com",
  "policy": "quarantine",
  "p": "none",
  "sp": "quarantine",
  "pct": 100,
  "rr": "v=DMARC1; p=none; sp=quarantine; rua=mailto:dmarc@example.com",
  "alignment": {
    "spf": {
      "result": "example.com",
      "strict": false
    },
    "dkim": {
      "result": false,
      "strict": false
    }
  },
  "info": "dmarc=pass (p=NONE sp=QUARANTINE) header.from=example.com"
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
