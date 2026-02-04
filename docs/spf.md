# SPF Verification Result Reference

This document describes the result object returned by the `spf()` function.

## Overview

The `spf` function verifies the SPF (Sender Policy Framework) record for an email sender and returns an object containing the verification result.

```javascript
const { spf } = require('mailauth/lib/spf');

const result = await spf({
    sender: 'user@example.com',
    ip: '192.0.2.1',
    helo: 'mail.example.com',
    mta: 'mx.receiver.com'
});
```

## Result Object Fields

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `domain` | `string` | Always | The domain extracted from the sender address for SPF lookup |
| `client-ip` | `string` | Always | The client IP address that was checked |
| `helo` | `string` | If provided | The EHLO/HELO hostname from the SMTP session |
| `envelope-from` | `string` | If provided | The MAIL FROM address |
| `status` | `object` | Always | Verification status object (see below) |
| `header` | `string` | Always | Formatted Received-SPF header value |
| `info` | `string` | Always | Formatted Authentication-Results header value |
| `rr` | `string` | Record found | Raw SPF DNS TXT record |
| `lookups` | `object` | Always | DNS lookup statistics (see below) |

## status Object

| Field | Type | Description |
|-------|------|-------------|
| `result` | `string` | SPF result code (see below) |
| `comment` | `string` | Human-readable explanation of the result |
| `smtp` | `object` | SMTP session identifiers |

### status.smtp Object

| Field | Type | Description |
|-------|------|-------------|
| `mailfrom` | `string` | The MAIL FROM address |
| `helo` | `string` | The HELO/EHLO hostname |

## lookups Object

| Field | Type | Description |
|-------|------|-------------|
| `limit` | `number` | Maximum DNS lookups allowed (default: 10) |
| `count` | `number` | Number of DNS lookups performed |
| `void` | `number` | Number of void (empty result) DNS lookups |
| `subqueries` | `object` | Counts of DNS queries by type (e.g., `{A: 2, MX: 1}`) |

## Result Values

| Result | SPF Qualifier | Description |
|--------|---------------|-------------|
| `pass` | `+` | Sender is authorized |
| `fail` | `-` | Sender is explicitly not authorized |
| `softfail` | `~` | Sender is probably not authorized (transitional) |
| `neutral` | `?` | No policy assertion about the sender |
| `none` | - | No SPF record found or invalid domain |
| `permerror` | - | Permanent error (invalid SPF record, too many DNS lookups) |
| `temperror` | - | Temporary error (DNS timeout, server refused) |

## Comment Format

The `status.comment` field follows this format based on the result:

| Result | Comment Format |
|--------|----------------|
| `pass` | `"{mta}: domain of {sender} designates {ip} as permitted sender"` |
| `fail` | `"{mta}: domain of {sender} does not designate {ip} as permitted sender"` |
| `softfail` | `"{mta}: domain of transitioning {sender} does not designate {ip} as permitted sender"` |
| `neutral` | `"{mta}: {ip} is neither permitted nor denied by domain of {sender}"` |
| `none` | `"{mta}: {domain} does not designate permitted sender hosts"` |
| `permerror` | `"{mta}: permanent error in processing during lookup of {sender}: {text}"` |
| `temperror` | `"{mta}: error in processing during lookup of {sender}: {text}"` |

## Example Output

### SPF Pass

```json
{
  "domain": "example.com",
  "client-ip": "192.0.2.1",
  "helo": "mail.example.com",
  "envelope-from": "user@example.com",
  "status": {
    "result": "pass",
    "comment": "mx.receiver.com: domain of user@example.com designates 192.0.2.1 as permitted sender",
    "smtp": {
      "mailfrom": "user@example.com",
      "helo": "mail.example.com"
    }
  },
  "header": "Received-SPF: pass (mx.receiver.com: domain of user@example.com designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1;",
  "info": "spf=pass (mx.receiver.com: domain of user@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=user@example.com smtp.helo=mail.example.com",
  "rr": "v=spf1 ip4:192.0.2.0/24 -all",
  "lookups": {
    "limit": 10,
    "count": 1,
    "void": 0,
    "subqueries": {}
  }
}
```

### SPF Fail

```json
{
  "domain": "example.com",
  "client-ip": "203.0.113.1",
  "helo": "attacker.example.net",
  "envelope-from": "user@example.com",
  "status": {
    "result": "fail",
    "comment": "mx.receiver.com: domain of user@example.com does not designate 203.0.113.1 as permitted sender",
    "smtp": {
      "mailfrom": "user@example.com",
      "helo": "attacker.example.net"
    }
  },
  "header": "Received-SPF: fail (mx.receiver.com: domain of user@example.com does not designate 203.0.113.1 as permitted sender) client-ip=203.0.113.1;",
  "info": "spf=fail (mx.receiver.com: domain of user@example.com does not designate 203.0.113.1 as permitted sender) smtp.mailfrom=user@example.com smtp.helo=attacker.example.net",
  "rr": "v=spf1 ip4:192.0.2.0/24 -all",
  "lookups": {
    "limit": 10,
    "count": 1,
    "void": 0,
    "subqueries": {}
  }
}
```

### SPF None (No Record)

```json
{
  "domain": "no-spf.example.com",
  "client-ip": "192.0.2.1",
  "helo": "mail.no-spf.example.com",
  "envelope-from": "user@no-spf.example.com",
  "status": {
    "result": "none",
    "comment": "mx.receiver.com: no-spf.example.com does not designate permitted sender hosts",
    "smtp": {
      "mailfrom": "user@no-spf.example.com",
      "helo": "mail.no-spf.example.com"
    }
  },
  "header": "Received-SPF: none (mx.receiver.com: no-spf.example.com does not designate permitted sender hosts) client-ip=192.0.2.1;",
  "info": "spf=none (mx.receiver.com: no-spf.example.com does not designate permitted sender hosts) smtp.mailfrom=user@no-spf.example.com smtp.helo=mail.no-spf.example.com",
  "lookups": {
    "limit": 10,
    "count": 1,
    "void": 1,
    "subqueries": {}
  }
}
```

### SPF Permerror (Too Many Lookups)

```json
{
  "domain": "complex.example.com",
  "client-ip": "192.0.2.1",
  "envelope-from": "user@complex.example.com",
  "status": {
    "result": "permerror",
    "comment": "mx.receiver.com: permanent error in processing during lookup of user@complex.example.com: Too many DNS requests",
    "smtp": {
      "mailfrom": "user@complex.example.com"
    }
  },
  "header": "Received-SPF: permerror (mx.receiver.com: permanent error in processing during lookup of user@complex.example.com: Too many DNS requests) client-ip=192.0.2.1;",
  "info": "spf=permerror (mx.receiver.com: permanent error in processing during lookup of user@complex.example.com: Too many DNS requests) smtp.mailfrom=user@complex.example.com",
  "lookups": {
    "limit": 10,
    "count": 11,
    "void": 0,
    "subqueries": {
      "include": 5,
      "a": 3,
      "mx": 2
    }
  }
}
```
