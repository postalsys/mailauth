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

## Options

| Option            | Type       | Default           | Description                                                                                                                |
| ----------------- | ---------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `sender`          | `string`   | `postmaster@helo` | MAIL FROM address. An empty value means a null reverse-path, so the HELO identity is checked                               |
| `ip`              | `string`   | Required          | SMTP client IP address. IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`, `::ffff:c000:201`) are checked as IPv4             |
| `helo`            | `string`   |                   | EHLO/HELO hostname                                                                                                         |
| `mta`             | `string`   | `os.hostname()`   | Hostname of the MTA performing the check                                                                                   |
| `resolver`        | `function` | `dns.resolve`     | Custom DNS resolver                                                                                                        |
| `maxResolveCount` | `number`   | `10`              | Maximum DNS lookups allowed                                                                                                |
| `maxVoidCount`    | `number`   | `2`               | Maximum void (empty) DNS lookups allowed. `0` is a valid limit, a value that is not a non-negative number uses the default |
| `maxElapsedTime`  | `number`   | No limit          | Maximum time in milliseconds for the whole evaluation. If exceeded, the result is `temperror` (RFC 7208 4.6.4)             |
| `strict`          | `boolean`  | `false`           | Follow RFC 7208 exactly instead of the lenient default, see [Strict Mode](#strict-mode)                                    |

A missing or invalid `ip` gives a `temperror` result with the comment `missing or invalid client IP address`.

## Result Object Fields

| Field           | Type     | Presence     | Description                                                 |
| --------------- | -------- | ------------ | ----------------------------------------------------------- |
| `domain`        | `string` | Always       | The domain extracted from the sender address for SPF lookup |
| `client-ip`     | `string` | Always       | The client IP address that was checked                      |
| `helo`          | `string` | If provided  | The EHLO/HELO hostname from the SMTP session                |
| `envelope-from` | `string` | If provided  | The MAIL FROM address                                       |
| `status`        | `object` | Always       | Verification status object (see below)                      |
| `header`        | `string` | Always       | Formatted Received-SPF header value                         |
| `info`          | `string` | Always       | Formatted Authentication-Results header value               |
| `rr`            | `string` | Record found | Raw SPF DNS TXT record                                      |
| `lookups`       | `object` | Always       | DNS lookup statistics (see below)                           |
| `explanation`   | `string` | Fail only    | Explanation string from the `exp` modifier (see below)      |
| `warnings`      | `array`  | Default mode | Leniencies that strict mode would have rejected (see below) |

## status Object

| Field     | Type     | Description                              |
| --------- | -------- | ---------------------------------------- |
| `result`  | `string` | SPF result code (see below)              |
| `comment` | `string` | Human-readable explanation of the result |
| `smtp`    | `object` | SMTP session identifiers                 |

### status.smtp Object

| Field      | Type     | Description            |
| ---------- | -------- | ---------------------- |
| `mailfrom` | `string` | The MAIL FROM address  |
| `helo`     | `string` | The HELO/EHLO hostname |

In strict mode `status.smtp` holds only the identity that was checked (RFC 8601 section 2.7.2): `mailfrom` for a MAIL FROM check, or `helo` for a null reverse-path. The `mailfrom` value is then only the domain, unless the evaluated policy uses the `%{l}` or `%{s}` macro.

## explanation

When the result is `fail` because of a mechanism match and the record has an `exp` modifier, the explanation string is fetched and expanded as described in RFC 7208 section 6.2. Any problem with it (DNS error, no or several TXT records, syntax error, text that is not printable US-ASCII before or after macro expansion) means that there is no explanation. The explanation lookup does not count toward the DNS lookup limits. The explanation of an included record is never used, and after a redirect only the explanation of the redirect target is used.

The explanation is text from the domain owner. It is not added to the generated headers. If you show it to an SMTP client, make clear that it comes from a third party, for example by prepending `"<domain> explains: "`.

## warnings

In the default mode some input is accepted that strict mode rejects. When that happens, the result gets a `warnings` array. It is never rendered into the headers. The values are:

| Warning                | Meaning                                                                                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `syntax-error`         | An evaluated record has a syntax error (for example after the matching term, a `c`, `r` or `t` macro outside of explanation text, or a duplicate `exp`), or leading space |
| `void-lookup-limit`    | The void lookup limit would have been exceeded if single-stack hosts were counted as void lookups, as RFC 7208 does                                                       |
| `non-ascii-local-part` | A `%{l}` or `%{s}` term was evaluated with a non-ASCII local-part (RFC 8616 section 4 says such terms do not match)                                                       |

`warnings` is not set for a `permerror` result.

## lookups Object

| Field        | Type     | Description                                           |
| ------------ | -------- | ----------------------------------------------------- |
| `limit`      | `number` | Maximum DNS lookups allowed (default: 10)             |
| `count`      | `number` | Number of DNS lookups performed                       |
| `void`       | `number` | Number of void (empty result) DNS lookups             |
| `subqueries` | `object` | Counts of DNS queries by type (e.g., `{A: 2, MX: 1}`) |

## Result Values

| Result      | SPF Qualifier | Description                                                |
| ----------- | ------------- | ---------------------------------------------------------- |
| `pass`      | `+`           | Sender is authorized                                       |
| `fail`      | `-`           | Sender is explicitly not authorized                        |
| `softfail`  | `~`           | Sender is probably not authorized (transitional)           |
| `neutral`   | `?`           | No policy assertion about the sender                       |
| `none`      | -             | No SPF record found or invalid domain                      |
| `permerror` | -             | Permanent error (invalid SPF record, too many DNS lookups) |
| `temperror` | -             | Temporary error (DNS timeout, server refused)              |

## Comment Format

The `status.comment` field follows this format based on the result:

| Result      | Comment Format                                                                          |
| ----------- | --------------------------------------------------------------------------------------- |
| `pass`      | `"{mta}: domain of {sender} designates {ip} as permitted sender"`                       |
| `fail`      | `"{mta}: domain of {sender} does not designate {ip} as permitted sender"`               |
| `softfail`  | `"{mta}: domain of transitioning {sender} does not designate {ip} as permitted sender"` |
| `neutral`   | `"{mta}: {ip} is neither permitted nor denied by domain of {sender}"`                   |
| `none`      | `"{mta}: {domain} does not designate permitted sender hosts"`                           |
| `permerror` | `"{mta}: permanent error in processing during lookup of {sender}: {text}"`              |
| `temperror` | `"{mta}: error in processing during lookup of {sender}: {text}"`                        |

## Received-SPF Header

The `header` field holds a `Received-SPF` header (RFC 7208 section 9.1) with the `client-ip`, `envelope-from` and `helo` keys. `envelope-from` is omitted for a null reverse-path, and `client-ip` if no valid IP was given. Values that are not a dot-atom, such as IPv6 addresses and email addresses, are quoted.

## Strict Mode

By default the SPF check is lenient where the leniency does not change which domain is authenticated. With `strict: true` it follows RFC 7208 exactly:

- The whole record is validated before evaluation (RFC 7208 section 4.6). A syntax error anywhere in the record gives `permerror`, even after the matching term. By default records are evaluated lazily, so an error after the matching term is not noticed.
- The `c`, `r` and `t` macros are only allowed in explanation text, a macro number must be nonzero, and transformers must follow the ABNF (`%{d0}`, `%{d2x}` and `%{dr2}` are errors).
- `exp` may appear only once, and modifier names must follow the `name` rule.
- `ip4` and `ip6` networks and prefix lengths are checked against the ABNF (`ip4:2001:db8::1`, `ip6:192.0.2.1`, `ip6:2001:db8::/32//64` and `ip4:192.0.2.0/00` are errors).
- A record must start with exactly `v=spf1` followed by a space or the end of the record. Records with leading whitespace are ignored.
- A void lookup is counted for the query of the client's address type alone. By default an `a` or `mx` host that has only addresses of the other type is not counted as void.
- A term that uses `%{l}` or `%{s}` does not match if the local-part is not ASCII (RFC 8616 section 4).
- A target name that is not a valid domain name after macro expansion makes the `a`, `mx`, `exists` or `ptr` mechanism not match. By default it is a `permerror`. For `include` and `redirect` it is a `permerror` in both modes.
- Authentication-Results reports only the checked identity, see [status.smtp Object](#statussmtp-object).

These rules apply in both modes:

- A DNS error (other than NXDOMAIN or an empty answer) in any lookup, including the targets of `include` and `redirect`, gives `temperror`.
- Every `ptr` mechanism and every `%{p}` expansion counts toward the DNS lookup limit. A DNS error in the PTR lookup makes the `ptr` mechanism not match.
- `%{p}` expands to a validated PTR name or `unknown`.
- Trailing dots in domain-specs are accepted, names longer than 253 characters are truncated from the left, and uppercase macros are URL escaped.
- An internationalized MAIL FROM domain is converted to A-labels.
- A single trailing dot is removed from the MAIL FROM domain and the HELO name (RFC 7208 section 4.3). A zero-length label anywhere else gives `none`.
- Address lookups of MX hosts are not counted as void lookups. The PTR lookup of a `%{p}` expansion is not counted as a void lookup either, the query of the term itself decides if the term was void.

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
    "header": "Received-SPF: pass (mx.receiver.com: domain of user@example.com designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1;\r\n envelope-from=\"user@example.com\"; helo=mail.example.com;",
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
    "header": "Received-SPF: fail (mx.receiver.com: domain of user@example.com does not designate 203.0.113.1 as permitted sender) client-ip=203.0.113.1;\r\n envelope-from=\"user@example.com\"; helo=attacker.example.net;",
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
    "header": "Received-SPF: none (mx.receiver.com: no-spf.example.com does not designate permitted sender hosts) client-ip=192.0.2.1;\r\n envelope-from=\"user@no-spf.example.com\"; helo=mail.no-spf.example.com;",
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
    "header": "Received-SPF: permerror (mx.receiver.com: permanent error in processing during lookup of user@complex.example.com: Too many DNS requests) client-ip=192.0.2.1;\r\n envelope-from=\"user@complex.example.com\";",
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
