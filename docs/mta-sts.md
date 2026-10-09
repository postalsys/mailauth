# MTA-STS Result Reference

This document describes the result objects returned by MTA-STS (Mail Transfer Agent Strict Transport Security) functions.

## Overview

MTA-STS allows domain owners to declare that their mail servers support TLS and specify policies for message delivery. mailauth provides functions to fetch, parse, and validate MTA-STS policies.

```javascript
const { getPolicy, validateMx } = require('mailauth/lib/mta-sts');
```

## Options

`getPolicy`, `fetchPolicy` and `resolvePolicy` accept an options object as their last argument. `parsePolicy` and `validateMx` accept `{ strict }`.

| Option          | Type       | Default                | Description                                                                                |
| --------------- | ---------- | ---------------------- | ------------------------------------------------------------------------------------------ |
| `resolver`      | `function` | `dns.promises.resolve` | Async DNS resolver with the `dns.promises.resolve` signature                               |
| `strict`        | `boolean`  | `false`                | Apply the RFC 8461 rules exactly, see [Strict Mode](#strict-mode)                          |
| `timeout`       | `number`   | `60000`                | Overall time limit for the HTTPS policy request in milliseconds (the idle timeout is 15 s) |
| `maxPolicySize` | `number`   | `65536`                | Maximum policy file size in bytes, larger responses fail with the `policy_too_large` error |

## getPolicy Result

The `getPolicy` function fetches and returns the MTA-STS policy for a domain. The domain may also be given as an email address.

```javascript
const { policy, status, warnings } = await getPolicy('example.com', knownPolicy, { strict: false });
```

### Result Object Fields

| Field      | Type       | Description                                                                                       |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------- |
| `policy`   | `object`   | The MTA-STS policy object to apply and to store in your cache (see below)                         |
| `status`   | `string`   | Policy retrieval status (see below)                                                               |
| `warnings` | `string[]` | Only present when lax mode accepted something strict mode would reject, see [Warnings](#warnings) |

### Status Values

| Status      | Description                                                                                                                                                                          |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `found`     | A new or updated policy was fetched successfully                                                                                                                                     |
| `not_found` | No MTA-STS policy exists for the domain, and there is no valid cached policy                                                                                                         |
| `renewed`   | The cached policy has the same ID as the DNS record and has not expired. It is returned unchanged, without fetching the policy file                                                  |
| `errored`   | No live policy could be discovered or fetched. `policy.error` holds the reason. `policy` is the valid cached policy if there is one, otherwise a policy with mode `none` (see below) |

### Policy Object Fields

| Field        | Type            | Presence         | Description                                                               |
| ------------ | --------------- | ---------------- | ------------------------------------------------------------------------- |
| `id`         | `string\|false` | Always           | Policy ID from DNS TXT record, or `false` if not found                    |
| `version`    | `string`        | Policy found     | Always `"STSv1"` for valid policies                                       |
| `mode`       | `string`        | Always           | Policy mode (see below)                                                   |
| `mx`         | `string[]`      | Listed in policy | Array of allowed MX hostnames (may include wildcards)                     |
| `maxAge`     | `number`        | Policy found     | Policy validity period in seconds                                         |
| `expires`    | `string`        | Policy found     | ISO 8601 expiration timestamp                                             |
| `error`      | `Error`         | Status errored   | Error object explaining why no live policy could be discovered or fetched |
| `retryId`    | `string`        | Fetch failed     | New policy ID that could not be fetched while the cached policy is kept   |
| `retryAfter` | `string`        | Fetch failed     | ISO 8601 timestamp before which `retryId` is not fetched again            |

### Mode Values

| Mode      | Description                                                 |
| --------- | ----------------------------------------------------------- |
| `testing` | Policy is in test mode; report violations but don't enforce |
| `enforce` | Strictly enforce TLS and MX restrictions                    |
| `none`    | No policy in effect                                         |

## Caching

Pass the `policy` value of the previous result as `knownPolicy`, and store the `policy` value of every result, whatever the status. `getPolicy` implements the RFC 8461 3.3 and 5.1 cache rules itself:

```javascript
const knownPolicy = await cache.get(domain); // undefined if not cached
const { policy } = await getPolicy(domain, knownPolicy);
await cache.set(domain, policy); // keep the entry at least until policy.expires
```

- **Valid cached policy, same ID in DNS:** the cached policy is returned as `renewed` without an HTTPS request. Its `expires` value is not extended, so the policy file is fetched again once it expires.
- **Valid cached policy, no live policy:** if the TXT lookup fails, the TXT record is missing, unusable or duplicated, the policy host has no address, or the new policy can not be fetched or is invalid, the cached policy is returned with `status: "errored"` and the reason in `policy.error`. A valid cached policy is never replaced by `mode: "none"` because of a discovery failure. An exception is a cached policy that already has mode `none`, which may be replaced by the retry placeholder described below.
- **Expired cached policy:** the policy file is fetched again. If the fetch fails, the default lax mode keeps returning the expired `enforce` or `testing` policy (with the `expired-cache` warning), while strict mode treats the domain as having no policy.
- **Cached policy kept after a failed fetch:** when the policy for a new ID can not be fetched and the cached policy is returned instead, it gets `retryId` (the new ID) and `retryAfter` (one hour ahead). Storing it makes the next calls return it as `errored` without HTTPS requests while the DNS record has the same ID, so the policy host is not retried for an hour (RFC 8461 3.3). A different policy ID is fetched right away, and the fields are dropped once a policy is fetched.
- **No usable cached policy and the fetch fails:** the result is a placeholder with the new policy ID, mode `none`, and `expires` set one hour ahead. Storing it makes the next calls return it as `renewed` without HTTPS requests, so the policy host is not retried for an hour. A changed policy ID is fetched right away.

## Strict Mode

With `strict: true` the RFC 8461 rules are applied exactly. The default lax mode accepts the following, and reports each acceptance in the `warnings` array of the `getPolicy` result:

| Rule                                                                                                                                 | Warning         |
| ------------------------------------------------------------------------------------------------------------------------------------ | --------------- |
| The TXT record must match the RFC 8461 3.1 syntax: case-sensitive `v=STSv1` at the start, `id` of 1 to 32 letters and digits         | `txt-syntax`    |
| Only HTTP status 200 is accepted (lax accepts any 2xx)                                                                               | `http-status`   |
| The policy must be served with the `text/plain` media type                                                                           | `content-type`  |
| Policy field names and the `mode` value are case-sensitive, `max_age` is 1 to 10 digits, `mx` values are `["*."] Domain`             | `policy-syntax` |
| The Policy Host certificate must match through a DNS-ID subjectAltName, with no CN fallback and no partial-label wildcards (`mta-*`) | `cert-identity` |
| An expired cached policy is not applied when the policy can not be fetched                                                           | `expired-cache` |

A strict TXT record syntax error makes the record unusable, so it is handled like a missing record. The other strict failures are fetch errors, so a valid cached policy is kept.

These rules apply in both modes:

- Only records that begin with `v=STSv1;` are counted when checking for multiple TXT records. Two or more remaining records fail with `multi_sts_records`.
- If a TXT or policy field other than `mx` is repeated, the first value is used.
- TXT extension fields may contain any value allowed by RFC 8461, including `:`, `(` and quotes.
- A policy without a `mode` field is invalid.
- Redirects are not followed, and only 2xx responses (200 in strict mode) are accepted.
- The policy file size is limited by `maxPolicySize` and the whole request by `timeout`.
- Internationalized domain names are converted to A-labels for DNS queries, TLS SNI, the Host header and MX matching.

## Warnings

| Warning         | Meaning                                                                       |
| --------------- | ----------------------------------------------------------------------------- |
| `txt-syntax`    | The TXT record does not match the RFC 8461 3.1 syntax                         |
| `http-status`   | The policy was served with a 2xx status other than 200                        |
| `content-type`  | The policy was not served as `text/plain`                                     |
| `policy-syntax` | The policy file does not match the RFC 8461 3.2 syntax                        |
| `cert-identity` | The Policy Host certificate matched only through the CN or a partial wildcard |
| `expired-cache` | An expired cached policy was returned because the policy could not be fetched |

## validateMx Result

The `validateMx` function checks if an MX hostname is valid according to the MTA-STS policy.

```javascript
const result = validateMx('alt1.mx.example.com', policy);
```

MX names are matched case-insensitively, a trailing dot is ignored, and U-label names are converted to A-labels. A wildcard pattern such as `*.example.com` matches exactly one complete left-most label: `mail.example.com` matches, but `example.com` and `foo.bar.example.com` do not. An `enforce` or `testing` policy without an `mx` list matches nothing. `validateMx` does not look at `policy.expires`; use `getPolicy` to refresh the policy.

### Result Object Fields

| Field     | Type      | Presence    | Description                                                                           |
| --------- | --------- | ----------- | ------------------------------------------------------------------------------------- |
| `valid`   | `boolean` | Always      | Whether the MX hostname is allowed                                                    |
| `mode`    | `string`  | Always      | Policy mode (`"testing"`, `"enforce"`, or `"none"`)                                   |
| `match`   | `string`  | Valid match | The matching hostname, or for a wildcard the suffix without `*` (e.g. `.example.com`) |
| `testing` | `boolean` | Always      | Whether policy is in testing mode                                                     |

## Example Output

### Policy Found

```json
{
    "policy": {
        "id": "20240115T120000",
        "version": "STSv1",
        "mode": "enforce",
        "mx": ["mx1.example.com", "mx2.example.com", "*.mail.example.com"],
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

### Policy Renewed

The cached policy is returned unchanged.

```json
{
    "policy": {
        "id": "20240115T120000",
        "version": "STSv1",
        "mode": "enforce",
        "mx": ["mx1.example.com", "mx2.example.com"],
        "maxAge": 86400,
        "expires": "2024-01-16T12:00:00.000Z"
    },
    "status": "renewed"
}
```

### Policy Error Without a Cached Policy

The policy ID is kept, and `expires` is one hour ahead, so the policy host is not retried before that.

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

### Policy Error With a Valid Cached Policy

```json
{
    "policy": {
        "id": "20240115T120000",
        "version": "STSv1",
        "mode": "enforce",
        "mx": ["mx1.example.com", "mx2.example.com"],
        "maxAge": 86400,
        "expires": "2024-01-16T12:00:00.000Z",
        "error": {
            "message": "No usable MTA-STS TXT record found for example.com",
            "code": "sts_record_not_found"
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

| Code                           | Description                                                                                                    |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| `multi_sts_records`            | More than one TXT record beginning with `v=STSv1;` found for `_mta-sts.{domain}`                               |
| `sts_record_not_found`         | No MTA-STS TXT record (only reported when a valid cached policy is returned)                                   |
| `invalid_sts_record`           | The TXT record has no usable `id`, or a syntax error in strict mode (only reported with a valid cached policy) |
| `policy_host_not_found`        | `mta-sts.{domain}` has no A or AAAA record (only reported with a valid cached policy)                          |
| `invalid_sts_version`          | Policy file has invalid or missing version field                                                               |
| `invalid_sts_mode`             | Policy file has invalid or missing mode field                                                                  |
| `invalid_sts_max_age`          | Policy file has invalid max_age value                                                                          |
| `invalid_sts_mx`               | Policy file missing mx field in enforce/testing mode, or invalid mx value (strict)                             |
| `invalid_content_type`         | Policy was not served as `text/plain` (strict mode only)                                                       |
| `policy_too_large`             | Policy file is larger than `maxPolicySize`                                                                     |
| `HTTP_SOCKET_TIMEOUT`          | The HTTPS connection was idle for too long                                                                     |
| `HTTP_REQUEST_TIMEOUT`         | The HTTPS request took longer than `timeout`                                                                   |
| `http_incomplete_response`     | The HTTPS response ended before the complete body was received                                                 |
| `http_status_{code}`           | HTTP request returned a non-2xx status (any status other than 200 in strict mode)                              |
| `ERR_TLS_CERT_ALTNAME_INVALID` | The Policy Host certificate is not valid for `mta-sts.{domain}`                                                |
| `ESERVFAIL`, `ETIMEOUT`, ...   | DNS lookup failed                                                                                              |

## Usage Example

```javascript
const { getPolicy, validateMx } = require('mailauth/lib/mta-sts');

// Fetch policy, using and updating the cached policy
const knownPolicy = await cache.get('gmail.com');
const { policy, status } = await getPolicy('gmail.com', knownPolicy);
await cache.set('gmail.com', policy);

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
