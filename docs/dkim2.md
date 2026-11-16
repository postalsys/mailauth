# DKIM2 Result Reference

This document describes the result object returned by `dkim2Verify()` and how mailauth reads the parts of the DKIM2 drafts that are open to interpretation.

> [!WARNING]
> DKIM2 support is experimental. It is built against these Internet-Drafts, which are not finished and can change:
>
> - [draft-ietf-dkim-dkim2-spec-09](https://www.ietf.org/archive/id/draft-ietf-dkim-dkim2-spec-09.txt) (1 November 2026), the protocol
> - [draft-ietf-dkim-dkim2-dns-02](https://www.ietf.org/archive/id/draft-ietf-dkim-dkim2-dns-02.txt) (21 October 2026), the key records
> - [draft-ietf-dkim-dkim2-bcp-01](https://www.ietf.org/archive/id/draft-ietf-dkim-dkim2-bcp-01.txt) (9 September 2026), best practices
> - [draft-gondwana-dkim2-authres-01](https://datatracker.ietf.org/doc/html/draft-gondwana-dkim2-authres-01) (28 October 2026, not adopted by the working group), the `dkim2` Authentication-Results method
>
> Section numbers below refer to draft-ietf-dkim-dkim2-spec-09 unless noted otherwise.

## Overview

```javascript
const { dkim2Verify } = require('mailauth');

const result = await dkim2Verify(message, {
    mailFrom: 'bounce@list.example.org',
    rcptTo: ['member@example.net']
});
```

The whole message gets one result (section 14.1):

| Result      | Meaning                                                                                                                                  |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `pass`      | The message is a Fully Verified DKIM2 Message: every instance, signature, chain of custody and From check passed                         |
| `fail`      | A hash or signature is not correct, a timestamp is out of range, the chain of custody is broken, or a From header field is not Authentic |
| `permerror` | The message could not be verified: malformed or missing header fields, an unknown algorithm, a missing or broken key, a null Recipe      |
| `temperror` | A DNS record (a public key or a Domain Policy Record) could not be fetched because of a temporary DNS failure                            |
| `none`      | The message has no DKIM2 header fields                                                                                                   |

When there are several problems, `fail` wins over `permerror`, and `permerror` over `temperror`, the rule of section 14.6 step 6 for checks that all have to pass: a TEMPERROR is only reported when every check that did not pass had a TEMPERROR, so that a failure is never reported as temporary.

## Top-Level Result Object

| Field        | Type       | Description                                                                                      |
| ------------ | ---------- | ------------------------------------------------------------------------------------------------ |
| `status`     | `object`   | `{ result, comment, header }`, see below                                                         |
| `info`       | `string`   | Authentication-Results resinfo, such as `dkim2=pass (i=1 example.com pass) header.d=example.com` |
| `errors`     | `object[]` | Every problem found, in the order the checks ran: `{ result, message, i, m }`                    |
| `instances`  | `object[]` | One entry per `Message-Instance`, see below                                                      |
| `signatures` | `object[]` | One entry per `DKIM2-Signature`, see below                                                       |
| `replay`     | `object`   | `{ key, exploded, intermediary, duplicate }`, see [Replay](#replay)                              |

### status

| Field      | Type       | Description                                                                                                                                                                                    |
| ---------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `result`   | `string`   | One of the results above                                                                                                                                                                       |
| `comment`  | `string`   | The human-readable string of the reported problem, as specified in section 14, such as `DKIM2-Signature i=1 selector rsa incorrect signature`. For `none` it is `No DKIM2 header fields found` |
| `header.d` | `string`   | `d=` of the `i=1` signature, the originator (draft-gondwana-dkim2-authres-01 section 3.2.1)                                                                                                    |
| `header.i` | `number`   | `i=` of the signature the problem is reported against. Not set for `pass`, or for a problem of the whole message                                                                               |
| `warnings` | `string[]` | `mail-from-not-checked` and/or `rcpt-to-not-checked` when that part of the SMTP envelope was not given, see [Envelope Warnings](#envelope-warnings)                                            |

`header.d` is an authenticated identity only when the result is `pass`. The `info` of a `none` result is a plain `dkim2=none` (draft-gondwana-dkim2-authres-01 section 3.1).

### Envelope Warnings

The chain of custody is what stops DKIM2 replay: the highest `DKIM2-Signature` names the MAIL FROM and RCPT TO the message was delivered with (section 14.4). A library does not see the SMTP transaction, so this check only runs for the parts of the envelope you pass as `mailFrom` and `rcptTo`. When one is missing, `status.warnings` says so:

- `mail-from-not-checked`: `mailFrom` was not given (`""` counts as given, it is the null sender)
- `rcpt-to-not-checked`: `rcptTo` was not given

Without them an unchanged copy of the message, sent to anyone, passes as well. The warnings do not change the result and are never written into `info`, in the same way as the DKIM1 warnings. `authenticate()` passes its `sender` and `rcptTo` options on, so set `rcptTo` there to have the recipients checked.

### instances

| Field    | Type       | Description                                                                                                                                                                                                                       |
| -------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `m`      | `number`   | Revision number                                                                                                                                                                                                                   |
| `hashes` | `object[]` | `{ algorithm, header, body, group }` for every hash-set with a known algorithm. `group` is the position of its `\|` group, from 1. `body` is `unknown` when a later hop declared that the body can not be recreated (`"b": null`) |
| `recipe` | `object`   | When the instance has a Recipe: `{ headers, body }`, the header field names it recreates, and `unchanged`, `recipe` or `unrecoverable` for the body                                                                               |

### signatures

| Field           | Type       | Description                                                                  |
| --------------- | ---------- | ---------------------------------------------------------------------------- |
| `i`             | `number`   | Sequence number                                                              |
| `m`             | `number`   | Highest `Message-Instance` covered                                           |
| `signingDomain` | `string`   | `d=`                                                                         |
| `timestamp`     | `number`   | `t=`, seconds since the epoch, and `signTime` as an ISO 8601 string          |
| `mailFrom`      | `string`   | Decoded `mf=`, with angle brackets                                           |
| `rcptTo`        | `string[]` | Decoded `rt=`                                                                |
| `nextDomain`    | `string`   | `nd=`                                                                        |
| `nonce`         | `string`   | `n=`                                                                         |
| `flags`         | `string[]` | `f=`, including flags mailauth does not know                                 |
| `status`        | `object`   | `{ result, comment }` for this hop, including the errors reported against it |
| `values`        | `object[]` | One entry per signature value in `s=`, see below                             |

Each entry of `values` has `selector`, `algorithm`, `group` (the position of its `|` group, from 1), `result` (the intermediate result of section 14.6: `pass`, `fail`, `permerror` or `temperror`), and when available `comment`, `rr` (the key record) and `modulusLength`. An algorithm mailauth does not implement is a `permerror` with the comment `selector <s1> algorithm unknown`.

### Replay

`replay` describes the message for DKIM Replay detection (section 15.1):

- `key`: the `m=1` hashes, `algorithm:headerHash:bodyHash` of the first hash-set with a known algorithm. Copies of one message have the same key
- `exploded`: a signature has the `exploded` flag, so the hop that set it said it sent several copies
- `intermediary`: the message has more than one `DKIM2-Signature`, so it passed through an intermediary
- `duplicate`: only when `checkReplay` is given, what it returned

A duplicate that came through an intermediary without an `exploded` flag is what section 15.1 calls suspicious. The draft leaves the decision to the receiver and defines no result or error string for it, so it does not change the result.

## What Is Checked

1. **Syntax and numbering (section 14.2).** Every `Message-Instance` and `DKIM2-Signature` is parsed. `m=` and `i=` start at 1 with no gaps or duplicates, no instance is above the highest `m=` of a signature, `m=` never goes down from one signature to the next (section 10.2), the highest signature covers the highest instance (section 13.2), no hash algorithm or selector repeats, the `mf=` and `rt=` paths have no SMTP parameters (sections 10.5 and 10.6), and the first signature has no `exploded` flag.
2. **Recipes (sections 5 and 14.2).** Starting from the message as it is, the Recipe of every instance is applied to recreate the one before it. A null body Recipe (`"b": null`) is a PERMERROR, `Message-Instance m=<x> has a null recipe`: the body hashes below it can not be checked. The header hashes below it still are.
3. **Hashes (section 14.7).** The header and body hashes of every instance are compared with the recreated message. The hash-sets of a `,` group all have to pass, and one `|` group has to pass. An unknown hash algorithm is a PERMERROR for its hash-set.
4. **Timestamps (section 14.3).** A signature older than `maxSignatureAge` (14 days), or more than `maxFutureTime` (one day) in the future, is a FAIL.
5. **Chain of custody (sections 7.1, 10.7, 10.8 and 14.4).** `d=` matches the `mf=` domain of every signature, the signature after one with `nd=` has exactly that `d=`, every other hop matches a RCPT TO of the hop before it, the highest signature has no `nd=`, and, for the parts of the envelope given as `mailFrom` and `rcptTo`, the highest signature matches the delivery. These are FAILs.
6. **Signatures (sections 12.8, 14.5 and 14.6).** Every signature value is checked with its key. The signatures of a `,` group all have to pass, one `|` group has to pass.
7. **Authentic From (sections 11 and 14.8).** The From header field of the first instance, and every From a later Recipe shows was changed, matches the signing domain of the lowest signature that covers the instance where it appeared. A FAIL otherwise.

## How the Drafts Are Read

The drafts leave some questions open. mailauth answers them like this:

- **Tag names and algorithm names are case-sensitive** (sections 2.14 and 8). `M=1` is an unknown tag, which is ignored, and not the `m=` tag. `RSA-SHA256` is an unknown algorithm. Selectors are DNS names and are compared without case.
- **Whitespace in values.** FWS is allowed inside a base64string, but not in front of its first character or after its last one (section 2.14), and the ABNF of `h=`, `s=` and `rt=` allows FWS around `,` and `|` only where it says so: never next to the `:` in front of a hash or signature value, and never around the `,` of `rt=`. Anything else is a syntax error. The signer folds long values only inside base64strings and between tags.
- **Groups (sections 9.3, 10.9, 14.6 and 14.7).** Within a `,` group: all PASS is a PASS; when every result that is not a PASS is a TEMPERROR, a TEMPERROR; any FAIL is a FAIL; otherwise a PERMERROR. Between `|` groups: any PASS, then any TEMPERROR, then any FAIL, otherwise PERMERROR. With one group the reported string is the one of the signature or hash-set that decided it; with several groups a FAIL is `no group of signatures passed` or `Message-Instance m=<x> no group of hashes passed`. A duplicate hash algorithm or selector is an error in any group.
- **Chain of custody between hops** (section 7.1 item 1). A non-null `mf=` domain has to be a RCPT TO domain of the previous hop or a subdomain of it. With the null `mf=`, or with `nd=`, a RCPT TO domain of the previous hop has to be the `d=` domain or a subdomain of it. The errors are `mf= does not match the rt= of i=<y>` and `d= does not match the rt= of i=<y>`. A domain literal never matches.
- **A highest signature with `nd=`** is `DKIM2-Signature i=<x> unexpected nd= tag`, a FAIL, with or without the envelope: sections 12.3 and 13.2 only accept such a message on out-of-band arrangements, and the receiving system then adds the signature that completes the chain itself.
- **The relevant signature of a From** (section 11). For the From of the first instance and for every instance whose From differs from the one before it (compared in the canonical form of section 6.2), the lowest signature whose `m=` is at least that instance. A Recipe that names `from` without changing it does not add a check.
- **From header fields that can never be Authentic.** More than one address, in one field, in a group, or in several From header fields: `From has more than one address`. A domain literal: `From uses a domain literal`. No From header field, an empty group, or a From that is not RFC 5322 syntax: `matching From is not authentic`. The address is read with the same parser as the DMARC Author Domain, and its domain is compared as a lower case A-label (section 18).
- **Domain Policy Records** (section 3.8). The record of the From domain is only looked up when the signing domain is a subdomain of it (the reversed match of section 7.1 item 3). Only TXT records that begin with `v=DKIM1` count. No record, or NXDOMAIN, means subdomains may sign. The `strict` flag of `f=` is case-sensitive, unknown flags are ignored. Two records are `multiple records for <domain> policy`, a temporary DNS failure is `policy for <domain> unavailable`, and a record that begins with `v=DKIM1` but is not a valid tag-list is a PERMERROR, `policy for <domain> has a syntax error`, instead of being read as one that authorizes subdomains.
- **Recipe errors.** Text that is not JSON, not UTF-8, not a JSON object, or that has a key twice in one object, is `Message-Instance m=<x> contains invalid JSON`. Anything else that breaks section 5 is `Message-Instance m=<x> recipe <value> is invalid`, with the invalid part of the Recipe (up to 100 characters) as the value: a key that is not in lower case, a step with more or other keys than one of `c`, `d` and `u`, a `c` range that is out of order or goes past the last line or header field, a `d` string with CR or LF or a lone surrogate, a `u` string that is not canonical base64 or decodes to CR or LF, and a Recipe for a header field that is not signed (section 5.1). Unknown keys at the top level are ignored, as the schema allows them.
- **RSA key size.** Verifiers have to handle 1024 to 4096 bits and may handle more (section 3.2). mailauth accepts 1024 to 8192 bits: a shorter key is `public key <s1> too short`, a longer one `public key <s1> is too long`.
- **Key records.** Records that begin with a `v=` other than `DKIM1` are dropped first (section 3.7), more than one remaining record is `has multiple records`. The rest is read with the tag-list rules of draft-ietf-dkim-dkim2-dns-02: tag names are case-sensitive, `v=`, when present, is exactly `DKIM1` and the first tag, and duplicate tags and other syntax errors make the record unusable. `k=` has to match the algorithm (`rsa` for `rsa-sha256`, `ed25519` for `ed25519-sha256`, `mldsa44` for `mldsa44`). The retired `h=`, `n=`, `s=` and `t=` tags are ignored. Ed25519 keys are the bare 32 byte key (RFC 8463), ML-DSA-44 keys the bare 1312 byte key, and a key of another length, or key data that can not be read, is `public key <s1> is malformed`. RSA keys need the public exponent 65537 (section 3.2). draft-ietf-dkim-dkim2-dns-02 still describes a composite `mldsa44-ed25519-sha512` key type, which spec-09 replaced with `mldsa44`, so it is an unknown key type.
- **ML-DSA-44** (section 3.4) is pure ML-DSA with the context string `DKIM2`, signed with the hedged variant. It needs Node.js 24 or later. Section 3 says verifiers MUST implement all algorithms, which mailauth can not do on Node.js 20 and 22: there `mldsa44` is an unknown algorithm, a PERMERROR for its signature, so a message that also offers RSA or Ed25519 in another `|` group still passes.
- **Leading whitespace in Recipe data.** The header hash removes the whitespace after the colon, so `{"d": [" value"]}` and `{"d": ["value"]}` recreate the same header field.
- **Large timestamps.** `t=` is any number of digits (section 10.4). A value too large to be read exactly is still far in the future and fails the timestamp check. When it is beyond what a JavaScript `Date` can hold, its `signTime` is an empty string.

### Error Strings Not in the Specification

Section 14 lists the human-readable strings to use. These cases have no string there, so mailauth adds its own:

- `Message has more than <n> Message-Instance or DKIM2-Signature header fields` (draft-ietf-dkim-dkim2-bcp-01 section 7.5)
- `DKIM2-Signature i=<x> public key <s1> is too long` and `... has an unsupported exponent`
- `DKIM2-Signature i=<x> policy for <domain> has a syntax error`
- `DKIM2-Signature i=<x> m= is below the m= of i=<y>`: `m=` is the highest instance when a signature is added (section 10.2), so it never goes down
- `Message-Instance m=<x> contains invalid JSON: <reason>` adds the reason for an object that is not a JSON object or has a duplicate key

## Interoperability

mailauth has been checked against three independent DKIM2 implementations. Where an implementation built for an earlier revision of the specification disagrees with draft-ietf-dkim-dkim2-spec-09, mailauth follows spec-09.

- **[croessner/dkim2](https://github.com/croessner/dkim2)** (draft-ietf-dkim-dkim2-spec-09 and draft-ietf-dkim-dkim2-dns-02, the same drafts as mailauth). Its public verification vectors, its ML-DSA-44 vector (a deterministic and a hedged signature with the `DKIM2` context) and its chain of custody cases are part of the test suite (`test/fixtures/dkim2-croessner`). The differences are choices outside the protocol:
    - a message with no DKIM2 header fields is `none` in mailauth (section 14.1 and draft-gondwana-dkim2-authres-01 section 3.1), a PERMERROR in croessner/dkim2, which also refuses messages with bare LF line endings
    - croessner/dkim2 does not query Domain Policy Records in its vector test, so its vector with a subdomain signing for its parent is `From not authentic` there and `From <domain> forbids subdomain signing` in mailauth when the parent publishes `f=strict`

- **[turscar/dkim2](https://forge.turscar.ie/Turscar/dkim2)** (draft-ietf-dkim-dkim2-spec-02). The 42 vectors of [turscar/dkim2tests](https://forge.turscar.ie/turscar/dkim2tests) give the expected result, the same section 12.8 canonical form, and the same Message-Instance hashes when mailauth signs the original messages, except where spec-09 changed the rules:
    - `algorithm_only_future` and `algorithm_with_future`: an unknown signature algorithm is a PERMERROR for its signature, and a `,` group needs every signature to pass
    - `tags_mixed_case` and the `d2_duplicate_*_tag` vectors: tag names are case-sensitive, so the upper case tags are unknown tags. `tags_mixed_case` lacks every required tag (PERMERROR), the duplicate tag vectors have one known tag and pass, except `d2_duplicate_s_tag`, whose `S=` is not emptied for the signature input (FAIL)
    - `domain_below_mailfrom`: a chain of custody error is a FAIL

    The vectors are part of the test suite (`test/fixtures/dkim2tests`). One vector, `flags_whitespace`, expects flags that its signed message does not have.

- **[stalwartlabs/mail-auth](https://github.com/stalwartlabs/mail-auth)** (draft-ietf-dkim-dkim2-spec-04). Messages signed by each implementation verify with the other: originators with Ed25519, and with RSA and Ed25519 together, flags, nonce and several recipients, the null reverse-path, forwarders with and without a Recipe, and hops with `nd=`. The messages signed by mail-auth are part of the test suite (`test/fixtures/dkim2-stalwart`). The differences:
    - spec-04 has no Authentic From rule. Eight of the messages have a From in another domain than the signing domain and FAIL with `matching From is not authentic`, every other check of them passes.
    - The interop vectors in the mail-auth corpus that were made by an implementation for an earlier draft encode `mf=` and `rt=` without angle brackets, which sections 10.5 and 10.6 require (mail-auth rejects them too, outside its tests), and sign `Received-SPF`, which section 4 leaves unsigned.

## Signing

`dkim2Sign()` follows section 12:

- **Verify before you sign a message that already has DKIM2 header fields.** Section 12 says such a message MUST NOT be signed unless it is a Fully Verified DKIM2 Message, or an out-of-band arrangement covers it. Full verification needs the SMTP envelope the message arrived with, which only the receiving system knows, so `dkim2Sign()` does not do it: verify the message with `dkim2Verify()` and that envelope first, and sign only when the result is `pass`. The signer itself only refuses a chain it can not continue (invalid or gapped header fields, a broken chain of custody to the new hop, a Recipe that does not recreate the previous instance).

- A `Message-Instance` is added when the message has none, or when its hashes differ from the highest one. A changed message needs a `recipe`, which is applied before signing to make sure it recreates the highest instance. A Recipe for a header field that is not signed is refused.
- The new signature continues the chain of custody: its signing domain has to equal the `nd=` of the previous signature, or its MAIL FROM domain has to match a RCPT TO of the previous signature, or, with the null MAIL FROM or `nextDomain`, a RCPT TO domain of the previous signature has to be the signing domain or one of its subdomains.
- When the message is signed for the first time, or the Recipe shows that this hop changed the From, the From has to be Authentic with the signing domain (section 12.4). A subdomain signing for a From in its parent looks up the Domain Policy Record of the parent with the `resolver` option, and is refused when it has `f=strict` or can not be fetched.
- The `exploded` flag is refused on the first signature (section 12.5).
- Keys are signed as one `,` group by default. A list of lists in `signatureData` gives `|` groups.
- Long tag values are folded inside base64strings, where section 2.14 allows FWS, never next to the `:`, `,` or `|` they are joined to.
