# DKIM2 Result Reference

This document describes the result object returned by `dkim2Verify()` and how mailauth reads the parts of the DKIM2 drafts that are open to interpretation.

> [!WARNING]
> DKIM2 support is experimental. It is built against these Internet-Drafts, which are not finished and can change:
>
> - [draft-ietf-dkim-dkim2-spec-06](https://www.ietf.org/archive/id/draft-ietf-dkim-dkim2-spec-06.txt) (28 August 2026), the protocol
> - [draft-ietf-dkim-dkim2-dns-00](https://www.ietf.org/archive/id/draft-ietf-dkim-dkim2-dns-00.txt) (20 July 2026), the key records. The specification cites its predecessor, draft-chuang-dkim2-dns-04, mailauth follows the working group version
> - [draft-ietf-dkim-dkim2-bcp-01](https://www.ietf.org/archive/id/draft-ietf-dkim-dkim2-bcp-01.txt) (9 September 2026), best practices
> - [draft-gondwana-dkim2-authres-00](https://datatracker.ietf.org/doc/html/draft-gondwana-dkim2-authres-00) (3 September 2026, not adopted by the working group), the `dkim2` Authentication-Results method
>
> Section numbers below refer to draft-ietf-dkim-dkim2-spec-06 unless noted otherwise.

## Overview

```javascript
const { dkim2Verify } = require('mailauth');

const result = await dkim2Verify(message, {
    mailFrom: 'bounce@list.example.org',
    rcptTo: ['member@example.net']
});
```

The whole message gets one result (section 11.1):

| Result      | Meaning                                                                                                    |
| ----------- | ---------------------------------------------------------------------------------------------------------- |
| `pass`      | Every instance, signature and chain of custody check passed                                                |
| `fail`      | A hash or signature was not correct, or a `donotmodify`, `donotexplode` or replay check failed             |
| `permerror` | The message could not be verified: malformed or missing header fields, missing keys, an envelope mismatch… |
| `temperror` | A public key could not be fetched because of a temporary DNS failure                                       |
| `none`      | The message has no DKIM2 header fields                                                                     |

When there are several problems, `fail` wins over `permerror`, and `permerror` over `temperror`, so that a cryptographic failure is never reported as temporary (section 10.4: such failures "MUST NOT provoke 4xx SMTP replies").

## Top-Level Result Object

| Field        | Type       | Description                                                                                               |
| ------------ | ---------- | --------------------------------------------------------------------------------------------------------- |
| `status`     | `object`   | `{ result, comment, header }`, see below                                                                  |
| `info`       | `string`   | Authentication-Results resinfo, such as `dkim2=pass (i=1 example.com pass) header.d=example.com`          |
| `errors`     | `object[]` | Every problem found, in the order the checks ran: `{ result, message, i, m }`                             |
| `instances`  | `object[]` | One entry per `Message-Instance`, see below                                                               |
| `signatures` | `object[]` | One entry per `DKIM2-Signature`, see below                                                                |
| `replay`     | `object`   | `{ key, exploded }`: the `m=1` hashes that identify the message, and whether a signature has `f=exploded` |

### status

| Field      | Type       | Description                                                                                                                                         |
| ---------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `result`   | `string`   | One of the results above                                                                                                                            |
| `comment`  | `string`   | The human-readable string of the reported problem, as specified in section 11, such as `DKIM2-Signature i=1 rsa incorrect signature`                |
| `header.d` | `string`   | `d=` of the `i=1` signature, the originator (draft-gondwana-dkim2-authres-00 section 3.2.1)                                                         |
| `header.i` | `number`   | `i=` of the signature the problem is reported against. Not set for `pass`, or for a problem of the whole message                                    |
| `warnings` | `string[]` | `mail-from-not-checked` and/or `rcpt-to-not-checked` when that part of the SMTP envelope was not given, see [Envelope Warnings](#envelope-warnings) |

`header.d` is an authenticated identity only when the result is `pass`.

### Envelope Warnings

The chain of custody is what stops DKIM2 replay: the highest `DKIM2-Signature` names the MAIL FROM and RCPT TO the message was delivered with (section 11.4). A library does not see the SMTP transaction, so this check only runs for the parts of the envelope you pass as `mailFrom` and `rcptTo`. When one is missing, `status.warnings` says so:

- `mail-from-not-checked`: `mailFrom` was not given (`""` counts as given, it is the null sender)
- `rcpt-to-not-checked`: `rcptTo` was not given

Without them an unchanged copy of the message, sent to anyone, passes as well. The warnings do not change the result and are never written into `info`, in the same way as the DKIM1 warnings. `authenticate()` passes its `sender` and `rcptTo` options on, so set `rcptTo` there to have the recipients checked.

### instances

| Field    | Type       | Description                                                                                                                                                      |
| -------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `m`      | `number`   | Revision number                                                                                                                                                  |
| `hashes` | `object[]` | `{ algorithm, header, body }` for every supported hash algorithm. `body` is `unknown` when a later hop declared that the body can not be recreated (`"b": null`) |
| `recipe` | `object`   | When the instance has a Recipe: `{ headers, body }`, the header field names it recreates, and `unchanged`, `recipe` or `unrecoverable` for the body              |

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

Each entry of `values` has `selector`, `algorithm`, `result` (`pass`, `fail`, `permerror`, `temperror`, or `none` for an algorithm that is not supported and so ignored, section 3.4), and when available `comment`, `rr` (the key record), `modulusLength` and `testing` (the key record has `t=y`; draft-ietf-dkim-dkim2-dns-00 says a signer in testing mode must be treated like unsigned mail, which is up to you).

## What Is Checked

1. **Syntax and numbering (section 11.2).** Every `Message-Instance` and `DKIM2-Signature` is parsed. `m=` and `i=` start at 1 with no gaps, no instance is above the highest `m=` of a signature, no hash algorithm or selector repeats, and no signing algorithm is used more than twice.
2. **Recipes (sections 5 and 11).** Starting from the message as it is, the Recipe of every instance is applied to recreate the one before it.
3. **Hashes (section 11.7).** The header and body hashes of every instance are compared with the recreated message.
4. **Timestamps (section 11.3).** A signature older than `maxSignatureAge` (14 days) is a PERMERROR.
5. **Chain of custody (sections 8.7, 8.8, 9.4 and 11.4).** `d=` matches the `mf=` domain of every signature, `nd=` names the next signer exactly, the MAIL FROM of every hop matches a RCPT TO of the hop before it, and, for the parts of the envelope given as `mailFrom` and `rcptTo`, the highest signature matches the delivery. A missing part is reported in `status.warnings`.
6. **Signatures (sections 9.6, 11.5 and 11.6).** Every signature value with a supported algorithm is checked with its key.
7. **Requests (section 11.8).** `donotmodify` and `donotexplode` were honored by the later hops.
8. **Replay (section 11.9).** When `checkReplay` is given and reports a duplicate, the message fails unless a signature has `f=exploded`.

## How the Drafts Are Read

The drafts leave some questions open. mailauth answers them like this:

- **Unknown keys in a Recipe step.** Section 2 says unrecognised JSON fields "MUST be ignored", while the JSON schema of section 5 sets `additionalProperties: false` for steps. Unknown keys are ignored, but a step still needs exactly one of `c` and `d`.
- **Recipe validity.** A Recipe that does not follow the schema (no `h` and no `b`, an empty `h`, an upper case header field name, a `c` range that is out of order or past the last line or header field, a `d` string with CR or LF) is reported as `Message-Instance m=<x> contains invalid JSON: <reason>`. Recipes for header fields that are not signed (section 4) are ignored.
- **Only unknown signature algorithms.** A `DKIM2-Signature` whose `s=` has no signature value with a supported algorithm is a PERMERROR, `DKIM2-Signature i=<x> has no supported signature algorithm`. Section 3.4 has the unknown algorithms ignored, so nothing could be verified and nothing was found incorrect, which section 11.1 defines as PERMERROR. The FAIL of section 11.6 step 3 is about the signatures that can be checked. The turscar vectors, written for spec-02, expect FAIL here, croessner/dkim2, written for spec-06, reports PERMERROR.
- **Signature values that can not be checked.** Section 11.6 requires every signature value that can be checked to pass. A value whose key is missing or broken can not be checked: when at least one other value passes and none fails, the signature passes and the key problem is reported in its `values` entry. When no value could be checked, the key problem is the result.
- **Chain of custody between hops.** Section 9.4 matches the MAIL FROM of a hop with a RCPT TO of the hop before it. A signature with `nd=` has no MAIL FROM, and the null MAIL FROM `<>` has no domain, so for those the `d=` is matched instead (section 9.3 says the signer of such a hop holds a key "associated with a domain in the RCPT TO entry"). Section 8.8 waives only the `d=` and `mf=` match for the null MAIL FROM, not the chain of custody, so a hop with `mf=<>` can not be added by a domain the message was never sent to.
- **`d=` and `mf=`.** Section 8.8 requires every signature's `d=` to match its `mf=` domain, so this is checked for every signature, not only the highest as section 11.4 describes.
- **Envelope.** The chain of custody against the SMTP envelope is only checked for the parts given as `mailFrom` and `rcptTo`, a missing part gives a warning. When either is given and the highest signature has `nd=`, the result is `DKIM2-Signature i=<x> unexpected nd= tag`, since the delivery can then only be accepted on out-of-band arrangements (section 9.3).
- **Future timestamps.** Section 8.4 allows ignoring signatures with a timestamp in the future. mailauth does not by default, as ignoring the only signature makes the message unsigned. With `maxFutureTime` a timestamp further ahead than that is a PERMERROR, `DKIM2-Signature i=<x> signature timestamp is in the future`.
- **RSA key size.** Verifiers have to handle 1024 to 2048 bits and may handle more (section 3.2). mailauth accepts up to 8192 bits, a longer key is `public key <selector> is too long`.
- **`donotmodify`.** Section 8.10 allows adding header fields. A message passes when every signed header field of the instance the request was made on is still present, in the same order, and the body hash is unchanged. A null body Recipe after the request counts as a change.
- **Key records.** Records are read with the tag-list rules of draft-ietf-dkim-dkim2-dns-00: tag names are case sensitive, `v=`, when present, is exactly `DKIM1` and the first tag, duplicate tags and other syntax errors make the record unusable, several TXT records are an error, and `k=` has to match the algorithm (`rsa` for `rsa-sha256`, `ed25519` for `ed25519-sha256`). The retired `h=`, `n=` and `s=` tags are ignored, and so is the `t=s` flag, as DKIM2 has no `i=` identity. Ed25519 keys are published as the bare 32 byte key (RFC 8463). RSA keys need at least 1024 bits and the public exponent 65537 (section 3.2).
- **Leading whitespace in Recipe data.** The header hash removes the whitespace after the colon, so `{"d": [" value"]}` and `{"d": ["value"]}` recreate the same header field.

### Error Strings Not in the Specification

Section 11 lists the human-readable strings to use. These cases have no string there, so mailauth adds its own:

- `Message-Instance m=<x> appears more than once` and `DKIM2-Signature i=<x> appears more than once`
- `Message-Instance m=<x> has no supported hash algorithm` and `DKIM2-Signature i=<x> has no supported signature algorithm`
- `Message has more than <n> Message-Instance or DKIM2-Signature header fields` (draft-ietf-dkim-dkim2-bcp-01 section 7.5)
- `DKIM2-Signature i=<x> public key <selector> is too short`, `... is too long` and `... has an unsupported exponent`
- `DKIM2-Signature i=<x> signature timestamp is in the future`

The strings of section 11 are used as written, including their inconsistencies (`Message Instance` without the hyphen in section 11.7, `MAIL nd= does not match` in section 11.4).

## Interoperability

mailauth has been checked against three independent DKIM2 implementations. Where an implementation built for an earlier revision of the specification disagrees with draft-ietf-dkim-dkim2-spec-06, mailauth follows spec-06.

- **[croessner/dkim2](https://github.com/croessner/dkim2)** (draft-ietf-dkim-dkim2-spec-06 and draft-ietf-dkim-dkim2-dns-00, the same drafts as mailauth). Its public verification vectors are part of the test suite (`test/fixtures/dkim2-croessner`), and its header, body and section 9.6 canonicalization, Recipe application, chain of custody, DNS record and crypto vectors give the same results. The differences are choices outside the protocol:
    - a message with no DKIM2 header fields is `none` in mailauth (draft-gondwana-dkim2-authres-00 section 3.1, and draft-ietf-dkim-dkim2-bcp-01 section 6.1.3 says the absence alone is not a reason to reject), a PERMERROR in croessner/dkim2, which also refuses messages with bare LF line endings
    - croessner/dkim2 rejects timestamps more than five minutes in the future, mailauth does that with `maxFutureTime: 300` (section 8.4 makes it a MAY)

- **[turscar/dkim2](https://forge.turscar.ie/Turscar/dkim2)** (draft-ietf-dkim-dkim2-spec-02). The 42 vectors of [turscar/dkim2tests](https://forge.turscar.ie/turscar/dkim2tests) give the expected result, except `algorithm_only_future` (only unknown signature algorithms), which is FAIL in the vector and PERMERROR by spec-06 (see above). They also give the same section 9.6 canonical form, and the same Message-Instance hashes when mailauth signs the original messages. The vectors are part of the test suite (`test/fixtures/dkim2tests`). One vector, `flags_whitespace`, expects flags that its signed message does not have.
- **[stalwartlabs/mail-auth](https://github.com/stalwartlabs/mail-auth)** (draft-ietf-dkim-dkim2-spec-04). Messages signed by each implementation verify with the other: originators with Ed25519, and with RSA and Ed25519 together, flags, nonce and several recipients, the null reverse-path, forwarders with and without a Recipe, and hops with `nd=`. The messages signed by mail-auth are part of the test suite (`test/fixtures/dkim2-stalwart`). The differences:
    - mail-auth fails a message whose body was declared unrecoverable with a null body Recipe (`{"b": null}`). mailauth passes it and reports the earlier body as `unknown`, as croessner/dkim2 does, since section 5.2 makes accepting such a declaration local policy, section 9.1 allows the null Recipe, and draft-ietf-dkim-dkim2-bcp-01 sections 5.7 and 7.6 recommend it.
    - The interop vectors in the mail-auth corpus that were made by an implementation for an earlier draft encode `mf=` and `rt=` without angle brackets, which sections 8.5 and 8.6 of spec-06 require (mail-auth rejects them too, outside its tests), and sign `Received-SPF`, which section 4 of spec-06 leaves unsigned. With those two rules relaxed, mailauth verifies all of them, including a chain of six hops with header and body Recipes.

## Signing

`dkim2Sign()` follows section 9:

- A `Message-Instance` is added when the message has none, or when its hashes differ from the highest one. A changed message needs a `recipe`, which is applied before signing to make sure it recreates the highest instance.
- The new signature continues the chain of custody: its signing domain has to equal the `nd=` of the previous signature, or its MAIL FROM domain (or, with `nextDomain`, its signing domain) has to match a RCPT TO of the previous signature.
- Long tag values are folded inside base64 values, where section 2.14 allows FWS.
