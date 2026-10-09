# mailauth: Email Authentication for Node.js

![mailauth Logo](https://github.com/postalsys/mailauth/raw/master/assets/mailauth.png)

**mailauth** is a comprehensive Node.js library and command-line utility for email authentication. It provides tools to work with various email security protocols, including SPF, DKIM, DMARC, ARC, BIMI, and MTA-STS. With mailauth, you can verify and sign emails, handle authentication results, and enhance your email security setup.

**Key Features:**

- **SPF** verification
- **DKIM** signing and verification
- **DMARC** verification
- **ARC** verification and sealing
    - Sealing during authentication
    - Sealing after message modifications
- **BIMI** resolving and **VMC** validation
- **MTA-STS** helper functions

mailauth is a pure JavaScript implementation, requiring no external applications or compilation. It runs on any server or device with Node.js version 22.19.0 or later.

> [!NOTE]
> mailauth is used by [EmailEngine](https://emailengine.app/) for validating email authentication settings. See the [Email Authentication Testing documentation](https://learn.emailengine.app/docs/advanced/email-authentication-testing) for details.

## Table of Contents

1. [Installation](#installation)
2. [Command-Line Usage](#command-line-usage)
3. [Library Usage](#library-usage)
    - [Authentication](#authentication)
        - [Strict mode](#strict-mode)
    - [DKIM](#dkim)
        - [Signing](#dkim-signing)
        - [Verification](#dkim-verification)
    - [SPF](#spf)
        - [Verification](#spf-verification)
    - [ARC](#arc)
        - [Validation](#arc-validation)
        - [Sealing](#arc-sealing)
    - [DMARC](#dmarc)
        - [Helpers](#dmarc-helpers)
    - [BIMI](#bimi)
    - [MTA-STS](#mta-sts)
        - [Policy Retrieval](#policy-retrieval)
        - [MX Validation](#mx-validation)
4. [Testing](#testing)
5. [License](#license)

## Installation

First, install mailauth from npm:

```bash
npm install mailauth
```

Then, import the desired methods into your script:

```javascript
const { authenticate } = require('mailauth');
```

## Command-Line Usage

mailauth includes a command-line utility called `mailauth`. For detailed information on how to use it, see the [command-line documentation](cli.md).

## Library Usage

### Authentication

Use the `authenticate` function to validate DKIM signatures, SPF, DMARC, ARC, and BIMI for an email.

#### Syntax

```javascript
await authenticate(message [, options])
// Returns: { dkim, spf, arc, dmarc, bimi, receivedChain, headers [, dmarcSkipReason] }
```

#### Parameters

- **message**: A `String`, `Buffer`, or `Readable` stream representing the email message.
- **options** (optional):
    - **sender** (`string`): Email address from the MAIL FROM command. Defaults to the `Return-Path` header if not set.
    - **ip** (`string`): IP address of the remote client that sent the message.
    - **helo** (`string`): Hostname from the HELO/EHLO command.
    - **trustReceived** (`boolean`): If `true`, parses `ip` and `helo` from the latest `Received` header if not provided. The IP address is the connecting address from the TCP-info comment of the `from` clause (RFC 5321 section 4.4), never an address literal the client sent in its HELO. The HELO name is the `from` value, or the `helo=` value that Exim writes into the comment, and is only taken when neither `ip` nor `helo` was provided. Postfix, Sendmail, Exim (including its `from [ip] (helo=...)` form) and similar formats are understood. If the header can not be read without guessing, for example when the HELO name holds parentheses, quotes, an address literal in a comment or a `by` keyword that make the `from` clause ambiguous, no IP address is taken from it. Defaults to `false`.
    - **mta** (`string`): Hostname of the server performing the authentication. Defaults to `os.hostname()`. Used as the authserv-id of the Authentication headers, so it should be a host name: an internationalized name is converted to A-labels, and a value that is not a valid token (for example one with a space or a semicolon) is written as a quoted string. With `strict` such a value throws an error with the code `EINVALIDAUTHSERVID` instead.
    - **minBitLength** (`number`): Minimum allowed bits for RSA public keys. Defaults to `1024`. Keys with fewer bits will fail validation.
    - **rejectRsaSha1** (`boolean`): If `true`, an rsa-sha1 DKIM signature gives `dkim=policy` with `policy.dkim-rules=weak-algorithm`, as in strict mode, and is not counted for DMARC. Every other check keeps the lenient default. It only affects verification. Defaults to `false`, and `strict` implies it.
    - **disableArc** (`boolean`): If `true`, skips ARC checks.
    - **disableDmarc** (`boolean`): If `true`, skips DMARC checks, also disabling dependent checks like BIMI.
    - **disableBimi** (`boolean`): If `true`, skips BIMI checks.
    - **seal** (`object`): Options for ARC sealing. A message without an ARC chain or with a valid one is sealed with `cv=none` or `cv=pass`, a message with a failed chain is sealed with `cv=fail`, unless its newest ARC-Seal already says `cv=fail` (RFC 8617 section 5.1).
        - **signingDomain** (`string`): ARC key domain name.
        - **selector** (`string`): ARC key selector.
        - **privateKey** (`string` or `Buffer`): Private key for signing (RSA or Ed25519).
    - **resolver** (`async function`): Custom DNS resolver function. Defaults to [`dns.promises.resolve`](https://nodejs.org/api/dns.html#dns_dnspromises_resolve_hostname_rrtype).
    - **maxResolveCount** (`number`): DNS lookup limit for SPF. Defaults to `10` as per [RFC7208](https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4).
    - **maxVoidCount** (`number`): DNS lookup limit for SPF producing empty results. Defaults to `2` as per [RFC7208](https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4).
    - **strict** (`boolean`): If `true`, every check follows its RFC exactly instead of the lenient defaults. Passed on to DKIM, SPF, ARC, DMARC, BIMI and ARC sealing (BIMI only uses it for the format of its Authentication-Results entry). Defaults to `false`. See [Strict mode](#strict-mode).

#### Example

```javascript
const { authenticate } = require('mailauth');
const dns = require('dns');

const message = /* Your email message here */;

const { dkim, spf, arc, dmarc, bimi, receivedChain, headers } = await authenticate(message, {
  // SMTP transmission options
  ip: '217.146.67.33',                 // SMTP client IP
  helo: 'uvn-67-33.tll01.zonevs.eu',   // HELO/EHLO hostname
  sender: 'andris@ekiri.ee',           // MAIL FROM address

  // Uncomment to parse `ip` and `helo` from the latest `Received` header
  // trustReceived: true,

  // Server performing the authentication
  mta: 'mx.ethereal.email',

  // Optional DNS resolver function
  resolver: async (name, rr) => await dns.promises.resolve(name, rr),
});

// Output authenticated message
process.stdout.write(headers); // Includes terminating line break
process.stdout.write(message);
```

**Sample Output:**

```
Received-SPF: pass (mx.ethereal.email: domain of andris@ekiri.ee designates 217.146.67.33 as permitted sender) client-ip=217.146.67.33;
Authentication-Results: mx.ethereal.email;
 dkim=pass header.i=@ekiri.ee header.s=default header.a=rsa-sha256 header.b=TXuCNlsq;
 spf=pass (mx.ethereal.email: domain of andris@ekiri.ee designates 217.146.67.33 as permitted sender) smtp.mailfrom=andris@ekiri.ee
 smtp.helo=uvn-67-33.tll01.zonevs.eu;
 arc=pass (i=2 spf=neutral dkim=pass dkdomain=ekiri.ee);
 dmarc=none header.from=ekiri.ee
From: ...
```

You can see the full output, including structured data for DKIM, SPF, DMARC, and ARC, from [this example](https://gist.github.com/andris9/6514b5e7c59154a5b08636f99052ce37).

**Note:** The `receivedChain` property is an array of parsed representations of the `Received:` headers.

**Note:** `dmarc` is `false` when DMARC can not be evaluated because the From header has no domain or more than one (RFC 9989 section 5.3.1). `dmarcSkipReason` then says why: `no-author-domain`, `multiple-author-domains`, `invalid-author-domain` (a From mailbox has no usable domain, or the From header is malformed) or `multiple-from-fields` (the message has more than one From header field, which RFC 5322 does not allow). RFC 9989 section 11.5 suggests treating such a message as suspicious.

**Note:** An ARC set is only added while the chain has fewer than 50 sets (RFC 8617 section 4.2.1). Otherwise the message is not sealed and `arc.sealErrors` says why.

#### Strict mode

By default mailauth is lenient where accepting non-conforming input costs little security, mostly weak signatures that still bind the signing domain to the content. With `strict: true` every check follows its RFC exactly.

Whatever the default mode accepts that strict mode would reject is marked in a `warnings` array on the affected result (for example `dkim.results[0].status.warnings` is `['rsa-sha1']`), so that you can apply your own policy without switching modes. The markers are never written into the generated headers. For rsa-sha1 verification the `rejectRsaSha1` option applies the strict rule on its own, which also keeps such a signature out of DMARC in `authenticate()`.

Some rules apply in both modes, because breaking them is a defect and not leniency. For DKIM these are: a signature must sign the From header, the key record's `h=` (hash algorithms) and `s=` (service types) restrictions are honored, `ed25519-sha1` is not an algorithm, the key type must match the signature algorithm, a `d=` with a character that can not be in a host name (such as `/`, `?` or `#`) makes the signature invalid, and signing refuses a domain, selector or identity that would break out of its tag.

DKIM differences between the modes:

| Input                                                              | Default                                               | `strict: true`                                                             |
| ------------------------------------------------------------------ | ----------------------------------------------------- | -------------------------------------------------------------------------- |
| rsa-sha1 signature (RFC 8301)                                      | `pass`, warning `rsa-sha1`                            | `policy` (`policy.dkim-rules=weak-algorithm`)                              |
| Missing `v=` or `h=`, `v=` other than 1                            | verified, warning `missing-v`/`missing-h`/`invalid-v` | `neutral` (`signature missing required tag`, `incompatible version`)       |
| Duplicate/upper case tags, bad `c=`/`t=`/`x=`/`l=`, `l=` > body    | verified, warning `tag-syntax`                        | `neutral` (`signature syntax error`)                                       |
| `i=` domain outside `d=`, or a subdomain with a key that has `t=s` | verified, warning `identity-domain`                   | `neutral` (`domain mismatch`)                                              |
| `x=` equal to `t=`                                                 | verified, warning `invalid-expiration`                | `neutral` (`invalid expiration`)                                           |
| Key record syntax errors, `v=` not first or not exactly `DKIM1`    | used, warning `key-syntax`/`key-v-syntax`             | key ignored                                                                |
| Ed25519 key record without `k=ed25519`                             | used, warning `key-type-inferred`                     | key ignored                                                                |
| Ed25519 key published as SubjectPublicKeyInfo                      | used, warning `key-ed25519-spki`                      | key ignored                                                                |
| Body hash mismatch                                                 | `neutral`                                             | `fail`                                                                     |
| Signature with an unknown algorithm or no `d=`/`s=`                | left out of the results                               | `neutral`                                                                  |
| `header.i` in Authentication-Results                               | always `@d`                                           | the AUID (`i=` or `@d`), plus `header.d`                                   |
| Email identities in Authentication-Results                         | a value that needs quoting is quoted as a whole       | `local-part@domain` with only the local-part quoted (RFC 8601 section 2.2) |
| Header order                                                       | Received-SPF above Authentication-Results             | Authentication-Results on top (RFC 8601 section 5)                         |
| Signing with rsa-sha1 or an RSA key under 1024 bits                | signed, warning `rsa-sha1`/`weak-key`                 | error                                                                      |

See the [DKIM result reference](docs/dkim.md) for every DKIM warning, and the SPF, DMARC, ARC and MTA-STS documentation for theirs.

### DKIM

#### DKIM Signing

Use the `dkimSign` function to sign an email message with DKIM.

##### Syntax

```javascript
const { dkimSign } = require('mailauth/lib/dkim/sign');

const signResult = await dkimSign(message, options);
// Returns: { signatures: String, errors: Array, warnings: Array }
```

`signatures` holds the `DKIM-Signature` header lines, each ending with a line break. It is an empty string when no signature could be created, in which case `errors` says why. Each entry of `errors` is an object with an `err` property (an `Error` with a `code`, such as `ENOFROM`, `ENOKEY`, `EINVALIDALGO`, `ESHORTKEY` or `EINVALIDDOMAIN`) and the `signingDomain` and `selector` it applies to. When no signature is configured at all, the only entry has the code `ENOSIGNATURE`. `warnings` lists what was signed although `strict` mode would have refused it (`rsa-sha1`, `weak-key`, `invalid-expiration`, `invalid-signtime`, `d-syntax`, `s-syntax`, `identity-syntax`, `identity-domain`).

##### Parameters

- **message**: A `String`, `Buffer`, or `Readable` stream representing the email message.
- **options**:
    - **canonicalization** (`string`): Canonicalization method, as `header/body`. Defaults to `'relaxed/relaxed'`. Read like a `c=` value: case-insensitive, and a value without a body part, such as `'relaxed'`, uses `simple` for the body. A signature with an unknown method is not created and gets an `EINVALIDCANON` error.
    - **algorithm** (`string`): Signing and hashing algorithm. Defaults to `'rsa-sha256'` for an RSA key and `'ed25519-sha256'` for an Ed25519 key. `'rsa-sha1'` is historic (RFC 8301) and adds a warning.
    - **signTime** (`Date`): Signing time. Defaults to current time.
    - **expires** (`Date`): Signature expiration time (`x=` tag). Optional. It must be later than the signing time.
    - **headerList** (`Array` or `string`): Header field names to sign, as an array or a colon separated string. Optional; uses default set if not specified. `From` must be included. Every field of a listed name is signed, and a name the message does not have is left out of `h=`. To over-sign a field (RFC 6376 section 8.15), so that adding another instance of it in transit breaks the signature, list its name more than once, such as `'From:From:Subject:Subject'`: a repeated name appears in `h=` as many times as it is listed, or as many times as the message has that field, whichever is more.
    - **strict** (`boolean`): If `true`, refuses to sign with `rsa-sha1`, with an RSA key shorter than 1024 bits, with an expiration that is not after the signing time, and with a domain, selector or identity that is not valid RFC 6376 syntax. Defaults to `false`, which signs these and lists them in `warnings`. A value that would break out of its tag (a semicolon, whitespace or a line break in the domain, selector or identity) is refused in both modes.
    - **signatureData** (`Array`): Array of signature objects, one for each signature to create. The domain, selector and key are only read from here, not from the top level of the options. Each object may contain:
        - **signingDomain** (`string`): DKIM key domain name. An internationalized domain name is converted to A-labels.
        - **selector** (`string`): DKIM key selector.
        - **privateKey** (`string` or `Buffer`): Private key for signing (RSA or Ed25519). An entry without a key is not signed and gets an `ENOKEY` error.
        - **algorithm** (`string`, optional): Overrides parent `algorithm`.
        - **canonicalization** (`string`, optional): Overrides parent `canonicalization`.
        - **headerList** (`Array` or `string`, optional): Overrides parent `headerList`.
        - **identity** (`string`, optional): Agent or User Identifier for the `i=` tag, such as `user@mail.example.com`. Its domain must be the signing domain or one of its subdomains. Pass the address as it is, not encoded: it is written in dkim-quoted-printable, so `jõgi@example.com` becomes `i=j=C3=B5gi@example.com` and a `=` becomes `=3D`.
        - **maxBodyLength** (`number`, optional): Maximum number of canonicalized body bytes to sign (`l=` tag). Not recommended for general use.

##### Example

```javascript
const { dkimSign } = require('mailauth/lib/dkim/sign');
const fs = require('fs');

const message = /* Your email message here */;

const signResult = await dkimSign(message, {
  canonicalization: 'relaxed/relaxed',
  algorithm: 'rsa-sha256',
  signTime: new Date(),
  signatureData: [
    {
      signingDomain: 'tahvel.info',
      selector: 'test.rsa',
      privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem'),
    },
  ],
});

// Display signing errors if any
if (signResult.errors.length) {
  console.error('Signing errors:', signResult.errors);
}

// Output signed message
process.stdout.write(signResult.signatures); // Includes terminating line break
process.stdout.write(message);
```

**Sample Output:**

```
DKIM-Signature: a=rsa-sha256; v=1; c=relaxed/relaxed; d=tahvel.info;
 s=test.rsa; b=...
From: ...
```

#### DKIM Signing as a Stream

Use `DkimSignStream` to sign messages as part of a stream processing pipeline.

##### Example

```javascript
const { DkimSignStream } = require('mailauth/lib/dkim/sign');
const fs = require('fs');

const dkimSignStream = new DkimSignStream({
    canonicalization: 'relaxed/relaxed',
    algorithm: 'rsa-sha256',
    signTime: new Date(),
    signatureData: [
        {
            signingDomain: 'tahvel.info',
            selector: 'test.rsa',
            privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
        }
    ]
});

// Read from stdin, write signed message to stdout
process.stdin.pipe(dkimSignStream).pipe(process.stdout);
```

When no signature can be created the message is passed through unchanged. Once the stream has ended, `dkimSignStream.errors` and `dkimSignStream.warnings` hold the same values as the `dkimSign` result.

#### DKIM Verification

Use the `dkimVerify` function to verify DKIM signatures in an email message.

##### Syntax

```javascript
const { dkimVerify } = require('mailauth/lib/dkim/verify');

const result = await dkimVerify(message [, options]);
// Returns an object containing verification results
```

- **options** (optional):
    - **resolver** (`async function`): Custom DNS resolver function. Defaults to `dns.promises.resolve`. A U-label signing domain is converted to A-labels before it is looked up (RFC 8616).
    - **minBitLength** (`number`): Minimum allowed bits for RSA public keys. Defaults to `1024`. A shorter key gives `dkim=policy` with `policy.dkim-rules=weak-key`.
    - **rejectRsaSha1** (`boolean`): If `true`, an rsa-sha1 signature gives `dkim=policy` with `policy.dkim-rules=weak-algorithm`, as in strict mode, while every other check keeps the lenient default. Signing is not affected. Defaults to `false`, and `strict` implies it.
    - **sender** (`string`): Envelope sender. Defaults to the `Return-Path` header.
    - **curTime** (`Date`): The time to check `t=` and `x=` against. Defaults to now.
    - **strict** (`boolean`): If `true`, follows RFC 6376, RFC 8301 and RFC 8463 exactly. Defaults to `false`. See [Strict mode](#strict-mode).

Whatever the mode, a signature that does not sign the From header is reported as `dkim=neutral (From field not signed)`, and a key record whose `h=` does not list the hash algorithm of the signature, or whose `s=` does not include `email`, is not used. A key record with `t=y` (testing) sets `status.testing`.

See [DKIM Result Reference](docs/dkim.md) for details on the result object structure.

##### Example

```javascript
const { dkimVerify } = require('mailauth/lib/dkim/verify');

const message = /* Your email message here */;

const result = await dkimVerify(message);

for (const { info } of result.results) {
  console.log(info);
}
```

**Sample Output:**

```
dkim=neutral (invalid public key) header.i=@tahvel.info header.s=test.invalid header.b="b85yao+1"
dkim=pass header.i=@tahvel.info header.s=test.rsa header.b="BrEgDN4A"
dkim=policy policy.dkim-rules=weak-key header.i=@tahvel.info header.s=test.small header.b="d0jjgPun"
```

### SPF

#### SPF Verification

Use the `spf` function to verify the SPF record for an email sender.

##### Syntax

```javascript
const { spf } = require('mailauth/lib/spf');

const result = await spf(options);
// Returns an object containing SPF verification results
```

See [SPF Result Reference](docs/spf.md) for details on the result object structure.

##### Parameters

- **options**:
    - **sender** (`string`): MAIL FROM address.
    - **ip** (`string`): SMTP client IP.
    - **helo** (`string`): HELO/EHLO hostname.
    - **mta** (`string`): Hostname of the MTA performing the check.
    - **resolver** (`function`): Custom DNS resolver, same signature as `dns.promises.resolve`.
    - **maxResolveCount** (`number`): Maximum DNS lookups, defaults to `10`.
    - **maxVoidCount** (`number`): Maximum void DNS lookups, defaults to `2`.
    - **maxElapsedTime** (`number`): Time limit in milliseconds for the whole evaluation. If exceeded, the result is `temperror`. No limit by default.
    - **strict** (`boolean`): If `true`, follow RFC 7208 exactly: the whole record is validated before evaluation, void lookups are counted as the RFC does, and Authentication-Results reports only the checked identity. Defaults to `false`. See [Strict Mode](docs/spf.md#strict-mode).

In the default mode, input that strict mode would reject is listed in the `warnings` array of the result. For a `fail` result, the `explanation` property holds the text published with the `exp` modifier, if any.

##### Example

```javascript
const { spf } = require('mailauth/lib/spf');

const result = await spf({
    sender: 'andris@wildduck.email',
    ip: '217.146.76.20',
    helo: 'foo',
    mta: 'mx.myhost.com'
});

console.log(result.header);
```

**Sample Output:**

```
Received-SPF: pass (mx.myhost.com: domain of andris@wildduck.email designates 217.146.76.20 as permitted sender) client-ip=217.146.76.20;
 envelope-from="andris@wildduck.email"; helo=foo;
```

### ARC

#### ARC Validation

ARC seals are validated automatically during the authentication step.

##### Example

```javascript
const { authenticate } = require('mailauth');

const message = /* Your email message here */;

const { arc } = await authenticate(message, {
  trustReceived: true,
});

console.log(arc);
```

See [ARC Result Reference](docs/arc.md) for details on the result object structure, and for what `strict: true` changes.

**Sample Output:**

```json
{
    "status": {
        "result": "pass",
        "comment": "i=2 spf=neutral dkim=pass dkdomain=zonevs.eu dkim=pass dkdomain=srs3.zonevs.eu dmarc=fail fromdomain=zone.ee"
    },
    "i": 2
    // Additional properties...
}
```

#### ARC Sealing

You can seal messages with ARC either during authentication or after modifications.

##### Sealing During Authentication

Provide the sealing key in the options to seal messages automatically during authentication.

```javascript
const { authenticate } = require('mailauth');
const fs = require('fs');

const message = /* Your email message here */;

const { headers } = await authenticate(message, {
  trustReceived: true,
  seal: {
    signingDomain: 'tahvel.info',
    selector: 'test.rsa',
    privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem'),
  },
});

// Output authenticated and sealed message
process.stdout.write(headers); // Includes terminating line break
process.stdout.write(message);
```

The sealing algorithm follows the key type (`rsa-sha256` or `ed25519-sha256`). A message with a failed ARC chain, including one that is malformed, is sealed with `cv=fail`. A message whose newest ARC-Seal already says `cv=fail` is not sealed again (RFC 8617 section 5.1 step 2). When a requested seal could not be added, for example because the chain already has 50 sets (RFC 8617 section 4.2.1), `arc.sealErrors` says why.

##### Sealing After Modifications

If you need to modify the message before sealing, first authenticate it, modify as needed, then seal using the authentication results.

```javascript
const { authenticate, sealMessage } = require('mailauth');
const fs = require('fs');

const message = /* Your email message here */;

// Step 1: Authenticate the message
const { arc, headers } = await authenticate(message, {
  ip: '217.146.67.33',
  helo: 'uvn-67-33.tll01.zonevs.eu',
  mta: 'mx.ethereal.email',
  sender: 'andris@ekiri.ee',
});

// Step 2: Modify the message as needed
// ... your modifications ...

// Step 3: Seal the modified message
const sealHeaders = await sealMessage(message, {
  signingDomain: 'tahvel.info',
  selector: 'test.rsa',
  privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem'),
  authResults: arc.authResults,
  cv: arc.status.result,
});

// sealHeaders is empty when no ARC set could be created, use createSeal() to get the errors

// Output the sealed message
process.stdout.write(sealHeaders); // ARC headers
process.stdout.write(headers);     // Authentication results
process.stdout.write(message);
```

### DMARC

DMARC is verified during the authentication process. Although the `dmarc` handler is exported, it requires input from previous steps like SPF and DKIM.

The author domain is the domain of the From address, also when the local-part is quoted and contains "@" or the address has an obsolete source route. Several From addresses are evaluated if they share one domain. With no domain or several domains, DMARC validation is not possible and the result is `false`.

The Authentication-Results entry includes `policy.dmarc` with the evaluated policy on `pass` and `fail`. With `strict: true`, records follow the RFC 6376 tag-list rules (case sensitive tag names, a duplicated tag invalidates the record) and the unregistered `header.d` is left out. The default mode keeps `header.d` and case-folds tag names, letting the last duplicate win, and lists such records in `warnings`.

See [DMARC Result Reference](docs/dmarc.md) for details on the result object structure.

#### DMARC Helpers

##### `getDmarcRecord(domain [, resolver [, options]])`

Fetches and parses the DMARC record that applies to a domain, found with the DNS Tree Walk of RFC 9989 section 4.10. That is the domain's own record, or else the record of its Organizational Domain, or else a record published with `psd=y` above it. Returns `false` if no record applies.

###### Syntax

```javascript
const getDmarcRecord = require('mailauth/lib/dmarc/get-dmarc-record');

const dmarcRecord = await getDmarcRecord(domain [, resolver [, { strict }]]);
// Returns an object with DMARC record details or `false` if not found
```

###### Parameters

- **domain** (`string`): The domain to check for a DMARC record.
- **resolver** (`function`, optional): Custom DNS resolver function. Defaults to `dns.resolve`.
- **options.strict** (`boolean`, optional): Parse records by the RFC 6376 tag-list rules, so a record with a duplicated tag is ignored. Defaults to `false`.

###### Example

```javascript
const getDmarcRecord = require('mailauth/lib/dmarc/get-dmarc-record');

const dmarcRecord = await getDmarcRecord('ethereal.email');
console.log(dmarcRecord);
```

**Sample Output:**

```json
{
    "v": "DMARC1",
    "p": "none",
    "pct": 100,
    "rua": "mailto:re+joqy8fpatm3@dmarc.postmarkapp.com",
    "sp": "none",
    "aspf": "r",
    "rr": "v=DMARC1; p=none; pct=100; rua=mailto:re+joqy8fpatm3@dmarc.postmarkapp.com; sp=none; aspf=r;",
    "isOrgRecord": false,
    "recordDomain": "ethereal.email",
    "orgDomain": "ethereal.email"
}
```

`isOrgRecord` is `true` when the record was inherited from the Organizational Domain or a PSD, and `recordDomain` is where it was published. `orgDomain` is `null` when the record was found at the domain itself but the rest of the Tree Walk failed.

### BIMI

Brand Indicators for Message Identification (BIMI) support is based on [draft-brand-indicators-for-message-identification-14](https://datatracker.ietf.org/doc/html/draft-brand-indicators-for-message-identification). BIMI information is resolved during the authentication step, provided the message has a single From address and passes DMARC validation with an enforcing policy: neither the author domain's DMARC record nor the one of its Organizational Domain may have `p=none` or `sp=none`. A declination record (`v=BIMI1; l=;`) gives `bimi=declined`, and a DNS error gives `bimi=temperror` (earlier versions used `temperr`).

See [BIMI Result Reference](docs/bimi.md) for details on the result object structure.

#### Example

```javascript
const { authenticate } = require('mailauth');

const message = /* Your email message here */;

const { bimi } = await authenticate(message, {
  ip: '217.146.67.33',
  helo: 'uvn-67-33.tll01.zonevs.eu',
  mta: 'mx.ethereal.email',
  sender: 'andris@ekiri.ee',
  bimiWithAlignedDkim: false, // If true, ignores SPF in DMARC and requires a valid DKIM signature
});

if (bimi?.location) {
  console.log(`BIMI location: ${bimi.location}`);
}
```

**Note:**

- The `BIMI-Location` header is ignored by mailauth.
- The `BIMI-Selector` header can be used for selector selection if available. A selector that is not found at the author domain is looked up at the Organizational Domain, it does not fall back to `default`.

#### Verified Mark Certificate (VMC)

If an Authority Evidence Document is specified in the BIMI record, its location is available in `bimi.authority`. mailauth exposes the certificate type (`"VMC"` or `"CMC"`) in `bimi.authority.vmc.type`.

**Example Authority Evidence Documents:**

- [CNN's VMC](https://amplify.valimail.com/bimi/time-warner/LysAFUdG-Hw-cnn_vmc.pem)
- [Entrust's VMC](https://www.entrustdatacard.com/-/media/certificate/Entrust%20VMC%20July%2014%202020.pem)

### MTA-STS

mailauth provides functions to fetch and validate MTA-STS policies for a domain.

#### Policy Retrieval

Use the `getPolicy` function to fetch the MTA-STS policy for a domain.

##### Syntax

```javascript
const { getPolicy } = require('mailauth/lib/mta-sts');

const { policy, status, warnings } = await getPolicy(domain [, knownPolicy [, options]]);
// Returns an object with the policy and status
```

See [MTA-STS Result Reference](docs/mta-sts.md) for details on the result object structure.

##### Parameters

- **domain** (`string`): The domain to retrieve the policy for. An email address is also accepted.
- **knownPolicy** (`object`, optional): Previously cached policy for the domain, the `policy` value of an earlier result.
- **options** (`object`, optional):
    - **resolver** (`function`): Custom DNS resolver with the `dns.promises.resolve` signature.
    - **strict** (`boolean`, default `false`): Apply the RFC 8461 rules exactly (TXT record and policy syntax, HTTP 200 only, `text/plain` only, no CN fallback or partial wildcards in the policy host certificate, expired cached policies are not applied). In the default lax mode these are accepted and listed in `warnings`.
    - **timeout** (`number`, default `60000`): Overall time limit for the HTTPS policy request in milliseconds.
    - **maxPolicySize** (`number`, default `65536`): Maximum size of the policy file in bytes.

##### Example

```javascript
const { getPolicy } = require('mailauth/lib/mta-sts');

const knownPolicy = await cache.get('gmail.com'); // undefined if not cached
const { policy, status } = await getPolicy('gmail.com', knownPolicy);

// Always store the returned policy. If no live policy can be found, getPolicy returns
// the still valid cached policy, so a DNS or HTTPS failure does not erase it.
await cache.set('gmail.com', policy);

if (policy.mode === 'enforce') {
    // TLS must be used when sending to this domain
}
```

Keep cache entries at least until `policy.expires`. A cached policy that has not expired is used as long as the policy ID in DNS stays the same, and it is kept when the TXT record or the policy file can not be retrieved (RFC 8461 3.3 and 5.1).

**Possible Status Values:**

- `"found"`: A new or updated policy was fetched.
- `"renewed"`: The cached policy is still valid and its ID matches DNS; it is returned unchanged without fetching the policy file.
- `"not_found"`: No policy was found, and there is no valid cached policy.
- `"errored"`: No live policy could be discovered or fetched; `policy.error` holds the reason. `policy` is the valid cached policy if there is one, otherwise a policy with mode `"none"`.

#### MX Validation

Use the `validateMx` function to check if an MX hostname is valid according to the MTA-STS policy.

##### Syntax

```javascript
const { validateMx } = require('mailauth/lib/mta-sts');

const validation = validateMx(mx, policy [, options]);
// Returns an object indicating if the MX is valid
```

##### Parameters

- **mx** (`string`): The resolved MX hostname.
- **policy** (`object`): The MTA-STS policy object.
- **options** (`object`, optional): `{ strict }` is accepted for consistency; the matching rules are the same in both modes.

A wildcard pattern such as `*.example.com` matches exactly one left-most label (`mail.example.com`, but not `example.com` or `foo.bar.example.com`). `validateMx` does not check `policy.expires`.

##### Example

```javascript
const { getPolicy, validateMx } = require('mailauth/lib/mta-sts');

const { policy } = await getPolicy('gmail.com');

const mx = 'alt4.gmail-smtp-in.l.google.com';
const policyMatch = validateMx(mx, policy);

if (policy.mx && !policyMatch.valid) {
    // The MX host is not listed in the policy; do not connect
}
```

## Testing

mailauth uses the following test suites:

### SPF Test Suite

Based on the [OpenSPF test suite](http://www.openspf.org/Test_Suite). Every test is run in both modes:

- With `strict: true`, all tests pass, including the explanation (`exp`) results.
- In the default mode, 7 tests give a different result: syntax errors after the matching term are not detected, the `c`, `r` and `t` macros are accepted outside of explanation text, and a name that is invalid after macro expansion gives `permerror` instead of not matching.

### ARC Test Suite from ValiMail

Based on ValiMail's [arc_test_suite](https://github.com/ValiMail/arc_test_suite). Every test is run in both modes:

- With `strict: true`, all validation tests pass except two where the suite, written against the ARC drafts, disagrees with RFC 8617: an ARC-Message-Signature with an empty `h=` (RFC 6376 requires a non-empty `h=` that includes From, so mailauth fails it in both modes), and one without `c=` that was signed `relaxed/relaxed` (the RFC default is `simple/simple`).
- In the default mode, the four ARC-Seal tag syntax tests (duplicate tags, tag name case, an invalid tag name and an empty tag-spec) are accepted with a warning instead of failing, and the ARC-Message-Signature without `c=` passes through a `relaxed/relaxed` fallback.
- Signing test suite is used for input; mailauth validates signatures and checks for the same `cv=` output.

## License

&copy; 2020-2026 Postal Systems OÜ

Licensed under the [MIT License](LICENSE).
