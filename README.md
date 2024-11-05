# mailauth: Email Authentication for Node.js

![mailauth Logo](https://github.com/postalsys/mailauth/raw/master/assets/mailauth.png)

**mailauth** is a comprehensive Node.js library and command-line utility for email authentication. It provides tools to work with various email security protocols, including SPF, DKIM, DMARC, ARC, BIMI, and MTA-STS. With mailauth, you can verify and sign emails, handle authentication results, and enhance your email security setup.

**Key Features:**

-   **SPF** verification
-   **DKIM** signing and verification
-   **DMARC** verification
-   **ARC** verification and sealing
    -   Sealing during authentication
    -   Sealing after message modifications
-   **BIMI** resolving and **VMC** validation
-   **MTA-STS** helper functions

mailauth is a pure JavaScript implementation, requiring no external applications or compilation. It runs on any server or device with Node.js version 16 or later.

## Table of Contents

1. [Installation](#installation)
2. [Command-Line Usage](#command-line-usage)
3. [Library Usage](#library-usage)
    - [Authentication](#authentication)
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
// Returns: { dkim, spf, arc, dmarc, bimi, receivedChain, headers }
```

#### Parameters

-   **message**: A `String`, `Buffer`, or `Readable` stream representing the email message.
-   **options** (optional):
    -   **sender** (`string`): Email address from the MAIL FROM command. Defaults to the `Return-Path` header if not set.
    -   **ip** (`string`): IP address of the remote client that sent the message.
    -   **helo** (`string`): Hostname from the HELO/EHLO command.
    -   **trustReceived** (`boolean`): If `true`, parses `ip` and `helo` from the latest `Received` header if not provided. Defaults to `false`.
    -   **mta** (`string`): Hostname of the server performing the authentication. Defaults to `os.hostname()`. Included in Authentication headers.
    -   **minBitLength** (`number`): Minimum allowed bits for RSA public keys. Defaults to `1024`. Keys with fewer bits will fail validation.
    -   **disableArc** (`boolean`): If `true`, skips ARC checks.
    -   **disableDmarc** (`boolean`): If `true`, skips DMARC checks, also disabling dependent checks like BIMI.
    -   **disableBimi** (`boolean`): If `true`, skips BIMI checks.
    -   **seal** (`object`): Options for ARC sealing if the message doesn't have a broken ARC chain.
        -   **signingDomain** (`string`): ARC key domain name.
        -   **selector** (`string`): ARC key selector.
        -   **privateKey** (`string` or `Buffer`): Private key for signing (RSA or Ed25519).
    -   **resolver** (`async function`): Custom DNS resolver function. Defaults to [`dns.promises.resolve`](https://nodejs.org/api/dns.html#dns_dnspromises_resolve_hostname_rrtype).
    -   **maxResolveCount** (`number`): DNS lookup limit for SPF. Defaults to `10` as per [RFC7208](https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4).
    -   **maxVoidCount** (`number`): DNS lookup limit for SPF producing empty results. Defaults to `2` as per [RFC7208](https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4).

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

### DKIM

#### DKIM Signing

Use the `dkimSign` function to sign an email message with DKIM.

##### Syntax

```javascript
const { dkimSign } = require('mailauth/lib/dkim/sign');

const signResult = await dkimSign(message, options);
// Returns: { signatures: String, errors: Array }
```

##### Parameters

-   **message**: A `String`, `Buffer`, or `Readable` stream representing the email message.
-   **options**:
    -   **canonicalization** (`string`): Canonicalization method. Defaults to `'relaxed/relaxed'`.
    -   **algorithm** (`string`): Signing and hashing algorithm. Defaults to `'rsa-sha256'`.
    -   **signTime** (`Date`): Signing time. Defaults to current time.
    -   **signatureData** (`Array`): Array of signature objects. Each object may contain:
        -   **signingDomain** (`string`): DKIM key domain name.
        -   **selector** (`string`): DKIM key selector.
        -   **privateKey** (`string` or `Buffer`): Private key for signing (RSA or Ed25519).
        -   **algorithm** (`string`, optional): Overrides parent `algorithm`.
        -   **canonicalization** (`string`, optional): Overrides parent `canonicalization`.
        -   **maxBodyLength** (`number`, optional): Maximum number of canonicalized body bytes to sign (`l=` tag). Not recommended for general use.

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

#### DKIM Verification

Use the `dkimVerify` function to verify DKIM signatures in an email message.

##### Syntax

```javascript
const { dkimVerify } = require('mailauth/lib/dkim/verify');

const result = await dkimVerify(message);
// Returns an object containing verification results
```

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

##### Parameters

-   **options**:
    -   **sender** (`string`): MAIL FROM address.
    -   **ip** (`string`): SMTP client IP.
    -   **helo** (`string`): HELO/EHLO hostname.
    -   **mta** (`string`): Hostname of the MTA performing the check.

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
Received-SPF: pass (mx.myhost.com: domain of andris@wildduck.email
 designates 217.146.76.20 as permitted sender) client-ip=217.146.76.20;
 envelope-from="andris@wildduck.email";
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

// Output the sealed message
process.stdout.write(sealHeaders); // ARC headers
process.stdout.write(headers);     // Authentication results
process.stdout.write(message);
```

### DMARC

DMARC is verified during the authentication process. Although the `dmarc` handler is exported, it requires input from previous steps like SPF and DKIM.

#### DMARC Helpers

##### `getDmarcRecord(domain [, resolver])`

Fetches and parses the DMARC DNS record for a domain or subdomain. Returns `false` if no record exists.

###### Syntax

```javascript
const getDmarcRecord = require('mailauth/lib/dmarc/get-dmarc-record');

const dmarcRecord = await getDmarcRecord(domain [, resolver]);
// Returns an object with DMARC record details or `false` if not found
```

###### Parameters

-   **domain** (`string`): The domain to check for a DMARC record.
-   **resolver** (`function`, optional): Custom DNS resolver function. Defaults to `dns.resolve`.

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
    "isOrgRecord": false
}
```

### BIMI

Brand Indicators for Message Identification (BIMI) support is based on [draft-blank-ietf-bimi-02](https://tools.ietf.org/html/draft-blank-ietf-bimi-02). BIMI information is resolved during the authentication step, provided the message passes DMARC validation with a policy other than "none".

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

-   The `BIMI-Location` header is ignored by mailauth.
-   The `BIMI-Selector` header can be used for selector selection if available.

#### Verified Mark Certificate (VMC)

If an Authority Evidence Document is specified in the BIMI record, its location is available in `bimi.authority`. mailauth exposes the certificate type (`"VMC"` or `"CMC"`) in `bimi.authority.vmc.type`.

**Example Authority Evidence Documents:**

-   [CNN's VMC](https://amplify.valimail.com/bimi/time-warner/LysAFUdG-Hw-cnn_vmc.pem)
-   [Entrust's VMC](https://www.entrustdatacard.com/-/media/certificate/Entrust%20VMC%20July%2014%202020.pem)

### MTA-STS

mailauth provides functions to fetch and validate MTA-STS policies for a domain.

#### Policy Retrieval

Use the `getPolicy` function to fetch the MTA-STS policy for a domain.

##### Syntax

```javascript
const { getPolicy } = require('mailauth/lib/mta-sts');

const { policy, status } = await getPolicy(domain [, knownPolicy]);
// Returns an object with the policy and status
```

##### Parameters

-   **domain** (`string`): The domain to retrieve the policy for.
-   **knownPolicy** (`object`, optional): Previously cached policy for the domain.

##### Example

```javascript
const { getPolicy } = require('mailauth/lib/mta-sts');

const knownPolicy = /* Retrieve from your cache if available */;
const { policy, status } = await getPolicy('gmail.com', knownPolicy);

if (policy.id !== knownPolicy?.id) {
  // Update your cache with the new policy
}

if (policy.mode === 'enforce') {
  // TLS must be used when sending to this domain
}
```

**Possible Status Values:**

-   `"not_found"`: No policy was found.
-   `"cached"`: Existing policy is still valid.
-   `"found"`: New or updated policy found.
-   `"renew"`: Existing policy is valid; renew cache.
-   `"errored"`: Policy discovery failed due to a temporary error.

#### MX Validation

Use the `validateMx` function to check if an MX hostname is valid according to the MTA-STS policy.

##### Syntax

```javascript
const { validateMx } = require('mailauth/lib/mta-sts');

const validation = validateMx(mx, policy);
// Returns an object indicating if the MX is valid
```

##### Parameters

-   **mx** (`string`): The resolved MX hostname.
-   **policy** (`object`): The MTA-STS policy object.

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

Based on the [OpenSPF test suite](http://www.openspf.org/Test_Suite), with some differences:

-   Less strict whitespace checks.
-   Some macro tests are skipped.
-   Some tests are skipped where the invalid component is after a matching part.
-   All other tests pass.

### ARC Test Suite from ValiMail

Based on ValiMail's [arc_test_suite](https://github.com/ValiMail/arc_test_suite):

-   mailauth is less strict on header tags and casing.
-   Signing test suite is used for input; mailauth validates signatures and checks for the same `cv=` output.
-   All tests pass, aside from minor differences.

## License

&copy; 2020-2024 Postal Systems OÜ

Licensed under the [MIT License](LICENSE).
