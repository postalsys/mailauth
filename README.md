![](https://github.com/postalsys/mailauth/raw/master/assets/mailauth.png)

[Command line utility](cli.md) and a Node.js library for email authentication.

-   **SPF** verification
-   **DKIM** signing
-   DKIM verification
-   **DMARC** verification
-   **ARC** verification
-   ARC sealing
    -   Sealing on authentication
    -   Sealing after modifications
-   **BIMI** resolving and **VMC** validation
-   **MTA-STS** helpers

Pure JavaScript implementation, no external applications or compilation needed. It runs on any server/device that has Node 16+ installed.

## Command line usage

See [command line documentation](cli.md) for the `mailauth` command.

## Library Usage

## Authentication

Validate DKIM signatures, SPF, DMARC, ARC, and BIMI for an email.

```js
await authenticate(message [,options]) ->
    { dkim, spf, arc, dmarc, bimi, receivedChain, headers }
```

Where

-   **message** is either a String, a Buffer, or a Readable stream that represents an email message
-   **options** (_object_) is an optional options object
    -   **sender** (_string_) is the email address from MAIL FROM command. If not set, then it is parsed from the `Return-Path` header
    -   **ip** (_string_) is the IP of the remote client that sent this message
    -   **helo** (_string_) is the hostname value from HELO/EHLO command
    -   **trustReceived** (_boolean_) if true, then parses values for `ip` and `helo` from the latest `Received` header if you have not set these values yourself. Defaults to `false`.
    -   **mta** (_string_) is the hostname of the server performing the authentication (defaults to `os.hostname()`)
    -   **minBitLength** (_number_) is the minimum allowed bits of RSA public keys (defaults to 1024). If a DKIM or ARC key has fewer bits, then validation is considered as failed
    -   **disableArc** (_boolean_) if true then skip ARC checks
    -   **disableDmarc** (_boolean_) if true then skip DMARC checks. It also disables checks that are dependent on DMARC (e.g., BIMI)
    -   **disableBimi** (_boolean_) if true, then skip BIMI checks
    -   **seal** (_object_) if set and message does not have a broken ARC chain, then seals the message using these values
        -   **signingDomain** (_string_) ARC key domain name
        -   **selector** (_string_) ARC key selector
        -   **privateKey** (_string_ or _buffer_) Private key for signing. Either an RSA or an Ed25519 key
    -   **resolver** (_async function_) is an optional async function for DNS requests. Defaults to [dns.promises.resolve](https://nodejs.org/api/dns.html#dns_dnspromises_resolve_hostname_rrtype)
    -   **maxResolveCount** (_number_ defaults to _10_) is the DNS lookup limit for SPF. [RFC7208](https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4) requires this limit to be 10.
    -   **maxVoidCount** (_number_ defaults to _2_) is the DNS lookup limit for SPF that produce an empty result. [RFC7208](https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4) requires this limit to be 2.

**Example**

```js
const { authenticate } = require('mailauth');
const { dkim, spf, arc, dmarc, bimi, receivedChain, headers } = await authenticate(
    message, // either a String, a Buffer or a Readable Stream
    {
        // SMTP transmission options if available
        ip: '217.146.67.33', // SMTP client IP
        helo: 'uvn-67-33.tll01.zonevs.eu', // EHLO/HELO hostname
        sender: 'andris@ekiri.ee', // MAIL FROM address

        // Uncomment if you do not want to provide ip/helo/sender manually but parse from the message
        //trustReceived: true,

        // Server processing this message, defaults to os.hostname(). Inserted into Authentication headers
        mta: 'mx.ethereal.email',

        //  Optional  DNS resolver function (defaults to `dns.promises.resolve`)
        resolver: async (name, rr) => await dns.promises.resolve(name, rr)
    }
);
// output authenticated message
process.stdout.write(headers); // includes terminating line break
process.stdout.write(message);
```

Example output:

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

You can see the full output (structured data for DKIM, SPF, DMARC, and ARC) from [this example](https://gist.github.com/andris9/6514b5e7c59154a5b08636f99052ce37).

### receivedChain

`receivedChain` property is an array of parsed representations of the `Received:` headers.

## DKIM

### Signing

```js
const { dkimSign } = require('mailauth/lib/dkim/sign');
const signResult = await dkimSign(
    message, // either a String, a Buffer or a Readable Stream
    {
        // Optional, default canonicalization, default is "relaxed/relaxed"
        canonicalization: 'relaxed/relaxed', // c=

        // Optional, default signing and hashing algorithm
        // Mostly useful when you want to use rsa-sha1, otherwise no need to set
        algorithm: 'rsa-sha256',

        // Optional, default is current time
        signTime: new Date(), // t=

        // Keys for one or more signatures
        // Different signatures can use different algorithms (mostly useful when
        // you want to sign a message both with RSA and Ed25519)
        signatureData: [
            {
                signingDomain: 'tahvel.info', // d=
                selector: 'test.rsa', // s=
                // supported key types: RSA, Ed25519
                privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem'),

                // Optional algorithm, default is derived from the key.
                // Overrides whatever was set in parent object
                algorithm: 'rsa-sha256',

                // Optional signature specifc canonicalization, overrides whatever was set in parent object
                canonicalization: 'relaxed/relaxed' // c=

                // Maximum number of canonicalized body bytes to sign (eg. the "l=" tag).
                // Do not use though. This is available only for compatibility testing.
                // maxBodyLength: 12345
            }
        ]
    }
); // -> {signatures: String, errors: Array} signature headers using \r\n as the line separator
// show signing errors (if any)
if (signResult.errors.length) {
    console.log(signResult.errors);
}
// output signed message
process.stdout.write(signResult.signatures); // includes terminating line break
process.stdout.write(message);
```

Example output:

```
DKIM-Signature: a=rsa-sha256; v=1; c=relaxed/relaxed; d=tahvel.info;
 s=test.rsa; b=...
From: ...
```

### Verifying

```js
const { dkimVerify } = require('mailauth/lib/dkim/verify');
// `message` is either a String, a Buffer or a Readable Stream
const result = await dkimVerify(message);
for (let { info } of result.results) {
    console.log(info);
}
```

Example output:

```txt
dkim=neutral (invalid public key) header.i=@tahvel.info header.s=test.invalid header.b="b85yao+1"
dkim=pass header.i=@tahvel.info header.s=test.rsa header.b="BrEgDN4A"
dkim=policy policy.dkim-rules=weak-key header.i=@tahvel.info header.s=test.small header.b="d0jjgPun"
```

## SPF

### Verifying

```js
const { spf } = require('mailauth/lib/spf');

let result = await spf({
    sender: 'andris@wildduck.email',
    ip: '217.146.76.20',
    helo: 'foo',
    mta: 'mx.myhost.com'
});
console.log(result.header);
```

Example output:

```txt
Received-SPF: pass (mx.myhost.com: domain of andris@wildduck.email
 designates 217.146.76.20 as permitted sender) client-ip=217.146.76.20;
 envelope-from="andris@wildduck.email";
```

## ARC

### Validation

ARC seals are automatically validated during the authentication step.

```js
const { authenticate } = require('mailauth');
const { arc } = await authenticate(
    message, // either a String, a Buffer or a Readable Stream
    {
        trustReceived: true
    }
);
console.log(arc);
```

The output is something like this:

```
{
  "status": {
    "result": "pass",
    "comment": "i=2 spf=neutral dkim=pass dkdomain=zonevs.eu dkim=pass dkdomain=srs3.zonevs.eu dmarc=fail fromdomain=zone.ee"
  },
  "i": 2,
  ...
}
```

### Sealing

#### During authentication

You can seal messages with ARC automatically in the authentication step by providing the sealing key. In this case, you can not modify the message any more as this would break the seal.

```js
const { authenticate } = require('mailauth');
const { headers } = await authenticate(
    message, // either a String, a Buffer or a Readable Stream
    {
        trustReceived: true,

        // ARC seal settings. If this is set then resulting headers include
        // a complete ARC header set (unless the message has a failing ARC chain)
        seal: {
            signingDomain: 'tahvel.info',
            selector: 'test.rsa',
            privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
        }
    }
);
// output authenticated and sealed message
process.stdout.write(headers); // includes terminating line break
process.stdout.write(message);
```

#### After modifications

If you want to modify the message before sealing, you have to authenticate the message first and then use authentication results as input for the sealing step.

```js
const { authenticate, sealMessage } = require('mailauth');

// 1. authenticate the message
const { arc, headers } = await authenticate(
    message, // either a String, a Buffer or a Readable Stream
    {
        ip: '217.146.67.33', // SMTP client IP
        helo: 'uvn-67-33.tll01.zonevs.eu', // EHLO/HELO hostname
        mta: 'mx.ethereal.email', // server processing this message, defaults to os.hostname()
        sender: 'andris@ekiri.ee' // MAIL FROM address
    }
);

// 2. perform some modifications with the message ...

// 3. seal the modified message using the initial authentication results
const sealHeaders = await sealMessage(message, {
    signingDomain: 'tahvel.info',
    selector: 'test.rsa',
    privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem'),

    // values from the authentication step
    authResults: arc.authResults,
    cv: arc.status.result
});

// output authenticated message
process.stdout.write(sealHeaders); // ARC set
process.stdout.write(headers); // authentication results
process.stdout.write(message);
```

## DMARC

DMARC is verified as part of the authentication process and even as the `dmarc` handler is exported, it requires input from previous steps.

### Helpers

#### getDmarcRecord(domain [,resolver])

Returns parsed DMARC DNS record for a domain or a subdomain or `false` is no record exists.

```
const getDmarcRecord = require('mailauth/lib/dmarc/get-dmarc-record');
const dmarcRecord = await getDmarcRecord("ethereal.email");
console.log(dmarcRecord);
```

**Output**

```
{
  v: 'DMARC1',
  p: 'none',
  pct: 100,
  rua: 'mailto:re+joqy8fpatm3@dmarc.postmarkapp.com',
  sp: 'none',
  aspf: 'r',
  rr: 'v=DMARC1; p=none; pct=100; rua=mailto:re+joqy8fpatm3@dmarc.postmarkapp.com; sp=none; aspf=r;',
  isOrgRecord: false
}
```

`isOrgRecord` is `true` for sudomains, where organizational domain's DMARC policy applies, so use the `sp`, not `p` policy.

Optionally set `resolver` argument with custom resolver (uses `dns.resolve` by default).

## BIMI

Brand Indicators for Message Identification (BIMI) support is based on [draft-blank-ietf-bimi-01](https://tools.ietf.org/html/draft-blank-ietf-bimi-01).

BIMI information is resolved in the authentication step, and the results can be found from the `bimi` property. The message must pass DMARC validation to be processed for BIMI. DMARC policy can not be "none" for BIMI to pass.

```js
const { bimi } = await authenticate(
    message, // either a String, a Buffer or a Readable Stream
    {
        ip: '217.146.67.33', // SMTP client IP
        helo: 'uvn-67-33.tll01.zonevs.eu', // EHLO/HELO hostname
        mta: 'mx.ethereal.email', // server processing this message, defaults to os.hostname()
        sender: 'andris@ekiri.ee' // MAIL FROM address
    }
);
if (bimi?.location) {
    console.log(`BIMI location: ${bimi.location}`);
}
```

`BIMI-Location` header is ignored by `mailauth`, it is not checked for, and it is not modified in any way if it is present. `BIMI-Selector` is used for selector selection (if available).

### Verified Mark Certificate

Authority Evidence Document location is available from the `bimi.authority` property (if set).

VMC (Verified Mark Certificates) for Authority Evidence Documents is a X509 certificate with an `id-pe-logotype` extension (`oid=1.3.6.1.5.5.7.1.12`) that includes a compressed SVG formatted logo file ([read more here](https://bimigroup.org/resources/VMC_Guidelines_latest.pdf)).

Some example authority evidence documents:

-   [from default.\_bimi.cnn.com](https://amplify.valimail.com/bimi/time-warner/LysAFUdG-Hw-cnn_vmc.pem)
-   [from default.\_bimi.entrustdatacard.com](https://www.entrustdatacard.com/-/media/certificate/Entrust%20VMC%20July%2014%202020.pem)

## MTA-STS

`mailauth` allows you to fetch MTA-STS information for a domain name.

```js
const { getPolicy, validateMx } = require('mailauth/lib/mta-sts');

let knownPolicy = getCachedPolicy('gmail.com'); // optional
let mx = 'alt4.gmail-smtp-in.l.google.com';

const { policy, status } = await getPolicy('gmail.com', knownPolicy);
const policyMatch = validateMx(mx, policy);

if (policy.id !== knownPolicy?.id) {
    // policy has been updated, update cache
}

if (policy.mode === 'enforce') {
    // must use TLS
}

if (policy.mx && !policyMatch) {
    // can't connect, unlisted MX
}
```

### Resolve policy

Resolve MTA-STS policy for a domain

```
async getPolicy(domain [,knownPolicy]) -> {policy, status}
```

Where

-   **domain** is the domain to check for (e.g. "gmail.com")
-   **knownPolicy** (optional) is the policy object from the last check for this domain. This is used to check if the policy is still valid or it was updated.

The function returns an object with the following properties:

-   **policy** (object)
    -   **id** (string or `false`) ID of the policy
    -   **mode** (string) one of _"none"_, _"testing"_ or _"enforce"_
    -   **mx** (array, if available) an Array of whitelisted MX hostnames
    -   **expires** (string, if available) ISO date string for cacheing
-   **status** (string) one of the following values:
    -   _"not_found"_ no policy was found for this domain. You can decide yourself how long you want to cache this response
    -   _"cached"_ no changes detected, current policy is still valid and can be used
    -   _"found"_ new or updated policy was found. Cache this in your system until _policy.expires_
    -   _"renew"_ existing policy is still valid, renew cached version until _policy.expires_
    -   _"errored"_ policy discovery failed for some temporary error (e.g., failing DNS queries). See _policy.error_ for details

### Validate MX hostname

Check if a resolved MX hostname is valid by MTA-STS policy or not.

```
validateMx(mx, policy) -> Boolean
```

Where

-   **mx** is the resolved MX hostname (eg. "gmail-smtp-in.l.google.com")
-   **policy** is the policy object returned by `getPolicy()`

The function returns a boolean. If it is `true`, then MX hostname is allowed to use.

## Testing

`mailauth` uses the following test suites:

### SPF test suite

[OpenSPF test suite](http://www.openspf.org/Test_Suite) ([archive.org mirror](https://web.archive.org/web/20190130131432/http://www.openspf.org/Test_Suite)) with the following differences:

-   Less strict whitespace checks (`mailauth` accepts multiple spaces between tags etc.)
-   Some macro tests are skipped (macro expansion is supported _in most parts_)
-   Some tests where the invalid component is listed after a matching part (mailauth processes from left to right and returns on the first match found)
-   Other than that, all tests pass

### ARC test suite from ValiMail

ValiMail [arc_test_suite](https://github.com/ValiMail/arc_test_suite)

-   `mailauth` is less strict on header tags and casing. For example, uppercase `S=` for a selector passes in `mailauth` but fails in ValiMail.
-   Signing test suite is used for input only. All listed messages are signed using provided keys, but signatures are not matched against the reference. Instead, `mailauth` validates the signatures itself and looks for the same cv= output that the ARC-Seal header in the test suite has
-   Other than that, all tests pass

## Setup

First, install the module from npm:

```
$ npm install mailauth
```

next import any method you want to use from mailauth package into your script:

```js
const { authenticate } = require('mailauth');
```

## License

&copy; 2020-2022 Postal Systems OÜ

Licensed under MIT license
