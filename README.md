# mailauth

Email authentication library for Node.js (work in progress)

-   [x] SPF verification
-   [x] DKIM signing
-   [x] DKIM verification
-   [x] DMARC verification
-   [x] ARC verification
-   [ ] ARC sealing
-   [ ] MTA-STS resolver

## Setup

### Free, AGPL-licensed version

First install the module from npm:

```
$ npm install mailauth
```

next import any method you want to use from mailauth package into your script:

```js
const { authenticate } = require('mailauth');
```

### MIT version

MIT-licensed version is available for [Postal Systems subscribers](https://postalsys.com/).

First install the module from Postal Systems private registry:

```
$ npm install @postalsys/mailauth
```

next import any method you want to use from mailauth package into your script:

```js
const { authenticate } = require('@postalsys/mailauth');
```

If you have already built your application using the free version of "mailauth" and do not want to modify require statements in your code, you can install the MIT-licensed version as an alias for "mailauth".

```
$ npm install mailauth@npm:@postalsys/mailauth
```

This way you can keep using the old module name

```js
const { authenticate } = require('mailauth');
```

## Usage

## Authentication

Validate DKIM signatures, SPF, DMARC and ARC for an email.

```js
const { authenticate } = require('mailauth');
const { headers } = await authenticate(
    message, // either a String, a Buffer or a Readable Stream
    {
        // SMTP transmission options must be provided as
        // these are not parsed from the message
        ip: '217.146.67.33', // SMTP client IP
        helo: 'uvn-67-33.tll01.zonevs.eu', // EHLO/HELO hostname
        mta: 'mx.ethereal.email', // server processing this message, defaults to os.hostname()
        sender: 'andris@ekiri.ee' // MAIL FROM address
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

## DKIM

### Signing

```js
const { dkimSign } = require('mailauth/lib/dkim/sign');
const signResult = await dkimSign(
    message, // either a String, a Buffer or a Readable Stream
    {
        // optional canonicalization, default is "relaxed/relaxed"
        // this option applies to all signatures, so you can't create multiple signatures
        // that use different canonicalization
        canonicalization: 'relaxed/relaxed', // c=

        // optional, default is current time
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
                // Mostly useful when you want to use rsa-sha1, otherwise no need to set
                algorithm: 'rsa-sha256'
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

## License

&copy; 2020 Andris Reinman

Licensed under GNU Affero General Public License v3.0 or later.

MIT-licensed version of mailauth is available for [Postal Systems subscribers](https://postalsys.com/).
