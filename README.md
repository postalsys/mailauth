# mailauth

Email authentication library for Node.js (work in progress)

-   [x] SPF verification
-   [x] DKIM signing
-   [x] DKIM verification
-   [ ] DMARC verification
-   [ ] ARC signing
-   [ ] ARC verification
-   [ ] MTA-STS resolver

## Setup

Install from dev channel

```
$ npm install mailauth@dev
```

## Authentication

```js
const { authenticate } = require('mailauth');
const { headers } = await authenticate(
    message, // either a String, a Buffer or a Readable Stream
    {
        ip: '217.146.67.33',
        helo: 'uvn-67-33.tll01.zonevs.eu',
        mta: 'mx.ethereal.email',
        sender: 'andris@ekiri.ee'
    }
);
// output authenticated message
process.stdout.write(headers); // includes terminating line break
process.stdout.write(message);
```

Example output:

```
Received-SPF: pass (mx.ethereal.email: domain of andris@ekiri.ee designates
 217.146.67.33 as permitted sender) client-ip=217.146.67.33;
Authentication-Results: mx.ethereal.email;
 dkim=pass header.i=@ekiri.ee header.s=default header.b="1VSEye1n"
 spf=pass (mx.ethereal.email: domain of andris@ekiri.ee designates
 217.146.67.33 as permitted sender) smtp.mailfrom=andris@ekiri.ee;
From: ...
```

## DKIM

### Signing

```js
const { dkimSign } = require('mailauth/lib/dkim/sign');
const signatures = await dkimSign(
    message, // either a String, a Buffer or a Readable Stream
    {
        algorithm: 'rsa-sha256', // a=
        canonicalization: 'relaxed/relaxed', // c=
        signTime: new Date(), // t=

        signatureData: [
            {
                signingDomain: 'tahvel.info', // d=
                selector: 'test.rsa', // s=
                privateKey: fs.readFileSync('./test/fixtures/private-rsa.pem')
            }
        ]
    }
); // -> {String} signature headers using \r\n as the line separator
// output signed message
process.stdout.write(signatures); // includes terminating line break
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
dkim=policy (weak key) header.i=@tahvel.info header.s=test.small header.b="d0jjgPun"
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

**MIT**
