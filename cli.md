![](https://github.com/postalsys/mailauth/raw/master/assets/mailauth.png)

Command line utility and a [Node.js library](README.md) for email authentication.

# CLI USAGE

## TOC

-   [Installation](#installation)
-   [Help](#help)
-   [Available commands](#available-commands)
    -   [report](#report) – to validate SPF, DKIM, DMARC, ARC
    -   [sign](#sign) - to sign an email with DKIM
    -   [seal](#seal) - to seal an email with ARC
    -   [spf](#spf) - to validate SPF for an IP address and an email address
    -   [vmc](#vmc) - to validate BIMI VMC logo files
    -   [license](#license) - display licenses for `mailauth` and included modules
-   [DNS cache file](#dns-cache-file)

## Installation

Download `mailauth` for your platform:

-   [MacOS](https://github.com/postalsys/mailauth/releases/latest/download/mailauth.pkg)
-   [Linux](https://github.com/postalsys/mailauth/releases/latest/download/mailauth.tar.gz)
-   [Windows](https://github.com/postalsys/mailauth/releases/latest/download/mailauth.exe)
-   Or install from the NPM registry: `npm install -g mailauth`

> **NB!** Downloadable files are quite large because these are packaged Node.js applications

Alternatively you can install `mailauth` from [npm](https://npmjs.com/package/mailauth).

```
npm install -g mailauth
```

## Help

```
$ mailauth --help
$ mailauth report --help
$ mailauth sign --help
$ mailauth seal --help
$ mailauth spf --help
```

## Available commands

### report

`report` command takes an email message and returns a JSON formatted report for SPF, DKIM, ARC, DMARC and BIMI. Not all reports might make sense for your use case, eg. SPF check for an outbound message usually gives no useful info, so you can ignore the parts you're not interested in.

```
$ mailauth report [options] [email]
```

Where

-   **options** are option flags and arguments
-   **email** is the path to EML formatted email message file. If not provided then email message is read from standard input

**Options**

-   `--client-ip x.x.x.x` or `-i x.x.x.x` is the IP of the remote client that sent the email. If not provided then it is parsed from the latest `Received` header
-   `--sender user@example.com` or `-f address` is the email address from the MAIL FROM command. If not provided then it is parsed from the latest Return-Path header
-   `--helo hostname` or `-e hostname` is the client hostname from the HELO/EHLO command. Used in some obscure SPF validation operations
-   `--mta hostname` or `-m hostname` is the server hostname doing the validation checks. Defaults to `os.hostname()`
-   `--dns-cache /path/to/dns.json` or `-n path` is the path to a file with cached DNS query responses. If this file is provided then no actual DNS requests are performed, only cached values from this file are used.
-   `--verbose` or `-v` if this flag is set then mailauth writes some debugging info to standard error
-   `--max-lookups nr` or `-x nr` defines the allowed DNS lookup limit for SPF checks. Defaults to 50.

**Example**

```
$ mailauth report --verbose --dns-cache examples/dns-cache.json test/fixtures/message2.eml
Reading email message from test/fixtures/message2.eml
DNS query for TXT mail.projectpending.com: not found
DNS query for TXT _dmarc.projectpending.com: not found
{
  "receivedChain": [
  ...
```

See full example for DKIM checks [here](https://gist.github.com/andris9/8d4ab527282041f6725a640d80da4872).

### sign

`sign` command takes an email message and signs it with a DKIM digital signature.

```
$ mailauth sign [options] [email]
```

Where

-   **options** are option flags and arguments
-   **email** is the path to EML formatted email message file. If not provided then email message is read from standard input

**Options**

-   `--private-key /path` or `-k /path` is the path to a private key for signing
-   `--domain example.com` or `-d example.com` is the domain name for signing (d= tag)
-   `--selector xxx` or `-s xxx` is the key selector name for signing (s= tag)
-   `--algo rsa-sha256` or `-a rsa-sha256` is the signing algorithm. Defaults either to "rsa-sha256" or
    "ed25519-sha256" depending on the private key format (a= tag)
-   `--canonicalization algo` or `-c algo` is the canonicalization algorithm, defaults to "relaxed/relaxed" (c= tag)
-   `--time 12345` or `-t 12345` is the signing time as a unix timestamp (t= tag)
-   `--header-fields "message-id:date"` or `-h keys` is a colon separated list of header field names to sign (h= tag)
-   `--body-length 12345` or `-l 12345` is the maximum length of canonicalizated body to sign (l= tag)
-   `--headers-only` or `-o` If set return signing headers only. Default is to return the entire message.

**Example**

```
$ mailauth sign /path/message.eml --domain kreata.ee --selector test --privateKey /path/private-rsa.pem --verbose
Reading email message from /path/message.eml
Signing domain:             kreata.ee
Key selector:               test
Canonicalization algorithm: relaxed/relaxed
Hashing algorithm:          rsa-sha256
Signing time:               2020-12-03T23:00:14.956Z
--------
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=kreata.ee;
 h=MIME-Version: Date: Message-ID: Subject: To: From: Content-Type;
 ...
```

### seal

`seal` command takes an email message and seals it with an ARC digital signature.

```
$ mailauth seal [options] [email]
```

Where

-   **options** are option flags and arguments
-   **email** is the path to EML formatted email message file. If not provided then email message is read from standard input

**Options**

As the emails needs to be authenticated before sealing then `seal` command expects in additon to sealing key information also the authentication options from the `report` command.

-   `--private-key /path` or `-k /path` is the path to a private key for sealing
-   `--domain example.com` or `-d example.com` is the domain name for sealing (d= tag)
-   `--selector xxx` or `-s xxx` is the key selector name for sealing (s= tag)
-   `--algo rsa-sha256` or `-a rsa-sha256` is the sealing algorithm. Defaults either to "rsa-sha256" or
    "ed25519-sha256" depending on the private key format (a= tag)
-   `--time 12345` or `-t 12345` is the sealing time as a unix timestamp (t= tag)
-   `--header-fields "message-id:date"` or `-h keys` is a colon separated list of header field names to seal (h= tag)
-   `--client-ip x.x.x.x` or `-i x.x.x.x` is the IP of the remote client that sent the email. If not provided then it is parsed from the latest `Received` header
-   `--sender user@example.com` or `-f address` is the email address from the MAIL FROM command. If not provided then it is parsed from the latest Return-Path header
-   `--helo hostname` or `-e hostname` is the client hostname from the HELO/EHLO command. Used in some obscure SPF validation operations
-   `--mta hostname` or `-m hostname` is the server hostname doing the validation checks. Defaults to `os.hostname()`
-   `--dns-cache /path/to/dns.json` or `-n path` is the path to a file with cached DNS query responses. If this file is provided then no actual DNS requests are performed, only cached values from this file are used.
-   `--headers-only` or `-o` If set return signing headers only. Default is to return the entire message.

> Canonicalization (c= tag) is always "relaxed/relaxed" when sealing, this can not be changed

**Example**

```
$ mailauth seal /path/message.eml --domain kreata.ee --selector test --privateKey /path/private-rsa.pem --verbose
Reading email message from /path/message.eml
Signing domain:             kreata.ee
Key selector:               test
Canonicalization algorithm: relaxed/relaxed
Hashing algorithm:          rsa-sha256
Signing time:               2020-12-03T23:04:41.082Z
--------
ARC-Seal: i=3; a=rsa-sha256; t=1607036681; cv=pass; d=kreata.ee; s=test;
 b=Fo3hayVos+J77lzzgmr6J92gsUBKlPt/ZkoQt9ZCi514zy8+1WLvTHmI8CMUXAcegdcqP0NHt
 ...
```

### spf

`spf` command takes an email address and an IP address and returns a JSON formatted SPF report.

```
$ mailauth spf [options]
```

Where

-   **options** are option flags and arguments

**Options**

-   `--sender user@example.com` or `-f address` is the email address from the MAIL FROM command. Required.
-   `--client-ip x.x.x.x` or `-i x.x.x.x` is the IP of the remote client that sent the email. Required.
-   `--helo hostname` or `-e hostname` is the client hostname from the HELO/EHLO command. Used in some obscure SPF validation operations
-   `--mta hostname` or `-m hostname` is the server hostname doing the validation checks. Defaults to `os.hostname()`. Used in authentication headers.
-   `--dns-cache /path/to/dns.json` or `-n path` is the path to a file with cached DNS query responses. If this file is provided then no actual DNS requests are performed, only cached values from this file are used.
-   `--verbose` or `-v` if this flag is set then mailauth writes some debugging info to standard error
-   `--headers-only` or `-o` If set return SPF authentication header only. Default is to return a JSON structure.
-   `--max-lookups nr` or `-x nr` defines the allowed DNS lookup limit for SPF checks. Defaults to 50.

**Example**

```
$ mailauth spf --verbose -f andris@wildduck.email -i 217.146.76.20
Checking SPF for andris@wildduck.email
Maximum DNS lookups: 50
--------
DNS query for TXT wildduck.email: [["v=spf1 mx a -all"]]
DNS query for MX wildduck.email: [{"exchange":"mail.wildduck.email","priority":1}]
DNS query for A mail.wildduck.email: ["217.146.76.20"]
{
  "domain": "wildduck.email",
  "client-ip": "217.146.76.20",
  ...
```

### vmc

`vmc` command takes either the URL for a VMC file or a file path or both. It then verifies if the VMC resource is a valid file or not and exposes its contents.

```
$ mailauth vmc [options]
```

Where

-   **options** are option flags and arguments

**Options**

-   `--authority <url>` or `-a <url>` is the URL for the VMC resource
-   `--authorityPath <path>` or `-p <path>` is the cached file for the authority URL to avoid network requests
-   `--domain <domain>` or `-d <domain>` is the sender domain to compare the certificate against

**Example**

```
$ mailauth vmc -a https://amplify.valimail.com/bimi/time-warner/yV3KRIg4nJW-cnn.pem -d cnn.com
{
  "url": "https://amplify.valimail.com/bimi/time-warner/yV3KRIg4nJW-cnn.pem",
  "success": true,
  "domainVerified": true,
  "vmc": {
    "mediaType": "image/svg+xml",
    "hashAlgo": "sha1",
    "hashValue": "ea8c81da633c66a16262134a78576cdf067638e9",
    "logoFile": "<2300B base64 encoded file>",
    "validHash": true,
    "certificate": {
      "subjectAltName": [
        "cnn.com"
      ],
      "subject": {
        "businessCategory": "Private Organization",
        "jurisdictionCountryName": "US",
        "jurisdictionStateOrProvinceName": "Delaware",
        "serialNumber": "2976730",
        "countryName": "US",
        "stateOrProvinceName": "Georgia",
        "localityName": "Atlanta",
        "street": "190 Marietta St NW",
        "organizationName": "Cable News Network, Inc.",
        "commonName": "Cable News Network, Inc.",
        "trademarkCountryOrRegionName": "US",
        "trademarkRegistration": "5817930"
      },
      "fingerprint": "17:B3:94:97:E6:6B:C8:6B:33:B8:0A:D2:F0:79:6B:08:A2:A6:84:BD",
      "serialNumber": "0821B8FE0A9CBC3BAC10DA08C088EEF4",
      "issuer": {
        "countryName": "US",
        "organizationName": "DigiCert, Inc.",
        "commonName": "DigiCert Verified Mark RSA4096 SHA256 2021 CA1"
      }
    }
  }
}
```

If the certificate verification fails, then the contents are not returned.

```
$ mailauth vmc -p /path/to/random/cert-bundle.pem
{
  "success": false,
  "error": {
    "message": "Self signed certificate in certificate chain",
    "details": {
      "subject": "CN=postal.vmc.local\nO=Postal Systems OU.\nC=EE",
      "fingerprint": "CC:49:83:ED:3F:6B:77:45:5B:A5:3B:9E:EC:99:0E:A1:EF:D7:FF:97",
      "fingerprint235": "D4:36:6F:B4:EF:2B:4F:9E:84:23:3D:F2:3A:F7:13:21:C6:C3:CF:CB:03:5F:BB:54:5B:69:A4:AC:6A:43:61:7D",
      "validFrom": "2022-07-10T06:28:06.482Z",
      "validTo": "2022-07-10T06:28:06.482Z"
    },
    "code": "SELF_SIGNED_CERT_IN_CHAIN"
  }
}
```

### license

Display licenses for `mailauth` and included modules.

```
$ mailauth licenses
```

## DNS cache file

In general you would use the `--dns-cache` option only when testing. This way you can provide different kind of DNS responses without actually setting up a DNS server and unlike when using real DNS you do not have to wait for the changes in the DNS server to propagate – whatever is in the provided cache file, is used for the DNS query responses.

DNS cache file includes a JSON encoded object where main keys are the domain names (eg. `"_dmarc.example.com"`), sub keys are resource record types (eg. `"TXT"`) and values are the corresponding values as provided by the [dns module](https://nodejs.org/api/dns.html#dns_dns_resolvetxt_hostname_callback).

```json
{
    "full_domain_name": {
        "TXT": [["string1"]]
    }
}
```

**Example**

This example provides SPF and DMARC policy records for "example.com":

```json
{
    "example.com": {
        "TXT": [["v=spf1 include:_spf.google.com include:sendgrid.net", " include:servers.mcsv.net include:servers.outfunnel.com ip4:18.194.223.2 ~all"]]
    },
    "_dmarc.example.com": {
        "TXT": [["v=DMARC1; p=reject; sp=reject;"]]
    }
}
```
