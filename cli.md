# mailauth CLI Usage

![mailauth Logo](https://github.com/postalsys/mailauth/raw/master/assets/mailauth.png)

mailauth provides a command-line utility for email authentication, complementing its [Node.js library](README.md). This guide explains how to use the mailauth CLI to perform various email authentication tasks.

## Table of Contents

-   [Installation](#installation)
-   [Getting Help](#getting-help)
-   [Available Commands](#available-commands)
    -   [`report`](#report) &mdash; Validate SPF, DKIM, DMARC, ARC, and BIMI
    -   [`sign`](#sign) &mdash; Sign an email with DKIM
    -   [`seal`](#seal) &mdash; Seal an email with ARC
    -   [`spf`](#spf) &mdash; Validate SPF for an IP address and email address
    -   [`vmc`](#vmc) &mdash; Validate BIMI VMC logo files
    -   [`bodyhash`](#bodyhash) &mdash; Generate the body hash value for an email
    -   [`license`](#license) &mdash; Display licenses for mailauth and included modules
-   [DNS Cache File](#dns-cache-file)
-   [License](#license)

## Installation

Install the mailauth CLI by downloading the appropriate package for your platform or via npm:

-   **MacOS:**
    -   [Intel processors](https://github.com/postalsys/mailauth/releases/latest/download/mailauth.pkg)
    -   [Apple silicon](https://github.com/postalsys/mailauth/releases/latest/download/mailauth-arm.pkg)
-   **Linux:**
    -   [Download mailauth.tar.gz](https://github.com/postalsys/mailauth/releases/latest/download/mailauth.tar.gz)
-   **Windows:**
    -   [Download mailauth.exe](https://github.com/postalsys/mailauth/releases/latest/download/mailauth.exe)
-   **NPM Registry:**

    -   Install globally using npm:

        ```bash
        npm install -g mailauth
        ```

## Getting Help

To display help information for the mailauth CLI or any specific command, use the `--help` flag:

```bash
mailauth --help
mailauth report --help
mailauth sign --help
mailauth seal --help
mailauth spf --help
```

## Available Commands

The mailauth CLI offers several commands to perform different email authentication tasks:

1. [`report`](#report) &mdash; Validate SPF, DKIM, DMARC, ARC, and BIMI.
2. [`sign`](#sign) &mdash; Sign an email with DKIM.
3. [`seal`](#seal) &mdash; Seal an email with ARC.
4. [`spf`](#spf) &mdash; Validate SPF for an IP address and email address.
5. [`vmc`](#vmc) &mdash; Validate BIMI VMC logo files.
6. [`bodyhash`](#bodyhash) &mdash; Generate the body hash value for an email.
7. [`license`](#license) &mdash; Display licenses for mailauth and included modules.

### report

The `report` command analyzes an email message and returns a JSON-formatted report detailing the results of SPF, DKIM, DMARC, ARC, and BIMI validations.

#### Usage

```bash
mailauth report [options] [email]
```

-   **email**: (Optional) Path to the EML-formatted email message file. If omitted, the email is read from standard input.

#### Options

-   `--client-ip x.x.x.x`, `-i x.x.x.x`: IP address of the remote client that sent the email. If not provided, it's parsed from the latest `Received` header.
-   `--sender user@example.com`, `-f user@example.com`: Email address from the MAIL FROM command. If not provided, it's parsed from the latest `Return-Path` header.
-   `--helo hostname`, `-e hostname`: Hostname from the HELO/EHLO command. Used in some SPF validations.
-   `--mta hostname`, `-m hostname`: Hostname of the server performing validations. Defaults to the local hostname.
-   `--dns-cache /path/to/dns.json`, `-n /path/to/dns.json`: Path to a DNS cache file. When provided, DNS queries use cached responses.
-   `--verbose`, `-v`: Enables verbose output, displaying debugging information.
-   `--max-lookups number`, `-x number`: Sets the maximum number of DNS lookups for SPF checks. Defaults to `10`.
-   `--max-void-lookups number`, `-z number`: Sets the maximum number of void DNS lookups for SPF checks. Defaults to `2`.

#### Example

```bash
mailauth report --verbose --dns-cache examples/dns-cache.json test/fixtures/message2.eml
```

**Sample Output:**

```
Reading email message from test/fixtures/message2.eml
DNS query for TXT mail.projectpending.com: not found
DNS query for TXT _dmarc.projectpending.com: not found
{
  "receivedChain": [
    "..."
  ]
}
```

For a detailed example of DKIM checks, refer to [this gist](https://gist.github.com/andris9/8d4ab527282041f6725a640d80da4872).

### sign

The `sign` command signs an email message using a DKIM signature.

#### Usage

```bash
mailauth sign [options] [email]
```

-   **email**: (Optional) Path to the EML-formatted email message file. If omitted, the email is read from standard input.

#### Options

-   `--private-key /path/to/private.key`, `-k /path/to/private.key`: Path to the private key used for signing.
-   `--domain example.com`, `-d example.com`: Domain name for the DKIM signature (`d=` tag).
-   `--selector selector`, `-s selector`: Selector for the DKIM key (`s=` tag).
-   `--algo algorithm`, `-a algorithm`: Signing algorithm (e.g., `rsa-sha256`). Defaults based on the private key type.
-   `--canonicalization method`, `-c method`: Canonicalization method (e.g., `relaxed/relaxed`). Defaults to `relaxed/relaxed`.
-   `--time timestamp`, `-t timestamp`: Signing time as a Unix timestamp (`t=` tag).
-   `--header-fields "field1:field2"`, `-h "field1:field2"`: Colon-separated list of header fields to include in the signature (`h=` tag).
-   `--body-length length`, `-l length`: Maximum length of the body to include in the signature (`l=` tag).
-   `--headers-only`, `-o`: Outputs only the DKIM signature headers without the entire message.

#### Example

```bash
mailauth sign /path/to/message.eml --domain example.com --selector s1 --private-key /path/to/private.key --verbose
```

**Sample Output:**

```
Reading email message from /path/to/message.eml
Signing domain:             example.com
Key selector:               s1
Canonicalization algorithm: relaxed/relaxed
Hashing algorithm:          rsa-sha256
Signing time:               2023-03-15T12:00:00.000Z
--------
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;
 h=MIME-Version:Date:Message-ID:Subject:To:From:Content-Type;
 ...
```

### seal

The `seal` command adds an ARC (Authenticated Received Chain) seal to an email message.

#### Usage

```bash
mailauth seal [options] [email]
```

-   **email**: (Optional) Path to the EML-formatted email message file. If omitted, the email is read from standard input.

#### Options

**Sealing Options:**

-   `--private-key /path/to/private.key`, `-k /path/to/private.key`: Path to the private key used for sealing.
-   `--domain example.com`, `-d example.com`: Domain name for the ARC seal (`d=` tag).
-   `--selector selector`, `-s selector`: Selector for the ARC key (`s=` tag).
-   `--algo algorithm`, `-a algorithm`: Sealing algorithm (e.g., `rsa-sha256`). Defaults based on the private key type.
-   `--time timestamp`, `-t timestamp`: Sealing time as a Unix timestamp (`t=` tag).
-   `--header-fields "field1:field2"`, `-h "field1:field2"`: Colon-separated list of header fields to include in the seal (`h=` tag).
-   `--headers-only`, `-o`: Outputs only the ARC seal headers without the entire message.

**Authentication Options (from `report` command):**

-   `--client-ip x.x.x.x`, `-i x.x.x.x`: IP address of the remote client that sent the email.
-   `--sender user@example.com`, `-f user@example.com`: Email address from the MAIL FROM command.
-   `--helo hostname`, `-e hostname`: Hostname from the HELO/EHLO command.
-   `--mta hostname`, `-m hostname`: Hostname of the server performing validations.
-   `--dns-cache /path/to/dns.json`, `-n /path/to/dns.json`: Path to a DNS cache file.
-   `--verbose`, `-v`: Enables verbose output.

**Note:** The canonicalization method (`c=` tag) for ARC sealing is always `relaxed/relaxed` and cannot be changed.

#### Example

```bash
mailauth seal /path/to/message.eml --domain example.com --selector s1 --private-key /path/to/private.key --verbose
```

**Sample Output:**

```
Reading email message from /path/to/message.eml
Signing domain:             example.com
Key selector:               s1
Canonicalization algorithm: relaxed/relaxed
Hashing algorithm:          rsa-sha256
Sealing time:               2023-03-15T12:05:00.000Z
--------
ARC-Seal: i=3; a=rsa-sha256; t=1678884300; cv=pass; d=example.com; s=s1;
 b=Fo3hayVos+J77lzzgmr6J92gsUBKlPt/ZkoQt9ZCi514zy8+1WLvTHmI8CMUXAcegdcqP0NHt
 ...
```

### spf

The `spf` command checks the SPF (Sender Policy Framework) record for a given email address and IP address.

#### Usage

```bash
mailauth spf [options]
```

#### Options

-   `--sender user@example.com`, `-f user@example.com`: Email address from the MAIL FROM command. **Required.**
-   `--client-ip x.x.x.x`, `-i x.x.x.x`: IP address of the remote client that sent the email. **Required.**
-   `--helo hostname`, `-e hostname`: Hostname from the HELO/EHLO command.
-   `--mta hostname`, `-m hostname`: Hostname of the server performing the SPF check.
-   `--dns-cache /path/to/dns.json`, `-n /path/to/dns.json`: Path to a DNS cache file.
-   `--verbose`, `-v`: Enables verbose output.
-   `--headers-only`, `-o`: Outputs only the SPF authentication header.
-   `--max-lookups number`, `-x number`: Sets the maximum number of DNS lookups. Defaults to `10`.
-   `--max-void-lookups number`, `-z number`: Sets the maximum number of void DNS lookups. Defaults to `2`.

#### Example

```bash
mailauth spf --verbose -f user@example.com -i 192.0.2.1
```

**Sample Output:**

```
Checking SPF for user@example.com
Maximum DNS lookups: 10
--------
DNS query for TXT example.com: [["v=spf1 include:_spf.example.com -all"]]
DNS query for TXT _spf.example.com: [["v=spf1 ip4:192.0.2.0/24 -all"]]
{
  "domain": "example.com",
  "client-ip": "192.0.2.1",
  "result": "pass",
  "..."
}
```

### vmc

The `vmc` command validates a Verified Mark Certificate (VMC) used in BIMI (Brand Indicators for Message Identification).

#### Usage

```bash
mailauth vmc [options]
```

#### Options

-   `--authority <url>`, `-a <url>`: URL of the VMC resource.
-   `--authorityPath <path>`, `-p <path>`: Path to a local VMC file, used to avoid network requests.
-   `--domain <domain>`, `-d <domain>`: Sender domain to validate against the certificate.

#### Example

```bash
mailauth vmc -a https://example.com/path/to/vmc.pem -d example.com
```

**Sample Output:**

```json
{
    "url": "https://example.com/path/to/vmc.pem",
    "success": true,
    "domainVerified": true,
    "vmc": {
        "mediaType": "image/svg+xml",
        "hashAlgo": "sha256",
        "hashValue": "abc123...",
        "logoFile": "<Base64 encoded SVG>",
        "validHash": true,
        "type": "VMC",
        "certificate": {
            "subject": {
                "commonName": "Example Inc.",
                "markType": "Registered Mark",
                "..."
            },
            "subjectAltName": ["example.com"],
            "fingerprint": "12:34:56:78:9A:BC:DE:F0...",
            "serialNumber": "0123456789ABCDEF",
            "validFrom": "2023-01-01T00:00:00.000Z",
            "validTo": "2024-01-01T23:59:59.000Z",
            "issuer": {
                "commonName": "Trusted CA"
                "..."
            }
        }
    }
}
```

If validation fails, the output includes error details:

```json
{
    "success": false,
    "error": {
        "message": "Self signed certificate in certificate chain",
        "details": {
            "..."
        },
        "code": "SELF_SIGNED_CERT_IN_CHAIN"
    }
}
```

### bodyhash

The `bodyhash` command computes the body hash value of an email message, which is used in DKIM signatures.

#### Usage

```bash
mailauth bodyhash [options] [email]
```

-   **email**: (Optional) Path to the EML-formatted email message file. If omitted, the email is read from standard input.

#### Options

-   `--algo algorithm`, `-a algorithm`: Hashing algorithm (e.g., `sha256`). Defaults to `sha256`. Can also specify DKIM-style algorithms (e.g., `rsa-sha256`).
-   `--canonicalization method`, `-c method`: Body canonicalization method (e.g., `relaxed`). Defaults to `relaxed`. Can use DKIM-style (e.g., `relaxed/relaxed`).
-   `--body-length length`, `-l length`: Maximum length of the body to hash (`l=` tag).
-   `--verbose`, `-v`: Enables verbose output.

#### Example

```bash
mailauth bodyhash /path/to/message.eml -a sha1 --verbose
```

**Sample Output:**

```
Hashing algorithm:               sha1
Body canonicalization algorithm: relaxed
--------
j+dD7whKXS1yDmyoWtvClYSyYiQ=
```

### license

The `license` command displays the licenses for mailauth and its included modules.

#### Usage

```bash
mailauth license
```

#### Example

```bash
mailauth license
```

**Sample Output:**

```
mailauth License: MIT License
Included Modules:
- module1: MIT License
- module2: Apache License 2.0
...
```

## DNS Cache File

The `--dns-cache` option allows you to use a JSON-formatted DNS cache file for testing purposes. This avoids the need to set up a DNS server or wait for DNS propagation.

### Format

The DNS cache file is a JSON object where:

-   **Keys**: Fully qualified domain names (e.g., `"example.com"`).
-   **Values**: Objects with DNS record types as keys (e.g., `"TXT"`, `"MX"`) and their corresponding values.

**Example:**

```json
{
    "example.com": {
        "TXT": [["v=spf1 include:_spf.example.com -all"]],
        "MX": [{ "exchange": "mail.example.com", "priority": 10 }]
    },
    "_dmarc.example.com": {
        "TXT": [["v=DMARC1; p=reject; rua=mailto:dmarc@example.com;"]]
    }
}
```

### Usage

Specify the DNS cache file using the `--dns-cache` option:

```bash
mailauth report --dns-cache /path/to/dns-cache.json email.eml
```

When this option is used, mailauth will not perform actual DNS queries but will use the data from the cache file instead.

## License

&copy; 2020-2024 Postal Systems OÜ

Licensed under the [MIT License](LICENSE).
