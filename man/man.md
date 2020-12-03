# mailauth(1)

> mailauth - authenticate, sign and seal emails

## SYNOPSIS

`mailauth` _command_ [ _command_opts_ ] [ _email_ ]

`mailauth help`

`mailauth` _command_ `help`

## DESCRIPTION

Mailauth is an email authentication application to validate SPF, DKIM, DMARC and ARC. You can also sign emails with DKIM digital signatures and seal messages with ARC.

## COMMANDS

**report**\
Validate an email message and return a report in JSON format

**sign**\
Sign an email with a DKIM digital signature

**seal**\
Authenticates an email and seals it with an ARC digital signature

## Website

[](https://github.com/andris9/mailauth)

## EXAMPLES

`npm install mailauth -g`

`mailauth report /path/to/email.eml`

`mailauth sign /path/to/email.eml -d kreata.ee -s test -k /path/to/key`

## EMAIL ARGUMENT

Email argument defines path to the email message file in EML format. If not specified then
content is read from standard input.

## OPTIONS

-   `--verbose`, `-v`
    Enable silly verbose mode

-   `--version`
    Print application version

-   `--client-ip`, `-i <ip>`
    Client IP used for SPF checks. If not set then parsed from latest Received header. (`report`, `seal`)

-   `--mta`, `-m <hostname>`
    Hostname of this machine, used in the Authentication-Results header. (`report`, `seal`)

-   `--helo`, `-e <hostname>`
    Client hostname from the EHLO/HELO command, used in some specific SPF checks. (`report`, `seal`)

-   `--sender`, `-f <address>`
    Email address from the `MAIL FROM` command. If not set then the address from the latest _Return-Path_ header is used instead. (`report`, `seal`)

-   `--dns-cache`, `-n <file>`
    Path to a JSON file with cached DNS responses. If this file is given then no actual DNS requests are performed. (`report`, `seal`)

-   `--headers-only`, `-h`
    Return signing headers only. By default the entire message is printed to console. (`sign`, `seal`)

-   `--domain`, `-d <domain>`
    Domain name for signing. (`sign`, `seal`)

-   `--selector`, `-s <selector>`
    Key selector for signing. (`sign`, `seal`)

-   `--private-key`, `-k <file>`
    Path to a private key for signing. Allowed key types are RSA and Ed25519 (`sign`, `seal`)

-   `--algo`, `-a <algo>`
    Signing algorithm. Defaults either to _rsa-sha256_ or _ed25519-sha256_ depending on the private key format. (`sign`, `seal`)

-   `--canonicalization`, `-c <algo>`
    Canonicalization algorithm. Defaults to _relaxed/relaxed_. (`sign`, `seal`)

-   `--time`, `-t <number>`
    Signing time as a unix timestamp. (`sign`, `seal`)

## DNS CACHE

For cached DNS requests use the following JSON structure where main keys are domain names and subkeys are rr types.

```
{
    "selector._domainkey.example.com": {
        "TXT": [
            [
                "v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQ...",
                "...sOLccRAmVAOmacHmayjDROTw/XilzErJj+uVAicGYfs10Nz+EUuwIDAQAB"
            ]
        ]
    }
}
```

Longer TXT strings can be split into multiple strings. Unlike in real DNS there is no length limit, so you can put the entire public key into a single string.

## BUGS

Please report any bugs to https://github.com/andris9/mailauth/issues.

## LICENSE

Copyright (c) 2020, Andris Reinman (AGPL-3.0-or-later OR EUPL-1.1+).

## SEE ALSO

node.js(1)
