# mailauth(1)

> mailauth - authenticate, sign and seal emails

## SYNOPSIS

`mailauth` _command_ [ _command_opts_ ] [ _email_ ]

`mailauth help`

`mailauth` _command_ `help`

## DESCRIPTION

Mailauth is an email authentication application to validate SPF, DKIM, DMARC, and ARC. You can also sign emails with DKIM digital signatures and seal messages with ARC.

## COMMANDS

**report**\
Validate an email message and return a report in JSON format

**sign**\
Sign an email with a DKIM digital signature

**seal**\
Authenticates an email and seals it with an ARC digital signature

**spf**\
Authenticates SPF for an IP address and email address

**license**\
Display licenses for mailauth and included modules

## Website

[](https://github.com/postalsys/mailauth)

## EXAMPLES

`npm install mailauth -g`

`mailauth report /path/to/email.eml`

`cat /path/to/email.eml | mailauth report`

`mailauth sign /path/to/email.eml -d kreata.ee -s test -k /path/to/key`

`mailauth spf -f andris@wildduck.email -i 217.146.76.20`

## EMAIL ARGUMENT

Email argument defines the path to the email message file in EML format. If not specified, then
content is read from standard input.

## OPTIONS

-   `--verbose`, `-v`
    Enable silly verbose mode

-   `--version`
    Print application version

-   `--client-ip`, `-i <ip>`
    Client IP used for SPF checks. If not set, then parsed from the latest Received header. (`report`, `seal`, `spf`)

-   `--mta`, `-m <hostname>`
    The hostname of this machine, used in the `Authentication-Results` header. (`report`, `seal`, `spf`)

-   `--helo`, `-e <hostname>`
    Client hostname from the EHLO/HELO command, used in some specific SPF checks. (`report`, `seal`, `spf`)

-   `--sender`, `-f <address>`
    The email address from the `MAIL FROM` command. If not set, the address from the latest _Return-Path_ header is used instead. (`report`, `seal`, `spf`)

-   `--dns-cache`, `-n <file>`
    Path to a JSON file with cached DNS responses. If this file is given, then no actual DNS requests are performed. Anything that is not listed returns an `ENOTFOUND` error. (`report`, `seal`, `spf`)

-   `--private-key`, `-k <file>`
    Path to a private key for signing. Allowed key types are RSA and Ed25519 (`sign`, `seal`)

-   `--domain`, `-d <domain>`
    Domain name for signing. (`sign`, `seal`)

-   `--selector`, `-s <selector>`
    Key selector for signing. (`sign`, `seal`)

-   `--algo`, `-a <algo>`
    Signing algorithm. Defaults either to _rsa-sha256_ or _ed25519-sha256_ depending on the private key format. (`sign`, `seal`)

-   `--canonicalization`, `-c <algo>`
    Canonicalization algorithm. Defaults to _relaxed/relaxed_. (`sign`)

-   `--body-length`, `-l <number>`
    The maximum length of the canonicalized body to sign. (`sign`)

-   `--time`, `-t <number>`
    Signing time as a Unix timestamp. (`sign`, `seal`)

-   `--header-fields`, `-h <list>`
    Colon separated list of header field names to sign. (`sign`, `seal`)

-   `--headers-only`, `-o`
    Return signing headers only. By default, the entire message is printed to the console. (`sign`, `seal`, `spf`)

-   `--max-lookups`, `-x`
    How many DNS lookups allowed for SPF validation. Defaults to 10. (`report`, `spf`)

-   `--max-void-lookups`, `-z`
    How many empty DNS lookups allowed for SPF validation. Defaults to 2. (`report`, `spf`)

## DNS CACHE

For cached DNS requests, use the following JSON object structure: primary keys are domain names, and subkeys are resource record types.

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

You can split longer TXT strings into multiple strings. There is no length limit, unlike in actual DNS so you can put the entire public key into a single string.

## BUGS

Please report any bugs to https://github.com/postalsys/mailauth/issues.

## LICENSE

Copyright (c) 2020-2024, Postal Systems (MIT).

## SEE ALSO

node.js(1)
