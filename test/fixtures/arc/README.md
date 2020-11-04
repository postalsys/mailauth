# ARC Test Suite

This is an informal schema for the open source test suites for the [Authenticated Recieved Chain(ARC)](https://tools.ietf.org/id/draft-ietf-dmarc-arc-protocol-18.txt) protocol, illustrated with examples.  This was prototyped from [the OpenSPF Test Suite](http://www.openspf.org/Test_Suite/Schema), and consists of two suites, one for the generation of ARC header fields, the other for their validation.

Their syntax is YAML. The top level object is a "scenario". A file can consist of multiple scenarios separated by '---' on a line by itself. Lexical comments are introduced by '#' and continue to the end of a line. Lexical comments are ignored. There are also comment fields which are part of a scenario. DKIM records, private keys, domains, and selectors are shared across scenarios.

The signing suite explicitly does not thoroughly test chain validation to avoid reimplementation of the validation test suite.

Parts of the test suite use the following external packages:

"dnslib", "dkimpy>=0.7.1", "pyyaml", "ddt", "authheaders"

They can be easy installed with pip using the provided dependencies.py script:

$ ./dependencies.py


## Example Validation Scenario

```
description: >-
  dummy scenario
tests:
  test1:
    spec:        12/16
    description: basic test
    message:     |
      MIME-Version: 1.0
      Return-Path: <jqd@d1.example.org>
      Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)
      Message-ID: <54B84785.1060301@d1.example.org>
      Date: Thu, 14 Jan 2015 15:00:01 -0800
      From: John Q Doe <jqd@d1.example.org>
      To: arc@dmarc.org
      Subject: Example 1

      Hey gang,
      This is a test message.
      --J.
    cv:          None
txt_records:
  dummy._domainkey.example.org: >-
    v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg1i2lO83x/r58cbo/JSBwfZrrct6S/yi4L6GsG3wNgFE9lO3orzBwnAEJJM33WrvJfOWia1fAx64Vs1QEpYtLFCzyeIhDDMaHv/G8NgKPgnWK4gI8/x2Q2SYCmiqil66oHaSOC2phMDRI+c/Q35MlZbc2FqlgevpKzdCg+YE6mYA0XN7/tdQplbx4meLVsVPIL9QCP4yu8oBsNqcwyxkQafJucVyoZI+VEO+dySw3QXNdmJhr7y1hD1tCNqoAG0iphKQVXPXmGnGhaxaVU92Kq5UKL6/LiTZ1piqyJfJyZ/zCgH+mtY8MNk9f7LHpwFljI7TbYmr7MmV3d6xj3sghwIDAQAB
comment: >-
  This is a comment
```

## Signing Suite Assumptions
An accurate chain validation status for the messages in the test suite has been stamped into the most recent Authentication-Results header.  Implementations are free to use this or not, although it is encouraged that they do so.  It is also assumed that signing implementations do not add additional Authentication-Results header fields, as this would be propagated into the AAR header & thus invalidate signatures.

All tests in the signing test suite are generated using the relaxed/relaxed cannonicalization rules.

## AR Consolidation
When generating AAR'sm implementations are expected to consolidate AR headers with the ADMD's authserv_id. How this is done is implementation specific. In order to test this feature, we asume a standard way of accomplishing this.

All AR's with the give authserv-id are consolidated, and kept in the order in which they appear in the message.  Each complete result is extracted from the AR headers, and kept in order.  These are added to the AAR, in order, one per line, beggining with the line containing the authserv_id.  For example:

```
Authentication-Results: lists.example.org; arc=none;
  spf=pass smtp.mfrom=jqd@d1.example
Authentication-Results: lists.example.org; dkim=pass (1024-bit key) header.i=@d1.example
Authentication-Results: lists.example.org; dmarc=pass
Authentication-Results: nobody.example.org; something=ignored
MIME-Version: 1.0
Return-Path: <jqd@d1.example.org>
....
```
Would yield the following AAR, assuming this to be the first arc hop:

```
ARC-Authentication-Results: i=1; lists.example.org; arc=none;
  spf=pass smtp.mfrom=jqd@d1.example;
  dkim=pass (1024-bit key) header.i=@d1.example;
  dmarc=pass
```

## Signing Header Format Standardization

There is an explicit ambiguity & indeterminism supported by the ARC & DKIM specs with respect to the format of generated signature headers.  Implementors are free to add additional tags, whitespace, and to arbitrarily order tags, etc.  This degree of variability makes it impossible to predict message signatures from inputs.  Therefore, for the purposes of the signing section of this test suite, we assume the signing implementer generates a standardized header format for both ARC-Message-Signature, and ARC-Seal header fields:

* All tags are ordered alphabetically by key
* All tag keys are lowercase
* All tag values are lowercase except for b= and bh=
* There is no whitespace(newlines, crlf, spaces) asside from exactly one space after separator semi-colons
* There is no trailing semi-colon
* The ARC-Seal tag set will be exactly - (a, b, cv, d, i, s, t)
* The ARC-Message-Signature tag set will be exactly - (a, b, b, bh, d, h, i, s, t)
* ARC-Seal & ARC-Message-Signature a=rsa-sha256

## Example Signing Scenario

```
description: >-
  dummy scenario
tests:
  test1:
    spec:        12/16
    description: basic test
    message:     |
      Authentication-Results: lists.example.org;
        spf=pass smtp.mfrom=jqd@d1.example;
        dkim=pass (1024-bit key) header.i=@d1.example;
        dmarc=pass
      MIME-Version: 1.0
      Return-Path: <jqd@d1.example.org>
      Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)
      Message-ID: <54B84785.1060301@d1.example.org>
      Date: Thu, 14 Jan 2015 15:00:01 -0800
      From: John Q Doe <jqd@d1.example.org>
      To: arc@dmarc.org
      Subject: Example 1

      Hey gang,
      This is a test message.
      --J.
    t:           12345
    sig-headers: from:to:subject
    srv-id: lists.example.org
    AS:          |
      a=rsa-sha256; b=oXNsU/I3fVAFVMIhssuTgCkdSqw6tLBI9w9c+izOlrVQElsVxarVCmhH
      7NGae7CyqDQMYxEFfrqjzSxsu6G9yhqxsge574oHCvZgx8VLkFAa16hrBe0M+YPauA0TCkMm
      zGPLTDJVtblJ5qZApAuIizX8smdreZJVS3BAv7FpnmQ=;
      cv=none; d=example.org; i=1; s=dummy; t=12345
    AMS:         |
      a=rsa-sha256;
      b=aHfjYd84tmqd6nApu4mmmxbR6ZRLwgqN5Acppn4jj3Dfij0WRHLpe22E30AiJ1fyyRyKS0
      zZmOfhcYA+5B2IJv91EjUzP3Vt1gW5UqjhYMkeJl4NCBdn0xBdn49fBX9w0PbC7AZjW3tok0
      ZEuORs3bB9rnoh1BSU+OM7+HnxxRo=;
      bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; c=relaxed/relaxed;
      d=example.org; h=from:to:subject:arc-authentication-results; i=1;
      s=dummy; t=12345
    AAR:         |
      i=1; lists.example.org;
      spf=pass smtp.mfrom=jqd@d1.example;
      dkim=pass (1024-bit key) header.i=@d1.example;
      dmarc=pass
domain:     example.org
sel:        dummy
privatekey: |
  -----BEGIN RSA PRIVATE KEY-----
  MIICXQIBAAKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQi
  Y/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqM
  KrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB
  AoGAH0cxOhFZDgzXWhDhnAJDw5s4roOXN4OhjiXa8W7Y3rhX3FJqmJSPuC8N9vQm
  6SVbaLAE4SG5mLMueHlh4KXffEpuLEiNp9Ss3O4YfLiQpbRqE7Tm5SxKjvvQoZZe
  zHorimOaChRL2it47iuWxzxSiRMv4c+j70GiWdxXnxe4UoECQQDzJB/0U58W7RZy
  6enGVj2kWF732CoWFZWzi1FicudrBFoy63QwcowpoCazKtvZGMNlPWnC7x/6o8Gc
  uSe0ga2xAkEA8C7PipPm1/1fTRQvj1o/dDmZp243044ZNyxjg+/OPN0oWCbXIGxy
  WvmZbXriOWoSALJTjExEgraHEgnXssuk7QJBALl5ICsYMu6hMxO73gnfNayNgPxd
  WFV6Z7ULnKyV7HSVYF0hgYOHjeYe9gaMtiJYoo0zGN+L3AAtNP9huqkWlzECQE1a
  licIeVlo1e+qJ6Mgqr0Q7Aa7falZ448ccbSFYEPD6oFxiOl9Y9se9iYHZKKfIcst
  o7DUw1/hz2Ck4N5JrgUCQQCyKveNvjzkkd8HjYs0SwM0fPjK16//5qDZ2UiDGnOe
  uEzxBDAr518Z8VFbR41in3W4Y3yCDgQlLlcETrS+zYcL
  -----END RSA PRIVATE KEY-----
txt-records:
  dummy._domainkey.example.org: |
    v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQ
    oBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzC
    Nb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvH
    O9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB
comment: >-
  This is a comment
```

## Running the Suite
Included is an example python harness for running the test suite.  The harness takes as input the suite to run(sign/validate), and a command line tool which performs the operation.  A DNS server with the key records is started on a local port during suite execution.  More details are provided by ./testarc.py -h.  Dependencies for this script are documented in requirements.txt.  OpenARC, dkimpy, & dummy runners are found in the runners directory.

## Modifying the suite
There are various tools for generating and modifying parts of the suite, found in the sig_gen directory.  See the Readme file in that directory for more information.
