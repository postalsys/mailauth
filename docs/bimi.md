# BIMI Result Reference

This document describes the result object returned by BIMI (Brand Indicators for Message Identification) resolution.

## Overview

BIMI allows organizations to display brand logos in email clients. BIMI information is resolved during the authentication step, provided the message passes DMARC validation with an enforcing policy. Record discovery and the result keywords follow [draft-brand-indicators-for-message-identification-14](https://datatracker.ietf.org/doc/html/draft-brand-indicators-for-message-identification). Local-part selectors (`lps=`) are not supported.

Before looking up a BIMI record, mailauth checks the requirements of section 7.1 of the draft:

- The message has one From header field with one address. DMARC evaluates several addresses that share a domain, BIMI does not.
- DMARC passed, with an effective policy other than `none` and without `t=y`.
- Neither the DMARC record of the author domain nor the one of its Organizational Domain has `p=none` or `sp=none`, or `p=quarantine` with a `pct` other than 100. A record found at the author domain itself does not hide a lax record of the Organizational Domain. `dmarc()` passes both records to `bimi()`, for a DMARC result built elsewhere `bimi()` looks up the Organizational Domain's record itself.

The record is looked up at `<selector>._bimi.<author domain>` and then at `<selector>._bimi.<organizational domain>`, where the selector comes from the `BIMI-Selector` header and defaults to `default`. A `BIMI-Selector` header without `v=BIMI1` or without a valid `s=` selector is ignored, and `default` is used (sections 5.1 and 7.2). A custom selector does not fall back to `default`. TXT records that do not start with `v=BIMI1` are ignored, several BIMI records are a failure.

```javascript
const { authenticate } = require('mailauth');

const { bimi } = await authenticate(message, {
    ip: '192.0.2.1',
    helo: 'mail.example.com',
    sender: 'user@example.com'
});
```

## Result Object Fields

| Field        | Type     | Presence             | Description                                                                                       |
| ------------ | -------- | -------------------- | ------------------------------------------------------------------------------------------------- |
| `status`     | `object` | Always               | Resolution status object (see below)                                                              |
| `location`   | `string` | Found                | HTTPS URL for the logo SVG file (from `l=` tag)                                                   |
| `authority`  | `string` | Found                | HTTPS URL for the VMC/CMC certificate (from `a=` tag)                                             |
| `preference` | `string` | When `avp=` is valid | Avatar preference from the `avp=` tag, `personal` or `brand`. Other values are ignored            |
| `rr`         | `string` | Found                | Raw BIMI DNS TXT record                                                                           |
| `warnings`   | `array`  | When there are any   | Assertion Record deviations accepted because `strict` is not set, see [Strict Mode](#strict-mode) |
| `info`       | `string` | Always               | Formatted Authentication-Results header value                                                     |

## Strict Mode

The Assertion Record uses the DKIM tag-list syntax, and the draft says that receivers must not fix syntax or capitalization errors (section 4.3). By default mailauth accepts the deviations below in the record and in the `BIMI-Selector` header, and lists them in `warnings`. With `strict: true` they are handled exactly:

| Input                                                                                        | Default                                                    | `strict: true`                                                     |
| -------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------ |
| `v=` value in another case, such as `v=bimi1`                                                | used, warning `record-version-case`                        | record ignored (`none` if it is the only one)                      |
| Upper case tag names, such as `L=`                                                           | used as the lower case tag, warning `record-tag-case`      | unknown tag, ignored                                               |
| Duplicate tags or other tag-list syntax errors                                               | last duplicate wins, warning `record-syntax`               | `fail` (`invalid syntax in dns record`)                            |
| Unencoded comma in `l=` or `a=`                                                              | used, warning `uri-comma`                                  | `fail` (`invalid location value...`, `invalid authority value...`) |
| `l=` URI ending in another image format suffix, such as `.png`                               | used, warning `location-format`                            | `fail` (`unsupported image format in location value`)              |
| `BIMI-Selector` header with `v=` in another case, `v=` not first, or a tag-list syntax error | used, warning `selector-version-case` or `selector-syntax` | header ignored, `default` is used                                  |
| `BIMI-Selector` selector with underscores                                                    | used, warning `selector-syntax`                            | header ignored, `default` is used                                  |

## status Object

| Field     | Type     | Presence               | Description                  |
| --------- | -------- | ---------------------- | ---------------------------- |
| `result`  | `string` | Always                 | BIMI result code (see below) |
| `comment` | `string` | On skip/fail/temperror | Reason for skip or failure   |
| `header`  | `object` | Always                 | Header information           |
| `policy`  | `object` | VMC found              | Authority policy details     |

### status.header Object

| Field      | Type     | Presence     | Description                            |
| ---------- | -------- | ------------ | -------------------------------------- |
| `selector` | `string` | Record found | BIMI selector used (e.g., `"default"`) |
| `d`        | `string` | Record found | Domain where BIMI record was found     |

### status.policy Object

| Field           | Type     | Description                                                                              |
| --------------- | -------- | ---------------------------------------------------------------------------------------- |
| `authority`     | `string` | VMC validation status, `"none"` from `bimi()`, `"pass"` or `"fail"` from `validateVMC()` |
| `authority-uri` | `string` | URL of the authority evidence document                                                   |

## Result Values

| Result      | Description                                                    |
| ----------- | -------------------------------------------------------------- |
| `pass`      | BIMI record found and valid                                    |
| `skipped`   | BIMI lookup skipped (see skip reasons below)                   |
| `fail`      | BIMI record found but invalid                                  |
| `none`      | No BIMI record found                                           |
| `declined`  | The domain published a Declination to Publish (`v=BIMI1; l=;`) |
| `temperror` | Temporary error during a DNS lookup                            |

Earlier versions reported a DNS error as `temperr`, a keyword the draft does not define. It is now `temperror`, the keyword of the draft and of the other methods in RFC 8601.

## Skip Reasons

The `status.comment` field explains why BIMI was skipped:

| Comment                                              | Description                                              |
| ---------------------------------------------------- | -------------------------------------------------------- |
| `"DMARC not enabled"`                                | DMARC result was `none`                                  |
| `"message failed DMARC"`                             | DMARC result was not `pass`                              |
| `"multiple From addresses"`                          | More than one From header field or address               |
| `"too lax DMARC policy"`                             | DMARC policy is `none`, or the record has `t=y`          |
| `"too lax DMARC subdomain policy"`                   | The author or Organizational Domain record has `sp=none` |
| `"DMARC policy applied to a percentage of messages"` | `p=quarantine` with a `pct` other than 100               |
| `"Aligned DKIM signature required"`                  | `bimiWithAlignedDkim` option set but no aligned DKIM     |
| `"undersized DKIM signature"`                        | DKIM signature has unsigned body bytes (due to `l=` tag) |
| `"could not determine domain"`                       | Unable to extract domain from headers                    |

## Fail Reasons

| Comment                                        | Description                                                                                                                |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `"multiple BIMI-Selector headers"`             | Message has more than one BIMI-Selector header                                                                             |
| `"missing bimi version in dns record"`         | DNS record missing `v=BIMI1`                                                                                               |
| `"missing location value in dns record"`       | Record has no `l=` value (and is not a declination), even if it has `a=`                                                   |
| `"invalid location value in dns record"`       | `l=` value is not a valid HTTPS URL with a domain name (IP addresses, `localhost` and single-label hosts are not accepted) |
| `"invalid authority value in dns record"`      | `a=` value is not a valid HTTPS URL with a domain name                                                                     |
| `"invalid syntax in dns record"`               | Tag-list syntax error, such as a duplicate tag (strict mode)                                                               |
| `"unsupported image format in location value"` | `l=` ends with an image format suffix other than SVG or SVGZ (strict mode)                                                 |
| `"multiple BIMI records for {name}"`           | More than one `v=BIMI1` record at the name                                                                                 |

## Temperror Reasons

| Comment                                                             | Description                                                          |
| ------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `"failed to resolve {name}"`                                        | DNS lookup error for a BIMI record                                   |
| `"failed to resolve the DMARC policy of the organizational domain"` | The DMARC record of the Organizational Domain could not be looked up |

## VMC Validation Result

When using `validateVMC()` to validate the authority evidence document:

```javascript
const { bimi, validateVMC } = require('mailauth/lib/bimi');

const bimiResult = await bimi(data);
const vmcResult = await validateVMC(bimiResult, options);
```

### Options

| Option            | Type         | Default  | Description                                                                                                      |
| ----------------- | ------------ | -------- | ---------------------------------------------------------------------------------------------------------------- |
| `strict`          | `boolean`    | `false`  | Validate the logo files exactly against the SVG Tiny PS profile, see [Logo SVG Validation](#logo-svg-validation) |
| `now`             | `Date`       | now      | Time used for the certificate validity checks (passed to `@postalsys/vmc`)                                       |
| `maxLogoSize`     | `number`     | `65536`  | Maximum size of the logo file in bytes, also the limit for an uncompressed SVGZ file                             |
| `maxEvidenceSize` | `number`     | `262144` | Maximum size of the evidence document in bytes                                                                   |
| `timeout`         | `number`     | `30000`  | Time limit in milliseconds for each download, including redirects and the response body                          |
| `dispatcher`      | `Dispatcher` |          | undici dispatcher for the downloads, for example to use a proxy                                                  |

Downloads only use HTTPS URLs whose host is a domain name. Redirects are followed up to 3 times when the target is such a URL as well, and the body is read up to the size limit only (section 7.6 of the draft allows a retrieval limit). The limits also apply to `locationPath` and `authorityPath` buffers.

### VMC Result Object

| Field       | Type     | Description                                                       |
| ----------- | -------- | ----------------------------------------------------------------- |
| `location`  | `object` | Logo file fetch result                                            |
| `authority` | `object` | VMC/CMC fetch and validation result                               |
| `headers`   | `object` | Ready-to-use email headers (only on validation success)           |
| `status`    | `object` | Updated BIMI status, when `bimiData.status.result` was `pass`     |
| `info`      | `string` | Updated Authentication-Results entry, along with `status`         |
| `warnings`  | `array`  | Accepted SVG Tiny PS profile deviations of the logo files, if any |

The `info` of `bimi()` covers record discovery only, it reports `bimi=pass policy.authority=none` before anything is downloaded. When `validateVMC()` is used, use its `info` for the Authentication-Results header instead (section 7.7 of the draft): the result is `fail` when the indicator can not be retrieved (`failed to retrieve indicator`), fails SVG validation (`invalid SVG indicator`), the evidence document does not validate (`evidence document validation failed`) or its logo does not match the indicator (`indicator does not match evidence document`). When the record has `a=`, `policy.authority` is `pass` if the evidence document validated and its logo matches, and `fail` otherwise. `authenticate()` does not download anything, so its `bimi.info` is the discovery result.

### location Object

| Field       | Type      | Description                                                    |
| ----------- | --------- | -------------------------------------------------------------- |
| `url`       | `string`  | Logo URL                                                       |
| `success`   | `boolean` | Whether the logo was fetched and passed SVG validation         |
| `logoFile`  | `string`  | Base64-encoded logo SVG, uncompressed if it was SVGZ (success) |
| `error`     | `object`  | Error details (on failure)                                     |
| `hashAlgo`  | `string`  | Hash algorithm used for verification                           |
| `hashValue` | `string`  | Calculated hash of the logo file                               |

The logo downloaded from `l=` is always checked with the SVG validator (section 7.6 of the draft), also when the record has no `a=` evidence document. An SVGZ file is uncompressed first. A logo that fails validation gives `success: false` with the error code `SVG_VALIDATION_FAILED`, and no headers are generated.

### authority Object

| Field            | Type      | Description                            |
| ---------------- | --------- | -------------------------------------- |
| `url`            | `string`  | VMC/CMC URL                            |
| `success`        | `boolean` | Whether fetch and validation succeeded |
| `vmc`            | `object`  | Parsed VMC data (on success)           |
| `domainVerified` | `boolean` | Whether domain matches certificate     |
| `hashMatch`      | `boolean` | Whether logo hash matches certificate  |
| `error`          | `object`  | Error details (on failure)             |

### headers Object

Present only when the logo passes SVG validation and, if the record has an `a=` tag, the evidence document validates and its logo hash matches. Contains ready-to-use email headers.

| Field        | Type     | Presence                              | Description                                                                                     |
| ------------ | -------- | ------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `indicator`  | `string` | Always                                | BIMI-Indicator header with base64-encoded SVG logo                                              |
| `location`   | `string` | Always                                | BIMI-Location header with the logo URL, and the `a=` evidence document URL when it was verified |
| `preference` | `string` | `preference` is `personal` or `brand` | BIMI-Logo-Preference header, for example `BIMI-Logo-Preference: avp=brand`                      |

These headers should be added to messages after successful BIMI validation. The MTA should:

1. Remove any existing BIMI-\* headers from incoming messages
2. Add these headers after successful validation

### VMC Error Codes

| Code                        | Description                                                                                                                              |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `HTTP_REQUEST_FAILED`       | HTTP request failed                                                                                                                      |
| `HTTP_REQUEST_TIMEOUT`      | The download took longer than `timeout`                                                                                                  |
| `HTTP_REDIRECT_NOT_ALLOWED` | A redirect to a URL that is not HTTPS with a domain name, or more than 3 redirects. `redirect` has the target                            |
| `INVALID_URL`               | The URL is not HTTPS, or its host is an IP address, `localhost` or a single label                                                        |
| `FILE_TOO_LARGE`            | The file, or the uncompressed SVGZ logo, is larger than the size limit                                                                   |
| `MISSING_VMC_LOGO`          | VMC does not contain a logo file                                                                                                         |
| `INVALID_MEDIATYPE`         | Logo media type is not `image/svg+xml`                                                                                                   |
| `INVALID_LOGO_HASH`         | Logo hash does not match certificate                                                                                                     |
| `SVG_VALIDATION_FAILED`     | SVG file failed validation, `details` has the validator's error code (`INVALID_SVGZ_FILE` for an SVGZ file that can not be uncompressed) |
| `VMC_DOMAIN_MISMATCH`       | Domain not found in certificate SAN                                                                                                      |

## Logo SVG Validation

`validateBimiSvg(logo, options)` (also `validateSvg` in `mailauth/lib/bimi/validate-svg`) checks a logo against the SVG Tiny Portable/Secure profile of [draft-svg-tiny-ps-abrotman](https://datatracker.ietf.org/doc/html/draft-svg-tiny-ps-abrotman). It returns `true` or throws an error with one of the codes below. `validateVMC()` runs it on the logo from `l=` and on the logo embedded in the evidence document, with the `strict` option of `validateVMC()`, and lists the warnings in `warnings` of its result.

```javascript
const { validateBimiSvg } = require('mailauth');

const warnings = [];
validateBimiSvg(logo, { strict: false, warnings }); // throws if the logo is not valid
```

The root element must be `svg` in the `http://www.w3.org/2000/svg` namespace. Some rules of the profile do not make a logo unsafe. By default a logo that breaks them is accepted and a marker is added to the `warnings` array, with `strict: true` it is rejected:

| Warning                | Rule                                                                                                                                                                             |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `svg-version`          | The root element has `version="1.2"` (`INVALID_SVG_VERSION`)                                                                                                                     |
| `svg-title-count`      | Only one `title` child of the root element (`LOGO_MULTIPLE_TITLES`)                                                                                                              |
| `svg-title-position`   | `title` is the first child of the root element, and not used elsewhere (`LOGO_INVALID_ELEMENT`)                                                                                  |
| `svg-attribute-value`  | `zoomAndPan`, `externalResourcesRequired`, `focusable`, `snapshotTime`, `playbackOrder`, `timelineBegin` and `editable` have their only allowed value (`LOGO_INVALID_ATTRIBUTE`) |
| `svg-empty-desc`       | A `desc` element is not empty (`LOGO_INVALID_CONTENT`)                                                                                                                           |
| `svg-element`          | Only the elements of the validation schema, not the other static SVG elements listed below (`LOGO_INVALID_ELEMENT`)                                                              |
| `svg-foreign-element`  | No elements in other namespaces outside `metadata` (`LOGO_INVALID_ELEMENT`)                                                                                                      |
| `svg-metadata-content` | `metadata` has text content only (`LOGO_INVALID_ELEMENT`)                                                                                                                        |

The rules below apply in both modes. Namespaces are resolved, and elements are checked against an allowlist: the element set of the validation schema in section 7 of the profile, plus static SVG 1.1 rendering elements found in published logos (`style`, `clipPath`, `mask`, `pattern`, `symbol`, `marker`, `tspan`, `textPath`, filter primitives other than `feImage`, and a few font elements). Script, interactivity, linking, multimedia, `image`, `switch`, `foreignObject` and animation elements are rejected, as are XHTML and MathML elements and SVG elements inside `metadata`. Elements in other namespaces, such as RDF metadata, are allowed by default.

These are rejected in every element and namespace:

- event handler attributes (any attribute whose local name starts with `on`)
- `href` in any namespace (XLink, no namespace, or another prefix) unless it is a same-document `#fragment` reference
- `url()` references that are not `#fragment`, `@import`, CSS image functions and CSS escapes, in `style` elements, `style` attributes and presentation attributes
- a non-empty `xml:base`
- processing instructions such as `xml-stylesheet`, DTDs with an internal subset, and entity references other than the predefined ones and character references
- markup that an HTML parser would read differently: `<` inside CDATA sections, comments that contain `<`, `>` or `--`, and a `font` element with `color`, `face` or `size` attributes

| Code                      | Description                                                              |
| ------------------------- | ------------------------------------------------------------------------ |
| `INVALID_XML_FILE`        | Not well-formed XML, or XML features that are not allowed (DTD, entity)  |
| `INVALID_SVG_FILE`        | The root element is not `svg` in the SVG namespace                       |
| `INVALID_BASE_PROFILE`    | `baseProfile` is not `tiny-ps`                                           |
| `LOGO_MISSING_TITLE`      | No `title` child of the root element, or it is empty                     |
| `LOGO_INVALID_ROOT_ATTRS` | The root element has `x` or `y` attributes                               |
| `LOGO_INVALID_ELEMENT`    | An element that is not allowed, `details.element` names it               |
| `LOGO_INVALID_ATTRIBUTE`  | An event handler attribute or `xml:base`, `details.attribute` names it   |
| `LOGO_INCLUDES_REFERENCE` | An external reference, `details.link` has the value                      |
| `LOGO_INVALID_CONTENT`    | A processing instruction, unexpected markup in text or comments, nesting |

## Example Output

### BIMI Pass

```json
{
    "status": {
        "result": "pass",
        "header": {
            "selector": "default",
            "d": "example.com"
        },
        "policy": {
            "authority": "none",
            "authority-uri": "https://example.com/bimi/vmc.pem"
        }
    },
    "location": "https://example.com/bimi/logo.svg",
    "authority": "https://example.com/bimi/vmc.pem",
    "preference": "brand",
    "rr": "v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/vmc.pem; avp=brand",
    "info": "bimi=pass header.selector=default header.d=example.com policy.authority=none policy.authority-uri=https://example.com/bimi/vmc.pem"
}
```

### BIMI Skipped (DMARC Failed)

```json
{
    "status": {
        "result": "skipped",
        "comment": "message failed DMARC",
        "header": {}
    },
    "info": "bimi=skipped (message failed DMARC)"
}
```

### BIMI Skipped (Policy Too Lax)

```json
{
    "status": {
        "result": "skipped",
        "comment": "too lax DMARC policy",
        "header": {}
    },
    "info": "bimi=skipped (too lax DMARC policy)"
}
```

### BIMI None (No Record)

```json
{
    "status": {
        "result": "none",
        "header": {}
    },
    "info": "bimi=none"
}
```

### BIMI Fail (Invalid Record)

```json
{
    "status": {
        "result": "fail",
        "comment": "missing location value in dns record",
        "header": {
            "selector": "default",
            "d": "example.com"
        }
    },
    "rr": "v=BIMI1;",
    "info": "bimi=fail (missing location value in dns record) header.selector=default header.d=example.com"
}
```

### VMC Validation Result

```json
{
    "location": {
        "url": "https://example.com/bimi/logo.svg",
        "success": true,
        "logoFile": "PHN2ZyB4bWxucz0i...",
        "hashAlgo": "sha256",
        "hashValue": "abc123..."
    },
    "authority": {
        "url": "https://example.com/bimi/vmc.pem",
        "success": true,
        "domainVerified": true,
        "hashMatch": true,
        "vmc": {
            "type": "VMC",
            "mediaType": "image/svg+xml",
            "logoFile": "PHN2ZyB4bWxucz0i...",
            "hashAlgo": "sha256",
            "hashValue": "abc123...",
            "validHash": true,
            "certificate": {
                "subjectAltName": ["example.com", "*.example.com"]
            }
        }
    },
    "headers": {
        "indicator": "BIMI-Indicator: PHN2ZyB4bWxucz0i...",
        "location": "BIMI-Location: v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/vmc.pem",
        "preference": "BIMI-Logo-Preference: avp=brand"
    },
    "status": {
        "result": "pass",
        "header": {
            "selector": "default",
            "d": "example.com"
        },
        "policy": {
            "authority": "pass",
            "authority-uri": "https://example.com/bimi/vmc.pem"
        }
    },
    "info": "bimi=pass policy.authority=pass policy.authority-uri=\"https://example.com/bimi/vmc.pem\" header.selector=default header.d=example.com"
}
```
