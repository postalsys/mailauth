// Public data shapes of mailauth: the options the functions take and the results they
// return. Re-exported from the package entry point. Every optional property is declared
// with an explicit `| undefined` so that a consumer compiling with
// exactOptionalPropertyTypes can pass a value that may be undefined.

import type { Readable } from 'node:stream';
/**
 * DNS resolver function type for custom DNS resolution
 */
export type DNSResolver = (domain: string, rrtype: string) => Promise<string[][] | string[]>;

/**
 * Input types accepted by mailauth functions
 */
export type MessageInput = Readable | Buffer | string;

// ============================================================================
// Main authenticate() function
// ============================================================================

/**
 * Options for the authenticate() function
 */
export interface AuthenticateOptions {
    /**
     * If true, parse ip and helo values from Received header and sender value from Return-Path
     */
    trustReceived?: boolean | undefined;

    /**
     * Address from MAIL FROM
     */
    sender?: string | undefined;

    /**
     * Client IP address
     */
    ip?: string | undefined;

    /**
     * Hostname from EHLO/HELO
     */
    helo?: string | undefined;

    /**
     * MTA/MX hostname (defaults to os.hostname())
     */
    mta?: string | undefined;

    /**
     * Minimal allowed length of public keys in bits (default: 1024)
     * If DKIM/ARC key is smaller, verification fails
     */
    minBitLength?: number | undefined;

    /**
     * If true, rsa-sha1 DKIM signatures get `policy` (weak-algorithm) as in strict mode and are
     * not counted for DMARC, while every other check keeps the lenient default. Verification
     * only (default: false)
     */
    rejectRsaSha1?: boolean | undefined;

    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver | undefined;

    /**
     * If true, do not perform ARC validation and sealing
     */
    disableArc?: boolean | undefined;

    /**
     * If true, do not perform DMARC check
     */
    disableDmarc?: boolean | undefined;

    /**
     * If true, do not perform BIMI check
     */
    disableBimi?: boolean | undefined;

    /**
     * Require aligned DKIM signature for BIMI
     */
    bimiWithAlignedDkim?: boolean | undefined;

    /**
     * ARC sealing options
     */
    seal?: ARCSealOptions | undefined;

    /**
     * Follow the RFCs exactly instead of the lenient defaults (default: false). Passed on
     * to every check (DKIM, SPF, ARC, DMARC, BIMI and ARC sealing), BIMI only uses it for the
     * format of its Authentication-Results entry. In strict mode:
     *
     * - rsa-sha1 DKIM signatures are reported as `dkim=policy` (`policy.dkim-rules=weak-algorithm`)
     * - DKIM-Signature and key record syntax is validated (RFC 6376 sections 3.2, 3.5, 3.6.1, 6.1.1)
     * - a body hash mismatch is reported as `dkim=fail`, and a signature that can not be
     *   processed as `dkim=neutral` instead of being left out
     * - DKIM results report `header.d` and the AUID as `header.i`
     * - email identities in Authentication-Results use the `local-part@domain` form of RFC 8601 section 2.2
     * - Authentication-Results is placed above Received-SPF (RFC 8601 section 5)
     *
     * What the lenient default accepts and strict mode would reject is listed in the
     * `warnings` array of the affected result. It is never written into the headers
     */
    strict?: boolean | undefined;

    /**
     * Verify DKIM2 header fields as well (default: false). Experimental, built against
     * draft-ietf-dkim-dkim2-spec-06. The result is added to Authentication-Results with the
     * `dkim2` method of draft-gondwana-dkim2-authres-00 and does not take part in DMARC
     */
    dkim2?: boolean | undefined;

    /**
     * RCPT TO addresses of the delivery, checked against the rt= tag of the highest
     * DKIM2-Signature. `sender` is checked against its mf= tag
     */
    rcptTo?: string | string[] | undefined;

    /**
     * Extra DKIM2 verifier options
     */
    dkim2Options?: Pick<DKIM2VerifyOptions, 'curTime' | 'maxSignatureAge' | 'maxFutureTime' | 'maxInstances' | 'checkReplay'> | undefined;
}

/**
 * ARC sealing options
 */
export interface ARCSealOptions {
    /**
     * ARC key domain name
     */
    signingDomain: string;

    /**
     * ARC key selector
     */
    selector: string;

    /**
     * Private key for signing (PEM format)
     */
    privateKey: string | Buffer;

    /**
     * Canonicalization algorithm (default: 'relaxed/relaxed')
     */
    canonicalization?: string | undefined;

    /**
     * Signing algorithm, 'rsa-sha256' or 'ed25519-sha256'. Follows the private key type when
     * not set. Used for both the ARC-Message-Signature and the ARC-Seal
     */
    algorithm?: string | undefined;

    /**
     * Chain validation status for the ARC-Seal cv= tag: 'none', 'pass' or 'fail' (compared
     * case-insensitively). Defaults to 'none' for the first set and is required for any later
     * set. `authenticate()` always sets it from the ARC validation result and ignores this value
     */
    cv?: 'none' | 'pass' | 'fail' | string | undefined;

    /**
     * ARC instance (i= tag), 1 to 50. Defaults to one more than the highest instance on the
     * message. An instance that already exists is refused, and one that leaves a gap is
     * refused in strict mode (the default mode seals it and adds an `arc-instance-gap` warning).
     * `authenticate()` ignores it and always uses the next instance
     */
    i?: number | undefined;

    /**
     * Authentication-Results payload for the ARC-Authentication-Results header (the part after
     * "i=N;"). Required, and a line break is only allowed as folding (CRLF followed by a space or
     * tab). `authenticate()` always sets it from its own results and ignores this value
     */
    authResults?: string | undefined;

    /**
     * Header fields to include in the ARC-Message-Signature, as an array or a colon separated
     * string. Defaults to DKIM-Signature and the default DKIM header list. ARC header fields and
     * Authentication-Results are never included (RFC 8617 section 4.1.2)
     */
    headerList?: string[] | string | undefined;

    /**
     * Signing timestamp
     */
    signTime?: Date | string | number | undefined;

    /**
     * Follow the RFCs exactly instead of the lenient defaults (default: false)
     */
    strict?: boolean | undefined;
}

/**
 * Policy information attached to authentication status
 */
export interface AuthPolicy {
    /**
     * DKIM policy rules: 'weak-key' when the key is shorter than minBitLength, 'weak-algorithm'
     * for an rsa-sha1 signature in strict mode
     */
    'dkim-rules'?: string | undefined;

    /**
     * Additional policy properties
     */
    [key: string]: string | undefined;
}

/**
 * Status result from authentication checks
 */
export interface AuthStatus {
    /**
     * The result keyword. `temperr` is deprecated, BIMI reports `temperror` now
     */
    result: 'pass' | 'fail' | 'neutral' | 'none' | 'temperror' | 'temperr' | 'permerror' | 'policy' | 'softfail' | 'skipped' | 'declined';
    comment?: string | undefined;
    header?: Record<string, any> | undefined;
    smtp?:
        | {
              mailfrom?: string | undefined;
              helo?: string | undefined;
          }
        | undefined;
    policy?: AuthPolicy | undefined;
}

/**
 * Lax acceptance markers of a DKIM result: what the default mode accepted and strict mode
 * would reject
 *
 * - `rsa-sha1`: the signature uses rsa-sha1 (RFC 8301 section 3.1)
 * - `tag-syntax`: the signature is not valid tag-list syntax (duplicate tags, upper case tag
 *   names, a malformed c=, t=, x= or l= value, an l= larger than the canonicalized body, or a d=
 *   or s= that is not a domain name)
 * - `missing-v`, `missing-h` (and the other `missing-*`): a required tag is missing
 * - `invalid-v`: v= is not "1"
 * - `identity-domain`: the i= domain is not d= or its subdomain, or it is a subdomain while
 *   the key has t=s
 * - `invalid-expiration`: x= is equal to t=
 * - `query-method`: q= does not list dns/txt
 * - `key-syntax`: the key record is not valid tag-list syntax, or a k=, s= or t= value has
 *   whitespace inside it
 * - `key-v-syntax`: the key record v= is not the first tag, or not exactly "DKIM1"
 * - `key-type-inferred`: an ed25519 key was found from its length, without k=ed25519
 * - `key-ed25519-spki`: an ed25519 key was published as a SubjectPublicKeyInfo structure, not
 *   as the bare 32 octet key of RFC 8463 section 4.2
 * - `ams-c-default`: ARC-Message-Signature results only, the signature has no c= and only
 *   verified with relaxed/relaxed instead of the simple/simple default
 */
export type DKIMWarning =
    | 'rsa-sha1'
    | 'tag-syntax'
    | 'missing-v'
    | 'missing-a'
    | 'missing-b'
    | 'missing-bh'
    | 'missing-d'
    | 'missing-h'
    | 'missing-s'
    | 'invalid-v'
    | 'identity-domain'
    | 'invalid-expiration'
    | 'query-method'
    | 'key-syntax'
    | 'key-v-syntax'
    | 'key-type-inferred'
    | 'key-ed25519-spki'
    | 'ams-c-default';

/**
 * DKIM verification result for a single signature
 */
export interface DKIMResult {
    /**
     * Signature identifier, the sha256 hash of the signature value
     */
    id?: string | undefined;

    /**
     * Signing domain (d= tag)
     */
    signingDomain?: string | undefined;

    /**
     * Key selector (s= tag)
     */
    selector?: string | undefined;

    /**
     * Signature value (b= tag)
     */
    signature?: string | undefined;

    /**
     * Signature algorithm (a= tag), eg. 'rsa-sha256'
     */
    algo?: string | undefined;

    /**
     * Canonicalization (c= tag), eg. 'relaxed/relaxed'
     */
    format?: string | undefined;

    /**
     * Body hash calculated for the message
     */
    bodyHash?: string | undefined;

    /**
     * Body hash from the bh= tag
     */
    bodyHashExpecting?: string | undefined;

    /**
     * Signed header fields and the canonicalized header data (base64)
     */
    signingHeaders?:
        | {
              keys: string;
              headers: string[];
              canonicalizedHeader: string;
          }
        | undefined;

    /**
     * Verification status
     */
    status: AuthStatus & {
        /**
         * Signing domain if it aligns with the From domain, false otherwise. For a passing
         * signature this follows the DMARC verdict once DMARC found a record, before that it
         * only guesses relaxed alignment from the Public Suffix List. Always false when the From
         * header field does not yield a single Author Domain, as DMARC requires.
         */
        aligned?: string | false | undefined;

        /**
         * Number of body bytes left unsigned by an l= tag
         */
        underSized?: number | undefined;

        /**
         * True when the key record has the t=y flag, the signing domain is testing DKIM
         * (RFC 6376 section 3.6.1)
         */
        testing?: boolean | undefined;

        /**
         * What the default mode accepted and strict mode would reject. Only present when
         * there is something to report, never written into the Authentication-Results text
         */
        warnings?: DKIMWarning[] | undefined;
    };

    /**
     * Authentication-Results formatted info
     */
    info: string;

    /**
     * Signing time from the t= tag, as an ISO string
     */
    signTime?: string | null | undefined;

    /**
     * Expiration time from the x= tag, as an ISO string
     */
    expiresAfter?: string | null | undefined;

    /**
     * False when t= is in the future or x= has passed
     */
    signatureTimeValid?: boolean | undefined;

    /**
     * Size of the message body in bytes
     */
    sourceBodyLength?: number | undefined;

    /**
     * Number of canonicalized body bytes covered by the signature
     */
    canonBodyLength?: number | undefined;

    /**
     * Number of canonicalized body bytes in total
     */
    canonBodyLengthTotal?: number | undefined;

    /**
     * True when the signature has an l= tag
     */
    canonBodyLengthLimited?: boolean | undefined;

    /**
     * The l= value
     */
    canonBodyLengthLimit?: number | undefined;

    /**
     * Where the MIME structure starts in the body, for multipart messages
     */
    mimeStructureStart?: number | undefined;

    /**
     * Public key in PEM format
     */
    publicKey?: string | undefined;

    /**
     * RSA key size in bits
     */
    modulusLength?: number | undefined;

    /**
     * Key record as found in DNS
     */
    rr?: string | undefined;

    /**
     * @deprecated Never set, use `algo`
     */
    algorithm?: string | undefined;

    /**
     * @deprecated Never set, use `format`
     */
    canonicalization?: string | undefined;

    /**
     * @deprecated Never set, use `signTime`
     */
    signingTime?: Date | undefined;

    /**
     * @deprecated Never set, use `expiresAfter`
     */
    expiration?: Date | undefined;
}

/**
 * DKIM verification results
 */
export interface DKIMVerifyResult {
    /**
     * Addresses from the From header, as full addr-specs (the domain is what follows the last
     * "@"). The mailboxes of a group (RFC 6854) are included
     */
    headerFrom: string[];

    /**
     * Number of From header fields in the message. RFC 5322 allows only one
     */
    fromFields: number;

    /**
     * Syntax of the From header fields: "valid" (RFC 5322), "lax" (accepted only by the lenient
     * parsing, such as an unquoted comma in a display name) or "invalid" (no reliable addresses,
     * for example text after the angle-addr). DMARC is not evaluated for an "invalid" field, nor
     * for a "lax" one in strict mode
     */
    fromSyntax: 'valid' | 'lax' | 'invalid';

    /**
     * Domain from Return-Path header
     */
    envelopeFrom: string | false;

    /**
     * Individual signature verification results
     */
    results: DKIMResult[];

    /**
     * Parsed message headers (non-enumerable property)
     * Access with result.headers or Object.getOwnPropertyDescriptor()
     */
    readonly headers?:
        | {
              parsed: Array<{ key: string; casedKey: string; line: Buffer }>;
              original: Buffer;
          }
        | undefined;

    /**
     * ARC chain data for sealing (non-enumerable property)
     * Access with result.arc or Object.getOwnPropertyDescriptor()
     */
    readonly arc?: ARCSigningData | undefined;

    /**
     * ARC sealing options passed to dkimVerify (non-enumerable property)
     * Access with result.seal or Object.getOwnPropertyDescriptor()
     */
    readonly seal?: ARCSealOptions | undefined;
}

/**
 * SPF verification result
 */
export interface SPFResult {
    /**
     * Sender domain
     */
    domain: string;

    /**
     * Client IP address
     */
    'client-ip': string;

    /**
     * HELO/EHLO hostname
     */
    helo?: string | undefined;

    /**
     * Envelope sender address
     */
    'envelope-from'?: string | undefined;

    /**
     * Verification status
     */
    status: AuthStatus;

    /**
     * SPF record used for verification
     */
    rr?: string | undefined;

    /**
     * Formatted Received-SPF header
     */
    header: string;

    /**
     * Authentication-Results formatted info
     */
    info: string;

    /**
     * DNS lookup statistics
     */
    lookups?:
        | {
              limit: number;
              count: number;
              void: number;
              subqueries: Record<string, number>;
          }
        | undefined;

    /**
     * Explanation string published by the domain owner with the "exp" modifier
     * (RFC 7208 section 6.2). Only set for a "fail" result. This is third party text
     */
    explanation?: string | undefined;

    /**
     * Set in the default mode when something was accepted that strict mode would have
     * rejected: "syntax-error", "void-lookup-limit" or "non-ascii-local-part"
     */
    warnings?: string[] | undefined;
}

/**
 * ARC verification result
 */
export interface ARCResult {
    /**
     * ARC instance number
     */
    i: number | false;

    /**
     * Verification status
     */
    status: AuthStatus & {
        /**
         * Set for a failed chain: whether it is sealed with cv=fail, false when the newest
         * ARC-Seal on the message already says cv=fail (RFC 8617 section 5.1 step 2)
         */
        shouldSeal?: boolean | undefined;

        smtp?:
            | {
                  /**
                   * Client IP address, reported in strict mode (RFC 8617 section 6)
                   */
                  'remote-ip'?: string | undefined;
              }
            | undefined;
    };

    /**
     * ARC-Message-Signature verification result
     */
    signature?: DKIMResult | false | undefined;

    /**
     * Parsed Authentication-Results from ARC chain
     */
    authenticationResults?: Record<string, any> | undefined;

    /**
     * Authentication-Results formatted info
     */
    info?: string | undefined;

    /**
     * Formatted Authentication-Results header value
     */
    authResults?: string | undefined;

    /**
     * Why sealing failed, when a seal was requested but could not be created.
     * The message is left unsealed in that case
     */
    sealErrors?: ARCSealError[] | undefined;

    /**
     * What the default mode accepted in the chain that strict mode would reject, for example
     * 'arc-tag-syntax' (a tag-list syntax error or a tag name that is not lower case),
     * 'arc-instance-syntax' (an i= value that is not 1*2DIGIT, an ARC-Authentication-Results
     * whose i= is not first, or an ARC header field that was ignored for its i= value),
     * 'ams-c-default' (an ARC-Message-Signature without c= that only verified with
     * relaxed/relaxed), and the key record warnings of the DKIM result. Not set for a failing
     * chain, and never written into the headers
     */
    warnings?: string[] | undefined;

    /**
     * ARC chain entries (non-enumerable property)
     * Access with result.chain or Object.getOwnPropertyDescriptor()
     */
    readonly chain?: ARCChainEntry[] | undefined;
}

/**
 * DMARC verification result
 */
export interface DMARCResult {
    /**
     * Organizational Domain of the author domain, found with the DNS Tree Walk (RFC 9989 4.10)
     */
    domain: string;

    /**
     * Effective DMARC policy ('none', 'quarantine', 'reject'): p for the author domain's own
     * record, np or sp for an inherited one, one level lower with t=y. Like p, sp, testMode and
     * alignment, only set when a policy record was applied, not for a none result or a
     * temperror before a record was found
     */
    policy?: string | undefined;

    /**
     * Domain whose DMARC record the policy was taken from
     */
    policyDomain?: string | undefined;

    /**
     * Policy for organizational domain
     */
    p?: string | undefined;

    /**
     * Policy for subdomains
     */
    sp?: string | undefined;

    /**
     * Policy for non-existent subdomains, if published
     */
    np?: string | undefined;

    /**
     * True when the record has t=y, in which case policy is one level below the published one
     */
    testMode?: boolean | undefined;

    /**
     * DMARC DNS record
     */
    rr?: string | undefined;

    /**
     * Verification status
     */
    status: AuthStatus & {
        header?:
            | {
                  /**
                   * Author Domain (RFC 9989 section 9.1 header.from)
                   */
                  from?: string | undefined;

                  /**
                   * Domain of the DMARC record, omitted in strict mode (not a registered property for dmarc)
                   */
                  d?: string | undefined;
              }
            | undefined;

        policy?:
            | {
                  /**
                   * The policy that was applied (RFC 9989 section 9.1 policy.dmarc)
                   */
                  dmarc?: string | undefined;
              }
            | undefined;
    };

    /**
     * Alignment results, set when a policy record was applied
     */
    alignment?:
        | {
              spf: {
                  /**
                   * Aligned SPF domain, or undefined if no domain aligned
                   */
                  result?: string | undefined;
                  strict: boolean;
              };
              dkim: {
                  /**
                   * Aligned signing domain, or undefined if no domain aligned
                   */
                  result?: string | undefined;
                  strict: boolean;

                  /**
                   * Number of body bytes left unsigned by an l= tag. Reported for a signature that
                   * aligns at the organizational domain even if adkim=s rejected it, so that it stays
                   * a reliable content-integrity warning regardless of the alignment mode.
                   */
                  underSized?: number | undefined;
              };
          }
        | undefined;

    /**
     * Authentication-Results formatted info
     */
    info: string;

    /**
     * Error message if verification failed
     */
    error?: string | undefined;

    /**
     * What the default mode accepted and strict mode would reject, only present when there
     * is something to report
     */
    warnings?: string[] | undefined;
}

/**
 * BIMI verification result
 */
export interface BIMIResult {
    /**
     * Verification status. `declined` means the domain published a declination record,
     * `temperror` a DNS failure. `temperr` is deprecated and no longer reported
     */
    status: AuthStatus & {
        result: 'pass' | 'none' | 'fail' | 'skipped' | 'declined' | 'temperror' | 'temperr';
    };

    /**
     * BIMI DNS record
     */
    rr?: string | undefined;

    /**
     * Logo location URL
     */
    location?: string | undefined;

    /**
     * VMC (Verified Mark Certificate) authority URL
     */
    authority?: string | undefined;

    /**
     * Avatar preference from the avp= tag, set only for the valid values
     */
    preference?: 'personal' | 'brand' | undefined;

    /**
     * Assertion Record and BIMI-Selector syntax deviations that were accepted because `strict` was not set:
     * 'record-version-case', 'record-tag-case', 'record-syntax', 'uri-comma', 'location-format',
     * 'selector-version-case', 'selector-syntax'
     */
    warnings?: string[] | undefined;

    /**
     * Authentication-Results formatted info
     */
    info: string;
}

/**
 * Parsed Received header information
 */
export interface ReceivedChainEntry {
    /**
     * Hostname/IP that sent the message
     */
    from?:
        | {
              /**
               * Hostname or IP address
               */
              value: string;

              /**
               * The comments after the value, joined with spaces. Usually the TCP-info of
               * RFC 5321 section 4.4, whose last address literal is the connecting IP address
               */
              comment?: string | undefined;
          }
        | undefined;

    /**
     * Hostname that received the message
     */
    by?:
        | {
              /**
               * Receiving hostname
               */
              value: string;

              /**
               * Additional comment
               */
              comment?: string | undefined;
          }
        | undefined;

    /**
     * Protocol used for transmission (e.g., 'SMTP', 'ESMTP', 'ESMTPS')
     */
    with?:
        | {
              value: string;
              comment?: string | undefined;
          }
        | undefined;

    /**
     * Message ID assigned by the receiving server
     */
    id?:
        | {
              value: string;
              comment?: string | undefined;
          }
        | undefined;

    /**
     * Recipient address
     */
    for?:
        | {
              value: string;
              comment?: string | undefined;
          }
        | undefined;

    /**
     * Envelope sender address from MAIL FROM
     */
    'envelope-from'?:
        | {
              value: string;
              comment?: string | undefined;
          }
        | undefined;

    /**
     * Transport security of the hop, taken from a comment that mentions TLS or a cipher, or
     * from an SMTPS `with` value. `value` is usually empty and `comment` holds the details
     */
    tls?:
        | {
              value: string;
              comment?: string | undefined;
          }
        | undefined;

    /**
     * The date-time part of the header, after the ";", as it was written
     */
    timestamp?: string | undefined;

    /**
     * The whole header line with whitespace collapsed to single spaces
     */
    full?: string | undefined;

    /**
     * Never set by the parser, only a "date" keyword of the header would add such a key, as a
     * `{ value, comment }` object like the other keywords. Kept for compatibility
     */
    date?: Date | undefined;

    /**
     * Additional parsed Received header fields
     */
    [key: string]: any;
}

/**
 * Result from authenticate() function
 */
export interface AuthenticateResult {
    /**
     * DKIM verification results
     */
    dkim: DKIMVerifyResult;

    /**
     * DKIM2 verification result, false unless the `dkim2` option is set
     */
    dkim2: DKIM2VerifyResult | false;

    /**
     * SPF verification result
     */
    spf: SPFResult | false;

    /**
     * DMARC verification result
     */
    dmarc: DMARCResult | false;

    /**
     * ARC verification result
     */
    arc: ARCResult | false;

    /**
     * BIMI verification result
     */
    bimi: BIMIResult | false;

    /**
     * Parsed Received header chain
     */
    receivedChain?: ReceivedChainEntry[] | undefined;

    /**
     * Combined authentication headers to prepend to message
     */
    headers: string;

    /**
     * Why DMARC was not evaluated when `dmarc` is false because the From header has no
     * domain or more than one (RFC 9989 section 5.3.1). Such a message can be treated as
     * suspicious (RFC 9989 section 11.5)
     */
    dmarcSkipReason?: 'no-author-domain' | 'multiple-author-domains' | 'invalid-author-domain' | 'multiple-from-fields' | undefined;
}

// ============================================================================
// DKIM Sign
// ============================================================================

/**
 * A single DKIM signature to create, an entry of `DKIMSignOptions.signatureData`
 */
export interface DKIMSignatureData {
    /**
     * Signing domain (d= tag)
     */
    signingDomain: string;

    /**
     * Key selector (s= tag)
     */
    selector: string;

    /**
     * Private key for signing (PEM format). An entry without a key is not signed and gets an
     * `ENOKEY` error
     */
    privateKey: string | Buffer;

    /**
     * Overrides the shared `canonicalization`
     */
    canonicalization?: string | undefined;

    /**
     * Overrides the shared `algorithm`
     */
    algorithm?: string | undefined;

    /**
     * Overrides the shared `headerList`
     */
    headerList?: string[] | string | undefined;

    /**
     * Maximum body length to sign (l= tag)
     */
    maxBodyLength?: number | undefined;

    /**
     * Identity (i= tag), an address whose domain is the signing domain or its subdomain.
     * Given unencoded, it is written as dkim-quoted-printable (`jõgi@example.com` as
     * `i=j=C3=B5gi@example.com`)
     */
    identity?: string | undefined;
}

/**
 * DKIM signing options. The values of each signature are set in `signatureData`, the other
 * options apply to all of them
 */
export interface DKIMSignOptions {
    /**
     * Canonicalization algorithm (default: 'relaxed/relaxed')
     * Format: 'header/body' where each can be 'simple' or 'relaxed'
     */
    canonicalization?: string | undefined;

    /**
     * Signing algorithm, defaults to 'rsa-sha256' or 'ed25519-sha256' depending on the key type.
     * Supported: 'rsa-sha256', 'ed25519-sha256' and 'rsa-sha1'. rsa-sha1 is historic
     * (RFC 8301): it adds the 'rsa-sha1' warning, and strict mode refuses it
     */
    algorithm?: string | undefined;

    /**
     * Header fields to sign, as an array or a colon separated string. Default includes
     * From, Subject, Date, To, etc. Set per signature in `signatureData` or for all of them.
     * A name listed more than once is over-signed: it appears in h= as many times as it is
     * listed or as the message has that field, whichever is more (`'From:From'`)
     */
    headerList?: string[] | string | undefined;

    /**
     * Signing timestamp (defaults to current time)
     */
    signTime?: Date | string | number | undefined;

    /**
     * Signature expiration time
     */
    expires?: Date | string | number | undefined;

    /**
     * The signatures to create. Without any, nothing is signed and `errors` holds an
     * `ENOSIGNATURE` error
     */
    signatureData: DKIMSignatureData[];

    /**
     * Follow the RFCs exactly (default: false). Strict mode refuses rsa-sha1, RSA keys
     * shorter than 1024 bits, an expiration that is not after the signing time, a signing
     * time that does not fit into t=, and a d=, s= or i= that is not valid RFC 6376 syntax.
     * The default mode signs these and lists them in `warnings`. A d=, s= or identity that
     * would break out of its tag is refused in both modes
     */
    strict?: boolean | undefined;
}

/**
 * Parsed DKIM/ARC header tag-value pair
 */
export interface ParsedHeaderValue {
    /**
     * Tag name
     */
    key?: string | undefined;

    /**
     * Tag value
     */
    value?: string | number | undefined;
}

/**
 * Parsed DKIM/ARC header structure
 */
export interface ParsedHeader {
    /**
     * Original header line
     */
    original?: string | undefined;

    /**
     * Parsed tag-value pairs
     */
    parsed?:
        | {
              /**
               * Instance number (i= tag for ARC)
               */
              i?: ParsedHeaderValue | undefined;

              /**
               * Algorithm (a= tag)
               */
              a?: ParsedHeaderValue | undefined;

              /**
               * Signature data (b= tag)
               */
              b?: ParsedHeaderValue | undefined;

              /**
               * Body hash (bh= tag)
               */
              bh?: ParsedHeaderValue | undefined;

              /**
               * Canonicalization (c= tag)
               */
              c?: ParsedHeaderValue | undefined;

              /**
               * Signing domain (d= tag)
               */
              d?: ParsedHeaderValue | undefined;

              /**
               * Selector (s= tag)
               */
              s?: ParsedHeaderValue | undefined;

              /**
               * Signed headers (h= tag)
               */
              h?: ParsedHeaderValue | undefined;

              /**
               * Chain validation result (cv= tag for ARC-Seal)
               */
              cv?: ParsedHeaderValue | undefined;

              /**
               * Timestamp (t= tag)
               */
              t?: ParsedHeaderValue | undefined;

              /**
               * Additional parsed properties
               */
              [key: string]: ParsedHeaderValue | undefined;
          }
        | undefined;

    /**
     * Signing algorithm type (e.g., 'rsa', 'ed25519')
     */
    signAlgo?: string | undefined;

    /**
     * Full algorithm (e.g., 'rsa-sha256')
     */
    algorithm?: string | undefined;
}

/**
 * ARC chain entry representing a single ARC set (i=N)
 */
export interface ARCChainEntry {
    /**
     * ARC instance number
     */
    i: number;

    /**
     * ARC-Seal header
     */
    'arc-seal'?: ParsedHeader | undefined;

    /**
     * ARC-Message-Signature header
     */
    'arc-message-signature'?: ParsedHeader | undefined;

    /**
     * ARC-Authentication-Results header
     */
    'arc-authentication-results'?: ParsedHeader | undefined;

    /**
     * Message signature verification result (for last entry)
     */
    messageSignature?: DKIMResult | undefined;
}

/**
 * ARC signing data returned from DKIM signing
 */
export interface ARCSigningData {
    /**
     * ARC chain from message headers (false if no chain found)
     */
    chain: ARCChainEntry[] | false;

    /**
     * Last entry in the ARC chain
     */
    lastEntry?: ARCChainEntry | undefined;

    /**
     * ARC instance number for signing
     */
    instance?: number | undefined;

    /**
     * Generated ARC-Message-Signature header
     */
    messageSignature?: string | undefined;

    /**
     * Error encountered during ARC processing
     */
    error?: Error | undefined;

    /**
     * ARC signing domain (from options)
     */
    signingDomain?: string | undefined;

    /**
     * ARC key selector (from options)
     */
    selector?: string | undefined;

    /**
     * ARC private key (from options)
     */
    privateKey?: string | Buffer | undefined;
}

/**
 * A signature that could not be created
 */
export interface DKIMSignError {
    /**
     * Why the signature was not created. `err.code` is eg. 'ENOFROM', 'EINVALIDALGO',
     * 'EINVALIDTYPE', 'ESHORTKEY', 'EINVALIDDOMAIN', 'EINVALIDSELECTOR', 'EINVALIDIDENTITY',
     * 'EINVALIDTIME', 'EINVALIDCANON', 'EINVALIDINSTANCE', 'ENOKEY' or 'ENOSIGNATURE'
     */
    err: Error & { code?: string | undefined };

    type?: 'DKIM' | 'ARC' | undefined;
    selector?: string | undefined;
    signingDomain?: string | undefined;
    algorithm?: string | undefined;
    canonicalization?: string | undefined;
}

/**
 * What the default mode signed although strict mode would have refused it
 *
 * - `rsa-sha1`: signed with rsa-sha1
 * - `weak-key`: signed with an RSA key shorter than 1024 bits
 * - `invalid-expiration`: the expiration is not after the signing time, or does not fit into x=
 * - `invalid-signtime`: the signing time does not fit into t=, which was left out
 * - `d-syntax`, `s-syntax`: d= or s= is not valid RFC 6376 syntax
 * - `identity-syntax`: the identity is not valid RFC 6376 i= syntax
 * - `identity-domain`: the identity domain is not the signing domain or its subdomain
 */
export type DKIMSignWarning =
    'rsa-sha1' | 'weak-key' | 'invalid-expiration' | 'invalid-signtime' | 'd-syntax' | 's-syntax' | 'identity-syntax' | 'identity-domain';

/**
 * DKIM signing result
 */
export interface DKIMSignResult {
    /**
     * DKIM-Signature header(s) to prepend to message, each ending with a CRLF. An empty
     * string when no signature was created
     */
    signatures: string;

    /**
     * ARC chain information (if ARC signing was performed)
     */
    arc?: ARCSigningData | undefined;

    /**
     * The signatures that could not be created, and why
     */
    errors: DKIMSignError[];

    /**
     * What was signed although strict mode would have refused it
     */
    warnings: DKIMSignWarning[];
}

// ============================================================================
// DKIM Verify
// ============================================================================

/**
 * DKIM verification options
 */
export interface DKIMVerifyOptions {
    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver | undefined;

    /**
     * Sender address (defaults to Return-Path header)
     */
    sender?: string | undefined;

    /**
     * Minimal allowed public key length in bits (default: 1024)
     */
    minBitLength?: number | undefined;

    /**
     * If true, rsa-sha1 signatures get `policy` (weak-algorithm) as in strict mode, while every
     * other check keeps the lenient default (default: false)
     */
    rejectRsaSha1?: boolean | undefined;

    /**
     * Current time for signature expiration checks
     */
    curTime?: Date | string | number | undefined;

    /**
     * ARC sealing options (if sealing should be prepared)
     */
    seal?: ARCSealOptions | undefined;

    /**
     * Follow RFC 6376, RFC 8301 and RFC 8463 exactly instead of the lenient default
     * (default: false). See `DKIMWarning` for what the default mode accepts
     */
    strict?: boolean | undefined;
}

// ============================================================================
// DKIM2 (experimental, draft-ietf-dkim-dkim2-spec-06, draft-ietf-dkim-dkim2-dns-00)
// ============================================================================

/**
 * A DKIM2 Recipe (draft-ietf-dkim-dkim2-spec-06 section 5). Each step either copies a range of
 * header fields (numbered from the bottom) or body lines (numbered from the top), or emits data
 */
export type DKIM2RecipeStep = { c: [number, number] } | { d: string[] };

export interface DKIM2Recipe {
    /**
     * Steps per lower case header field name. An empty array removes every field of that name
     */
    h?: Record<string, DKIM2RecipeStep[]> | undefined;

    /**
     * Steps for the body, or null when the previous body can not be recreated
     */
    b?: DKIM2RecipeStep[] | null | undefined;
}

export interface DKIM2SignatureKey {
    /**
     * Key selector
     */
    selector: string;

    /**
     * Private key, PEM or a raw 32 byte Ed25519 key
     */
    privateKey: string | Buffer;

    /**
     * "rsa-sha256" or "ed25519-sha256", follows the key type when not set
     */
    algorithm?: 'rsa-sha256' | 'ed25519-sha256' | undefined;
}

/**
 * DKIM2 signing options
 */
export interface DKIM2SignOptions {
    /**
     * Signing domain (d= tag)
     */
    signingDomain: string;

    /**
     * Signing keys. At most two keys per algorithm, each with its own selector
     */
    signatureData?: DKIM2SignatureKey[] | undefined;

    /**
     * Selector of a single key, used with `privateKey` when `signatureData` is not set
     */
    selector?: string | undefined;

    /**
     * A single private key, used with `selector` when `signatureData` is not set
     */
    privateKey?: string | Buffer | undefined;

    /**
     * Algorithm of the single key
     */
    algorithm?: 'rsa-sha256' | 'ed25519-sha256' | undefined;

    /**
     * SMTP MAIL FROM the message is sent with (mf= tag), "" or "<>" for the null sender.
     * Required unless `nextDomain` is set
     */
    mailFrom?: string | undefined;

    /**
     * SMTP RCPT TO addresses the message is sent to (rt= tag). Required unless `nextDomain` is set
     */
    rcptTo?: string | string[] | undefined;

    /**
     * Domain of the next DKIM2-Signature for an imaginary hop (nd= tag), instead of mailFrom and rcptTo
     */
    nextDomain?: string | undefined;

    /**
     * Nonce (n= tag), at most 64 printable ASCII characters without ";"
     */
    nonce?: string | undefined;

    /**
     * Flags (f= tag), such as "donotmodify", "donotexplode", "exploded", "feedback" or "feedhere"
     */
    flags?: string[] | undefined;

    /**
     * Hash algorithms of a new Message-Instance (default: ["sha256"])
     */
    hashAlgorithms?: ('sha256' | 'sha512')[] | undefined;

    /**
     * Recipe that recreates the previous instance of a message that was changed since its
     * highest Message-Instance. It is checked against that instance before signing
     */
    recipe?: DKIM2Recipe | undefined;

    /**
     * Signing time (t= tag), defaults to now
     */
    signTime?: Date | string | number | undefined;
}

/**
 * DKIM2 signing result
 */
export interface DKIM2SignResult {
    /**
     * Header fields to prepend to the message, each ending with CRLF
     */
    signatures: string;

    /**
     * The new DKIM2-Signature header field
     */
    signature: string;

    /**
     * The new Message-Instance header field, null when the message did not change
     */
    messageInstance: string | null;

    /**
     * i= of the new signature
     */
    i: number;

    /**
     * m= of the new signature
     */
    m: number;
}

/**
 * DKIM2 verification options
 */
export interface DKIM2VerifyOptions {
    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver | undefined;

    /**
     * SMTP MAIL FROM of the delivery, "" for the null sender. Compared with mf= of the highest
     * DKIM2-Signature when set
     */
    mailFrom?: string | undefined;

    /**
     * SMTP RCPT TO addresses of the delivery, each of which has to be listed in rt= of the highest
     * DKIM2-Signature
     */
    rcptTo?: string | string[] | undefined;

    /**
     * Seconds after t= when a signature expires (default: 1209600, 14 days), false to not check
     */
    maxSignatureAge?: number | false | undefined;

    /**
     * Seconds a t= may be ahead of the current time (default: 300), false to not check. Section 8.4
     * allows ignoring signatures from the future
     */
    maxFutureTime?: number | false | undefined;

    /**
     * Time to verify against (default: now)
     */
    curTime?: Date | string | number | undefined;

    /**
     * Most Message-Instance, and most DKIM2-Signature, header fields processed (default: 20)
     */
    maxInstances?: number | undefined;

    /**
     * Called with the replay key (the m=1 hashes) of the message. Return true when a message with
     * the same key was seen before; without an exploded flag the result is then FAIL
     */
    checkReplay?: ((replay: { key: string; exploded: boolean }) => Promise<boolean> | boolean) | undefined;
}

export type DKIM2Result = 'pass' | 'fail' | 'permerror' | 'temperror';

export type DKIM2Warning = 'mail-from-not-checked' | 'rcpt-to-not-checked';

export interface DKIM2Error {
    result: DKIM2Result;

    /**
     * Human-readable string of draft-ietf-dkim-dkim2-spec-06 section 11
     */
    message: string;

    /**
     * i= of the DKIM2-Signature the error is reported against
     */
    i?: number | undefined;

    /**
     * m= of the Message-Instance the error is about
     */
    m?: number | undefined;
}

export interface DKIM2InstanceResult {
    m: number;
    hashes: { algorithm: string; header: 'pass' | 'fail'; body: 'pass' | 'fail' | 'unknown' }[];
    recipe?: { headers: string[]; body: 'unchanged' | 'recipe' | 'unrecoverable' } | undefined;
}

export interface DKIM2SignatureValueResult {
    selector: string;
    algorithm: string;

    /**
     * "none" for an algorithm that is not supported and ignored
     */
    result?: DKIM2Result | 'none' | undefined;
    comment?: string | undefined;
    rr?: string | undefined;
    modulusLength?: number | undefined;

    /**
     * The key record has the t=y testing flag
     */
    testing?: boolean | undefined;
}

export interface DKIM2SignatureResult {
    i: number;
    m: number;
    signingDomain: string;
    timestamp: number;
    signTime: string;
    flags: string[];
    mailFrom?: string | undefined;
    rcptTo?: string[] | undefined;
    nextDomain?: string | undefined;
    nonce?: string | undefined;
    status: { result: DKIM2Result | 'skipped'; comment?: string | undefined };
    values: DKIM2SignatureValueResult[];
}

/**
 * DKIM2 verification result
 */
export interface DKIM2VerifyResult {
    status: {
        result: DKIM2Result | 'none';

        /**
         * The human-readable string of the reported failure
         */
        comment?: string | undefined;
        header?: { d?: string | undefined; i?: number | undefined } | undefined;

        /**
         * The parts of the SMTP envelope that were not given, so the highest DKIM2-Signature was
         * not compared with them and an unchanged copy sent to someone else would pass as well.
         * Only present when there is something to report, never written into `info`
         */
        warnings?: DKIM2Warning[] | undefined;
    };

    /**
     * Authentication-Results resinfo
     */
    info: string;
    errors: DKIM2Error[];
    instances: DKIM2InstanceResult[];
    signatures: DKIM2SignatureResult[];

    /**
     * The key for replay detection and whether a signature allows copies
     */
    replay?: { key: string; exploded: boolean } | undefined;
}

/**
 * DKIM2 hashing options
 */
export interface DKIM2HashOptions {
    /**
     * Hash algorithms (default: ["sha256"])
     */
    algorithms?: ('sha256' | 'sha512')[] | undefined;
}

/**
 * DKIM2 hashes of a message
 */
export interface DKIM2HashResult {
    /**
     * Names of the hashed header fields, in the order they are hashed
     */
    headers: string[];

    /**
     * The hash-sets of the h= tag of a Message-Instance
     */
    hashes: { algorithm: 'sha256' | 'sha512'; headerHash: string; bodyHash: string }[];
}

// ============================================================================
// SPF
// ============================================================================

/**
 * SPF verification options
 */
export interface SPFOptions {
    /**
     * Email address from MAIL FROM
     */
    sender?: string | undefined;

    /**
     * Client IP address
     */
    ip: string;

    /**
     * Client EHLO/HELO hostname
     */
    helo?: string | undefined;

    /**
     * MTA hostname (defaults to os.hostname())
     */
    mta?: string | undefined;

    /**
     * Maximum DNS lookups allowed (default: 10)
     */
    maxResolveCount?: number | undefined;

    /**
     * Maximum void DNS lookups allowed (default: 2)
     */
    maxVoidCount?: number | undefined;

    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver | undefined;

    /**
     * Follow RFC 7208 exactly instead of the lenient default (default: false)
     */
    strict?: boolean | undefined;

    /**
     * Maximum time in milliseconds for the whole evaluation, after which the result is
     * temperror (RFC 7208 section 4.6.4). No limit by default
     */
    maxElapsedTime?: number | undefined;
}

// ============================================================================
// DMARC
// ============================================================================

/**
 * DMARC verification options
 */
export interface DMARCOptions {
    /**
     * Domain from From header
     */
    headerFrom: string | string[];

    /**
     * Number of From header fields the addresses came from. With more than one, DMARC
     * validation is not possible (reason "multiple-from-fields")
     */
    fromFields?: number | undefined;

    /**
     * Syntax of the From header field the addresses came from (see DKIMVerifyResult.fromSyntax).
     * With "invalid", or "lax" in strict mode, DMARC validation is not possible (reason
     * "invalid-author-domain"). "lax" adds the "from-syntax" warning in the default mode
     */
    fromSyntax?: 'valid' | 'lax' | 'invalid' | undefined;

    /**
     * Domains that passed SPF
     */
    spfDomains?: string[] | undefined;

    /**
     * Domains and alignment info from DKIM signatures
     */
    dkimDomains?:
        | Array<{
              id?: string | undefined;
              domain: string;
              aligned?: string | false | undefined;
              underSized?: number | undefined;
          }>
        | undefined;

    /**
     * ARC verification result
     */
    arcResult?: ARCResult | undefined;

    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver | undefined;

    /**
     * Follow RFC 9989 exactly instead of the lenient default (default: false)
     */
    strict?: boolean | undefined;
}

// ============================================================================
// ARC
// ============================================================================

/**
 * ARC data structure
 */
export interface ARCData {
    /**
     * ARC chain entries, false if the message has no ARC sets
     */
    chain: ARCChainEntry[] | false;

    /**
     * Last entry in the ARC chain
     */
    lastEntry?: ARCChainEntry | undefined;

    /**
     * Error encountered during ARC chain parsing
     */
    error?: Error | undefined;

    /**
     * The lower case cv= of the newest ARC-Seal in the header fields, or false if there is
     * none, set by the DKIM verifier. Read from the header fields even when the chain could not
     * be parsed, to decide whether a failed chain is sealed with cv=fail
     */
    latestCv?: string | false | undefined;
}

/**
 * An error from ARC sealing
 */
export interface ARCSealError {
    /**
     * The error. Codes include EINVALIDCV (a missing or invalid cv), EINVALIDINSTANCE (an
     * instance out of 1-50, a chain that already has 50 sets, one that already exists, or in
     * strict mode one that leaves a gap),
     * EARCCHAINFAILED (the newest ARC-Seal already has cv=fail, RFC 8617 section 5.1 step 2),
     * EINVALIDALGO and EINVALIDTYPE (an algorithm that is not supported or does not match the key),
     * EINVALIDAUTHRESULTS (a missing or empty authResults, or one with a line break that is not
     * CRLF folding)
     */
    err: Error & { code?: string | undefined };
    type?: string | undefined;
    selector?: string | undefined;
    signingDomain?: string | undefined;
    algorithm?: string | undefined;
    canonicalization?: string | undefined;
}

/**
 * ARC verification options
 */
export interface ARCOptions {
    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver | undefined;

    /**
     * Minimal allowed public key length in bits (default: 1024)
     */
    minBitLength?: number | undefined;

    /**
     * Follow RFC 8617 exactly instead of the lenient default (default: false). In strict mode
     * ARC-Seal and ARC-Message-Signature tag lists must be valid RFC 6376 section 3.2 syntax
     * with lower case tag names and every required tag, instance values must be 1*2DIGIT from
     * 1 to 50 (and come first in ARC-Authentication-Results), ARC header fields with an
     * invalid instance fail the chain instead of being ignored, an ARC-Message-Signature
     * without c= is only verified as simple/simple, and the arc= result also reports
     * arc=none and smtp.remote-ip
     */
    strict?: boolean | undefined;

    /**
     * Client IP address, reported as smtp.remote-ip in strict mode (RFC 8617 section 6)
     */
    ip?: string | undefined;
}

/**
 * Seal creation data for createSeal()
 */
export interface ARCCreateSealData {
    /**
     * Parsed message headers, when `input` is false
     */
    headers?: any | undefined;

    /**
     * ARC chain data of the message, when `input` is false
     */
    arc?: ARCData | ARCSigningData | undefined;

    /**
     * Sealing options, with `bodyHash` (the relaxed/relaxed sha256 body hash) when `input` is false
     */
    seal: ARCSealOptions & { bodyHash?: string | undefined };

    /**
     * Follow the RFCs exactly (default: false, or `seal.strict`)
     */
    strict?: boolean | undefined;
}

// ============================================================================
// BIMI
// ============================================================================

/**
 * BIMI lookup options
 */
export interface BIMIOptions {
    /**
     * DMARC verification result
     */
    dmarc?: DMARCResult | false | undefined;

    /**
     * Parsed message headers
     */
    headers?: any | undefined;

    /**
     * Require aligned DKIM signature
     */
    bimiWithAlignedDkim?: boolean | undefined;

    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver | undefined;

    /**
     * Parse the Assertion Record exactly (default: false): `v=BIMI1` and the tag names are
     * case-sensitive, syntax errors such as duplicate tags fail the record, and so do an `l=` URI with
     * another image format suffix and unencoded commas in URIs. Without it these are accepted and
     * reported in `warnings`. Also formats the Authentication-Results entry in the RFC 8601 section 2.2 form
     */
    strict?: boolean | undefined;
}

/**
 * VMC (Verified Mark Certificate) validation result
 */
export interface VMCValidationResult {
    /**
     * Logo file fetch and validation result
     */
    location?:
        | {
              /**
               * URL the logo was fetched from
               */
              url: string;

              /**
               * Whether the logo was successfully fetched and validated
               */
              success: boolean;

              /**
               * Error information if fetch/validation failed
               */
              error?:
                  | {
                        /**
                         * Human-readable error message
                         */
                        message: string;

                        /**
                         * Error code
                         */
                        code?: string | undefined;

                        /**
                         * Additional error details, for `SVG_VALIDATION_FAILED` the message and code of the SVG validation error
                         */
                        details?: any | undefined;

                        /**
                         * Redirect URL if logo location redirected
                         */
                        redirect?: string | undefined;
                    }
                  | undefined;

              /**
               * Base64-encoded SVG logo file content, uncompressed if the file was SVGZ. Set only when the
               * file passed SVG validation
               */
              logoFile?: string | undefined;

              /**
               * Hash algorithm used for logo verification (e.g., 'sha256')
               */
              hashAlgo?: string | undefined;

              /**
               * Hash value of the logo file
               */
              hashValue?: string | undefined;
          }
        | undefined;

    /**
     * VMC certificate fetch and validation result
     */
    authority?:
        | {
              /**
               * URL the VMC certificate was fetched from
               */
              url: string;

              /**
               * Whether the certificate was successfully fetched and validated
               */
              success: boolean;

              /**
               * Error information if fetch/validation failed
               */
              error?:
                  | {
                        /**
                         * Human-readable error message
                         */
                        message: string;

                        /**
                         * Error code
                         */
                        code?: string | undefined;

                        /**
                         * Additional error details
                         */
                        details?: any | undefined;

                        /**
                         * Redirect URL if authority location redirected
                         */
                        redirect?: string | undefined;
                    }
                  | undefined;

              /**
               * Parsed VMC certificate data
               */
              vmc?: any | undefined;

              /**
               * Whether the domain in the certificate matches the sender domain
               */
              domainVerified?: boolean | undefined;

              /**
               * Whether the logo hash in the certificate matches the fetched logo
               */
              hashMatch?: boolean | undefined;
          }
        | undefined;

    /**
     * The BIMI status of `bimiData` updated with the validation results (7.7): `fail` with a comment
     * when the indicator or the evidence document failed, `policy.authority` set to `pass` or `fail`
     * when an evidence document was checked. Set only when `bimiData.status.result` was `pass`
     */
    status?: BIMIResult['status'] | undefined;

    /**
     * Authentication-Results entry for the updated status, use it instead of the `info` of `bimi()`
     */
    info?: string | undefined;

    /**
     * SVG Tiny PS profile deviations of the logo files that were accepted because `strict` was not set,
     * for example 'svg-version'
     */
    warnings?: string[] | undefined;

    /**
     * BIMI headers for the message, set only when the logo and the evidence document (if any) validated
     */
    headers?:
        | {
              /**
               * BIMI-Indicator header with the base64-encoded SVG logo
               */
              indicator: string;

              /**
               * BIMI-Location header, with a= when the evidence document was verified
               */
              location: string;

              /**
               * BIMI-Logo-Preference header
               */
              preference?: string | undefined;
          }
        | undefined;
}

/**
 * BIMI data for VMC validation
 */
export interface BIMIData extends BIMIResult {
    locationPath?: Buffer | undefined;
    authorityPath?: Buffer | undefined;
}

/**
 * VMC validation options
 */
export interface VMCValidationOptions {
    /**
     * Validate the logo files exactly against the SVG Tiny PS profile (default: false). Without it,
     * the deviations that do not make a logo unsafe are accepted and listed in `warnings`. Also
     * formats `info` in the RFC 8601 section 2.2 form
     */
    strict?: boolean | undefined;

    /**
     * Maximum size of the logo file in bytes, also applied to an uncompressed SVGZ file (default: 65536)
     */
    maxLogoSize?: number | undefined;

    /**
     * Maximum size of the evidence document in bytes (default: 262144)
     */
    maxEvidenceSize?: number | undefined;

    /**
     * Time limit for each download in milliseconds, including redirects and the body (default: 30000)
     */
    timeout?: number | undefined;

    /**
     * undici Dispatcher used for the downloads
     */
    dispatcher?: any | undefined;

    /**
     * Time to validate the certificate chain at, passed to @postalsys/vmc (default: now)
     */
    now?: Date | undefined;

    /**
     * Trusted root certificates, a RootStore instance of @postalsys/vmc (default: the bundled VMC roots)
     */
    rootStore?: unknown;

    /**
     * Custom VMC validation options passed to @postalsys/vmc
     */
    [key: string]: any;
}

/**
 * SVG logo validation options
 */
export interface BIMISvgValidationOptions {
    /**
     * Apply the SVG Tiny PS profile exactly (default: false)
     */
    strict?: boolean | undefined;

    /**
     * Markers of the accepted profile deviations are added to this array when `strict` is not set
     */
    warnings?: string[] | undefined;
}

// ============================================================================
// MTA-STS
// ============================================================================

/**
 * MTA-STS policy
 */
export interface MTASTSPolicy {
    /**
     * Policy ID from DNS (undefined when returned from parsePolicy)
     */
    id?: string | false | undefined;

    /**
     * Policy version (should be 'STSv1')
     */
    version?: string | undefined;

    /**
     * Policy mode ('enforce', 'testing', 'none')
     */
    mode: 'enforce' | 'testing' | 'none';

    /**
     * Maximum age in seconds
     */
    maxAge?: number | undefined;

    /**
     * List of allowed MX hostnames (may include wildcards like *.example.com)
     */
    mx?: string[] | undefined;

    /**
     * Policy expiration timestamp
     */
    expires?: string | undefined;

    /**
     * Error encountered during policy fetch
     */
    error?: Error | undefined;

    /**
     * Policy ID from DNS that could not be fetched, set on a cached policy that is kept in use instead
     */
    retryId?: string | undefined;

    /**
     * ISO 8601 timestamp before which the policy for `retryId` is not fetched again (RFC 8461 3.3)
     */
    retryAfter?: string | undefined;
}

/**
 * MTA-STS policy fetch result
 */
export interface MTASTSPolicyResult {
    /**
     * Fetched or renewed policy
     */
    policy: MTASTSPolicy;

    /**
     * Status of the fetch operation
     *
     * - `found`: a new or changed policy was fetched
     * - `renewed`: the cached policy has the same id and has not expired, it is returned without a fetch
     * - `not_found`: the domain has no MTA-STS policy
     * - `errored`: the policy could not be fetched. With a valid cached policy, that policy is
     *   returned with `error` set
     */
    status: 'found' | 'renewed' | 'not_found' | 'errored';

    /**
     * Lax acceptance markers, only present when the default lax mode accepted something strict mode would reject
     */
    warnings?: MTASTSWarning[] | undefined;
}

/**
 * Markers for input that the default lax mode accepted but `strict: true` would reject
 *
 * - `txt-syntax`: the TXT record does not match the RFC 8461 3.1 syntax
 * - `http-status`: the policy was served with a 2xx status other than 200
 * - `content-type`: the policy was not served as `text/plain`
 * - `policy-syntax`: the policy file does not match the RFC 8461 3.2 syntax
 * - `cert-identity`: the Policy Host certificate matched only through the CN or a partial-label wildcard
 * - `expired-cache`: an expired cached policy was returned because the policy could not be fetched
 */
export type MTASTSWarning = 'txt-syntax' | 'http-status' | 'content-type' | 'policy-syntax' | 'cert-identity' | 'expired-cache';

/**
 * MTA-STS MX validation result
 */
export interface MTASTSValidationResult {
    /**
     * Whether the MX hostname is valid according to policy
     */
    valid: boolean;

    /**
     * Policy mode
     */
    mode: string;

    /**
     * Matching policy pattern (if valid)
     */
    match?: string | undefined;

    /**
     * Whether policy is in testing mode
     */
    testing: boolean;
}

/**
 * MTA-STS options
 */
export interface MTASTSOptions {
    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver | undefined;

    /**
     * Apply the RFC 8461 rules exactly (default false)
     */
    strict?: boolean | undefined;

    /**
     * Overall time limit for the HTTPS policy request in milliseconds (default 60000)
     */
    timeout?: number | undefined;

    /**
     * Maximum size of the policy file in bytes (default 65536)
     */
    maxPolicySize?: number | undefined;
}

// Note: MTA-STS functions (resolvePolicy, fetchPolicy, parsePolicy, validateMx, getPolicy)
// are not exported from the main module. Import them directly from 'mailauth/lib/mta-sts'.
