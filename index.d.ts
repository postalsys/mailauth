// Type definitions for mailauth
// Project: https://github.com/postalsys/mailauth
// Definitions by: Claude Code

/// <reference types="node" />

import { Readable, Transform } from 'stream';

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
    trustReceived?: boolean;

    /**
     * Address from MAIL FROM
     */
    sender?: string;

    /**
     * Client IP address
     */
    ip?: string;

    /**
     * Hostname from EHLO/HELO
     */
    helo?: string;

    /**
     * MTA/MX hostname (defaults to os.hostname())
     */
    mta?: string;

    /**
     * Minimal allowed length of public keys in bits (default: 1024)
     * If DKIM/ARC key is smaller, verification fails
     */
    minBitLength?: number;

    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver;

    /**
     * If true, do not perform ARC validation and sealing
     */
    disableArc?: boolean;

    /**
     * If true, do not perform DMARC check
     */
    disableDmarc?: boolean;

    /**
     * If true, do not perform BIMI check
     */
    disableBimi?: boolean;

    /**
     * Require aligned DKIM signature for BIMI
     */
    bimiWithAlignedDkim?: boolean;

    /**
     * ARC sealing options
     */
    seal?: ARCSealOptions;

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
    strict?: boolean;
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
    canonicalization?: string;

    /**
     * Signing algorithm, 'rsa-sha256' or 'ed25519-sha256'. Follows the private key type when
     * not set. Used for both the ARC-Message-Signature and the ARC-Seal
     */
    algorithm?: string;

    /**
     * Chain validation status for the ARC-Seal cv= tag: 'none', 'pass' or 'fail' (compared
     * case-insensitively). Defaults to 'none' for the first set and is required for any later
     * set. `authenticate()` sets it from the ARC validation result
     */
    cv?: 'none' | 'pass' | 'fail' | string;

    /**
     * ARC instance (i= tag), 1 to 50. Defaults to one more than the highest instance on the
     * message. An instance that already exists is refused, and one that leaves a gap is
     * refused in strict mode (the default mode seals it and adds an `arc-instance-gap` warning)
     */
    i?: number;

    /**
     * Authentication-Results payload for the ARC-Authentication-Results header (the part after
     * "i=N;"). `authenticate()` sets it from its own results
     */
    authResults?: string;

    /**
     * Header fields to include in the ARC-Message-Signature, as an array or a colon separated
     * string. Defaults to DKIM-Signature and the default DKIM header list. ARC header fields and
     * Authentication-Results are never included (RFC 8617 section 4.1.2)
     */
    headerList?: string[] | string;

    /**
     * Signing timestamp
     */
    signTime?: Date | string | number;

    /**
     * Follow the RFCs exactly instead of the lenient defaults (default: false)
     */
    strict?: boolean;
}

/**
 * Policy information attached to authentication status
 */
export interface AuthPolicy {
    /**
     * DKIM policy rules: 'weak-key' when the key is shorter than minBitLength, 'weak-algorithm'
     * for an rsa-sha1 signature in strict mode
     */
    'dkim-rules'?: string;

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
    comment?: string;
    header?: Record<string, any>;
    smtp?: {
        mailfrom?: string;
        helo?: string;
    };
    policy?: AuthPolicy;
}

/**
 * Lax acceptance markers of a DKIM result: what the default mode accepted and strict mode
 * would reject
 *
 * - `rsa-sha1`: the signature uses rsa-sha1 (RFC 8301 section 3.1)
 * - `tag-syntax`: the signature is not valid tag-list syntax (duplicate tags, upper case tag
 *   names, a malformed t=, x= or l= value, or a d= or s= that is not a domain name)
 * - `missing-v`, `missing-h` (and the other `missing-*`): a required tag is missing
 * - `invalid-v`: v= is not "1"
 * - `identity-domain`: the i= domain is not d= or its subdomain, or it is a subdomain while
 *   the key has t=s
 * - `invalid-expiration`: x= is equal to t=
 * - `query-method`: q= does not list dns/txt
 * - `key-syntax`: the key record is not valid tag-list syntax
 * - `key-v-syntax`: the key record v= is not the first tag, or not exactly "DKIM1"
 * - `key-type-inferred`: an ed25519 key was found from its length, without k=ed25519
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
    | 'key-type-inferred';

/**
 * DKIM verification result for a single signature
 */
export interface DKIMResult {
    /**
     * Signature identifier, the sha256 hash of the signature value
     */
    id?: string;

    /**
     * Signing domain (d= tag)
     */
    signingDomain?: string;

    /**
     * Key selector (s= tag)
     */
    selector?: string;

    /**
     * Signature value (b= tag)
     */
    signature?: string;

    /**
     * Signature algorithm (a= tag), eg. 'rsa-sha256'
     */
    algo?: string;

    /**
     * Canonicalization (c= tag), eg. 'relaxed/relaxed'
     */
    format?: string;

    /**
     * Body hash calculated for the message
     */
    bodyHash?: string;

    /**
     * Body hash from the bh= tag
     */
    bodyHashExpecting?: string;

    /**
     * Signed header fields and the canonicalized header data (base64)
     */
    signingHeaders?: {
        keys: string;
        headers: string[];
        canonicalizedHeader: string;
    };

    /**
     * Verification status
     */
    status: AuthStatus & {
        /**
         * Signing domain if it aligns with the From domain, false otherwise. For a passing
         * signature this follows the DMARC verdict once DMARC found a record, before that it
         * only guesses relaxed alignment from the Public Suffix List.
         */
        aligned?: string | false;

        /**
         * Number of body bytes left unsigned by an l= tag
         */
        underSized?: number;

        /**
         * True when the key record has the t=y flag, the signing domain is testing DKIM
         * (RFC 6376 section 3.6.1)
         */
        testing?: boolean;

        /**
         * What the default mode accepted and strict mode would reject. Only present when
         * there is something to report, never written into the Authentication-Results text
         */
        warnings?: DKIMWarning[];
    };

    /**
     * Authentication-Results formatted info
     */
    info: string;

    /**
     * Signing time from the t= tag, as an ISO string
     */
    signTime?: string | null;

    /**
     * Expiration time from the x= tag, as an ISO string
     */
    expiresAfter?: string | null;

    /**
     * False when t= is in the future or x= has passed
     */
    signatureTimeValid?: boolean;

    /**
     * Size of the message body in bytes
     */
    sourceBodyLength?: number;

    /**
     * Number of canonicalized body bytes covered by the signature
     */
    canonBodyLength?: number;

    /**
     * Number of canonicalized body bytes in total
     */
    canonBodyLengthTotal?: number;

    /**
     * True when the signature has an l= tag
     */
    canonBodyLengthLimited?: boolean;

    /**
     * The l= value
     */
    canonBodyLengthLimit?: number;

    /**
     * Where the MIME structure starts in the body, for multipart messages
     */
    mimeStructureStart?: number;

    /**
     * Public key in PEM format
     */
    publicKey?: string;

    /**
     * RSA key size in bits
     */
    modulusLength?: number;

    /**
     * Key record as found in DNS
     */
    rr?: string;

    /**
     * @deprecated Never set, use `algo`
     */
    algorithm?: string;

    /**
     * @deprecated Never set, use `format`
     */
    canonicalization?: string;

    /**
     * @deprecated Never set, use `signTime`
     */
    signingTime?: Date;

    /**
     * @deprecated Never set, use `expiresAfter`
     */
    expiration?: Date;
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
    readonly headers?: {
        parsed: Array<{ key: string; casedKey: string; line: Buffer }>;
        original: Buffer;
    };

    /**
     * ARC chain data for sealing (non-enumerable property)
     * Access with result.arc or Object.getOwnPropertyDescriptor()
     */
    readonly arc?: ARCSigningData;

    /**
     * ARC sealing options passed to dkimVerify (non-enumerable property)
     * Access with result.seal or Object.getOwnPropertyDescriptor()
     */
    readonly seal?: ARCSealOptions;
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
    helo?: string;

    /**
     * Envelope sender address
     */
    'envelope-from'?: string;

    /**
     * Verification status
     */
    status: AuthStatus;

    /**
     * SPF record used for verification
     */
    rr?: string;

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
    lookups?: {
        limit: number;
        count: number;
        void: number;
        subqueries: Record<string, number>;
    };

    /**
     * Explanation string published by the domain owner with the "exp" modifier
     * (RFC 7208 section 6.2). Only set for a "fail" result. This is third party text
     */
    explanation?: string;

    /**
     * Set in the default mode when something was accepted that strict mode would have
     * rejected: "syntax-error", "void-lookup-limit" or "non-ascii-local-part"
     */
    warnings?: string[];
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
        shouldSeal?: boolean;
    };

    /**
     * ARC-Message-Signature verification result
     */
    signature?: DKIMResult | false;

    /**
     * Parsed Authentication-Results from ARC chain
     */
    authenticationResults?: Record<string, any>;

    /**
     * Authentication-Results formatted info
     */
    info?: string;

    /**
     * Formatted Authentication-Results header value
     */
    authResults?: string;

    /**
     * Why sealing failed, when a seal was requested but could not be created.
     * The message is left unsealed in that case
     */
    sealErrors?: ARCSealError[];

    /**
     * What the default mode accepted in the chain that strict mode would reject, for example
     * 'arc-tag-syntax' (a tag-list syntax error or a tag name that is not lower case),
     * 'arc-instance-syntax' (an i= value that is not 1*2DIGIT, an ARC-Authentication-Results
     * whose i= is not first, or an ARC header field that was ignored for its i= value),
     * 'ams-c-default' (an ARC-Message-Signature without c= that only verified with
     * relaxed/relaxed), and the key record warnings of the DKIM result. Not set for a failing
     * chain, and never written into the headers
     */
    warnings?: string[];

    /**
     * ARC chain entries (non-enumerable property)
     * Access with result.chain or Object.getOwnPropertyDescriptor()
     */
    readonly chain?: ARCChainEntry[];
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
     * record, np or sp for an inherited one, one level lower with t=y
     */
    policy: string;

    /**
     * Domain whose DMARC record the policy was taken from
     */
    policyDomain?: string;

    /**
     * Policy for organizational domain
     */
    p: string;

    /**
     * Policy for subdomains
     */
    sp: string;

    /**
     * Policy for non-existent subdomains, if published
     */
    np?: string;

    /**
     * True when the record has t=y, in which case policy is one level below the published one
     */
    testMode: boolean;

    /**
     * DMARC DNS record
     */
    rr?: string;

    /**
     * Verification status
     */
    status: AuthStatus & {
        header?: {
            /**
             * Author Domain
             */
            from?: string;

            /**
             * Domain of the DMARC record, omitted in strict mode (not a registered property for dmarc)
             */
            d?: string;
        };

        policy?: {
            /**
             * The policy that was applied (RFC 8601 section 2.7.2 policy.dmarc)
             */
            dmarc?: string;
        };
    };

    /**
     * Alignment results
     */
    alignment: {
        spf: {
            /**
             * Aligned SPF domain, or undefined if no domain aligned
             */
            result?: string;
            strict: boolean;
        };
        dkim: {
            /**
             * Aligned signing domain, or undefined if no domain aligned
             */
            result?: string;
            strict: boolean;

            /**
             * Number of body bytes left unsigned by an l= tag. Reported for a signature that
             * aligns at the organizational domain even if adkim=s rejected it, so that it stays
             * a reliable content-integrity warning regardless of the alignment mode.
             */
            underSized?: number;
        };
    };

    /**
     * Authentication-Results formatted info
     */
    info: string;

    /**
     * Error message if verification failed
     */
    error?: string;

    /**
     * What the default mode accepted and strict mode would reject, only present when there
     * is something to report
     */
    warnings?: string[];
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
    rr?: string;

    /**
     * Logo location URL
     */
    location?: string;

    /**
     * VMC (Verified Mark Certificate) authority URL
     */
    authority?: string;

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
    from?: {
        /**
         * Hostname or IP address
         */
        value: string;

        /**
         * The comments after the value, joined with spaces. Usually the TCP-info of
         * RFC 5321 section 4.4, whose last address literal is the connecting IP address
         */
        comment?: string;
    };

    /**
     * Hostname that received the message
     */
    by?: {
        /**
         * Receiving hostname
         */
        value: string;

        /**
         * Additional comment
         */
        comment?: string;
    };

    /**
     * Protocol used for transmission (e.g., 'SMTP', 'ESMTP', 'ESMTPS')
     */
    with?: {
        value: string;
    };

    /**
     * Message ID assigned by the receiving server
     */
    id?: {
        value: string;
    };

    /**
     * Recipient address
     */
    for?: {
        value: string;
    };

    /**
     * Envelope sender address from MAIL FROM
     */
    'envelope-from'?: {
        value: string;
    };

    /**
     * Timestamp when the message was received
     */
    date?: Date;

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
    receivedChain?: ReceivedChainEntry[];

    /**
     * Combined authentication headers to prepend to message
     */
    headers: string;

    /**
     * Why DMARC was not evaluated when `dmarc` is false because the From header has no
     * domain or more than one (RFC 9989 section 5.3.1). Such a message can be treated as
     * suspicious (RFC 9989 section 11.5)
     */
    dmarcSkipReason?: 'no-author-domain' | 'multiple-author-domains' | 'invalid-author-domain' | 'multiple-from-fields';
}

/**
 * Verifies DKIM, SPF, DMARC, ARC, and BIMI for an email message
 *
 * @param input - RFC822 formatted message (stream, buffer, or string)
 * @param opts - Authentication options
 * @returns Authentication results including all protocol checks
 */
export function authenticate(input: MessageInput, opts?: AuthenticateOptions): Promise<AuthenticateResult>;

// ============================================================================
// DKIM Sign
// ============================================================================

/**
 * DKIM signing options
 */
export interface DKIMSignOptions {
    /**
     * Signing domain (d= tag)
     */
    signingDomain: string;

    /**
     * Key selector (s= tag)
     */
    selector: string;

    /**
     * Private key for signing (PEM format)
     */
    privateKey: string | Buffer;

    /**
     * Canonicalization algorithm (default: 'relaxed/relaxed')
     * Format: 'header/body' where each can be 'simple' or 'relaxed'
     */
    canonicalization?: string;

    /**
     * Signing algorithm, defaults to 'rsa-sha256' or 'ed25519-sha256' depending on the key type.
     * Supported: 'rsa-sha256', 'ed25519-sha256' and 'rsa-sha1'. rsa-sha1 is historic
     * (RFC 8301): it adds the 'rsa-sha1' warning, and strict mode refuses it
     */
    algorithm?: string;

    /**
     * Header fields to sign, as an array or a colon separated string. Default includes
     * From, Subject, Date, To, etc. Set per signature in `signatureData` or for all of them
     */
    headerList?: string[] | string;

    /**
     * Signing timestamp (defaults to current time)
     */
    signTime?: Date | string | number;

    /**
     * Signature expiration time
     */
    expires?: Date | string | number;

    /**
     * Maximum body length to sign (l= tag)
     */
    maxBodyLength?: number;

    /**
     * Identity (i= tag), an address whose domain is the signing domain or its subdomain
     */
    identity?: string;

    /**
     * Multiple signature configurations
     */
    signatureData?: DKIMSignOptions[];

    /**
     * Follow the RFCs exactly (default: false). Strict mode refuses rsa-sha1, RSA keys
     * shorter than 1024 bits, an expiration that is not after the signing time, a signing
     * time that does not fit into t=, and a d=, s= or i= that is not valid RFC 6376 syntax.
     * The default mode signs these and lists them in `warnings`. A d=, s= or identity that
     * would break out of its tag is refused in both modes
     */
    strict?: boolean;
}

/**
 * Parsed DKIM/ARC header tag-value pair
 */
export interface ParsedHeaderValue {
    /**
     * Tag name
     */
    key?: string;

    /**
     * Tag value
     */
    value?: string | number;
}

/**
 * Parsed DKIM/ARC header structure
 */
export interface ParsedHeader {
    /**
     * Original header line
     */
    original?: string;

    /**
     * Parsed tag-value pairs
     */
    parsed?: {
        /**
         * Instance number (i= tag for ARC)
         */
        i?: ParsedHeaderValue;

        /**
         * Algorithm (a= tag)
         */
        a?: ParsedHeaderValue;

        /**
         * Signature data (b= tag)
         */
        b?: ParsedHeaderValue;

        /**
         * Body hash (bh= tag)
         */
        bh?: ParsedHeaderValue;

        /**
         * Canonicalization (c= tag)
         */
        c?: ParsedHeaderValue;

        /**
         * Signing domain (d= tag)
         */
        d?: ParsedHeaderValue;

        /**
         * Selector (s= tag)
         */
        s?: ParsedHeaderValue;

        /**
         * Signed headers (h= tag)
         */
        h?: ParsedHeaderValue;

        /**
         * Chain validation result (cv= tag for ARC-Seal)
         */
        cv?: ParsedHeaderValue;

        /**
         * Timestamp (t= tag)
         */
        t?: ParsedHeaderValue;

        /**
         * Additional parsed properties
         */
        [key: string]: ParsedHeaderValue | undefined;
    };

    /**
     * Signing algorithm type (e.g., 'rsa', 'ed25519')
     */
    signAlgo?: string;

    /**
     * Full algorithm (e.g., 'rsa-sha256')
     */
    algorithm?: string;
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
    'arc-seal'?: ParsedHeader;

    /**
     * ARC-Message-Signature header
     */
    'arc-message-signature'?: ParsedHeader;

    /**
     * ARC-Authentication-Results header
     */
    'arc-authentication-results'?: ParsedHeader;

    /**
     * Message signature verification result (for last entry)
     */
    messageSignature?: DKIMResult;
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
    lastEntry?: ARCChainEntry;

    /**
     * ARC instance number for signing
     */
    instance?: number;

    /**
     * Generated ARC-Message-Signature header
     */
    messageSignature?: string;

    /**
     * Error encountered during ARC processing
     */
    error?: Error;

    /**
     * ARC signing domain (from options)
     */
    signingDomain?: string;

    /**
     * ARC key selector (from options)
     */
    selector?: string;

    /**
     * ARC private key (from options)
     */
    privateKey?: string | Buffer;
}

/**
 * A signature that could not be created
 */
export interface DKIMSignError {
    /**
     * Why the signature was not created. `err.code` is eg. 'ENOFROM', 'EINVALIDALGO',
     * 'EINVALIDTYPE', 'ESHORTKEY', 'EINVALIDDOMAIN', 'EINVALIDSELECTOR', 'EINVALIDIDENTITY',
     * 'EINVALIDTIME', 'EINVALIDCANON' or 'EINVALIDINSTANCE'
     */
    err: Error & { code?: string };

    type?: 'DKIM' | 'ARC';
    selector?: string;
    signingDomain?: string;
    algorithm?: string;
    canonicalization?: string;
}

/**
 * What the default mode signed although strict mode would have refused it
 *
 * - `rsa-sha1`: signed with rsa-sha1
 * - `weak-key`: signed with an RSA key shorter than 1024 bits
 * - `invalid-expiration`: the expiration is not after the signing time, or does not fit into x=
 * - `invalid-signtime`: the signing time does not fit into t=, which was left out
 * - `d-syntax`, `s-syntax`: d= or s= is not valid RFC 6376 syntax
 * - `identity-domain`: the identity domain is not the signing domain or its subdomain
 */
export type DKIMSignWarning = 'rsa-sha1' | 'weak-key' | 'invalid-expiration' | 'invalid-signtime' | 'd-syntax' | 's-syntax' | 'identity-domain';

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
    arc?: ARCSigningData;

    /**
     * The signatures that could not be created, and why
     */
    errors: DKIMSignError[];

    /**
     * What was signed although strict mode would have refused it
     */
    warnings: DKIMSignWarning[];
}

/**
 * Signs an email message with DKIM signature(s)
 *
 * @param input - RFC822 formatted message (stream, buffer, or string)
 * @param options - DKIM signing options
 * @returns DKIM signature header(s) and any errors
 */
export function dkimSign(input: MessageInput, options: DKIMSignOptions): Promise<DKIMSignResult>;

/**
 * Transform stream for DKIM signing
 * Prepends DKIM-Signature header to the message stream
 */
export class DkimSignStream extends Transform {
    /**
     * Creates a DKIM signing stream
     *
     * @param options - DKIM signing options
     */
    constructor(options: DKIMSignOptions);

    /**
     * The signatures that could not be created, set when the stream ends
     */
    errors: DKIMSignError[] | null;

    /**
     * What was signed although strict mode would have refused it, set when the stream ends
     */
    warnings: DKIMSignWarning[] | null;
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
    resolver?: DNSResolver;

    /**
     * Sender address (defaults to Return-Path header)
     */
    sender?: string;

    /**
     * Minimal allowed public key length in bits (default: 1024)
     */
    minBitLength?: number;

    /**
     * Current time for signature expiration checks
     */
    curTime?: Date | string | number;

    /**
     * ARC sealing options (if sealing should be prepared)
     */
    seal?: ARCSealOptions;

    /**
     * Follow RFC 6376, RFC 8301 and RFC 8463 exactly instead of the lenient default
     * (default: false). See `DKIMWarning` for what the default mode accepts
     */
    strict?: boolean;
}

/**
 * Verifies DKIM signatures in an email message
 *
 * @param input - RFC822 formatted message (stream, buffer, or string)
 * @param options - DKIM verification options
 * @returns DKIM verification results
 */
export function dkimVerify(input: MessageInput, options?: DKIMVerifyOptions): Promise<DKIMVerifyResult>;

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
    sender?: string;

    /**
     * Client IP address
     */
    ip: string;

    /**
     * Client EHLO/HELO hostname
     */
    helo?: string;

    /**
     * MTA hostname (defaults to os.hostname())
     */
    mta?: string;

    /**
     * Maximum DNS lookups allowed (default: 10)
     */
    maxResolveCount?: number;

    /**
     * Maximum void DNS lookups allowed (default: 2)
     */
    maxVoidCount?: number;

    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver;

    /**
     * Follow RFC 7208 exactly instead of the lenient default (default: false)
     */
    strict?: boolean;

    /**
     * Maximum time in milliseconds for the whole evaluation, after which the result is
     * temperror (RFC 7208 section 4.6.4). No limit by default
     */
    maxElapsedTime?: number;
}

/**
 * Verifies SPF for a sender
 *
 * @param opts - SPF verification options
 * @returns SPF verification result
 */
export function spf(opts: SPFOptions): Promise<SPFResult>;

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
    fromFields?: number;

    /**
     * Domains that passed SPF
     */
    spfDomains?: string[];

    /**
     * Domains and alignment info from DKIM signatures
     */
    dkimDomains?: Array<{
        id?: string;
        domain: string;
        aligned?: string | false;
        underSized?: number;
    }>;

    /**
     * ARC verification result
     */
    arcResult?: ARCResult;

    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver;

    /**
     * Follow RFC 9989 exactly instead of the lenient default (default: false)
     */
    strict?: boolean;
}

/**
 * Verifies DMARC policy for a message
 *
 * @param opts - DMARC verification options
 * @returns DMARC verification result
 */
export function dmarc(opts: DMARCOptions): Promise<DMARCResult | false>;

// ============================================================================
// ARC
// ============================================================================

/**
 * ARC data structure
 */
export interface ARCData {
    /**
     * ARC chain entries
     */
    chain: ARCChainEntry[];

    /**
     * Last entry in the ARC chain
     */
    lastEntry?: ARCChainEntry;

    /**
     * Error encountered during ARC chain parsing
     */
    error?: Error;
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
     * EINVALIDALGO and EINVALIDTYPE (an algorithm that is not supported or does not match the key)
     */
    err: Error & { code?: string };
    type?: string;
    selector?: string;
    signingDomain?: string;
    [key: string]: any;
}

/**
 * ARC verification options
 */
export interface ARCOptions {
    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver;

    /**
     * Minimal allowed public key length in bits (default: 1024)
     */
    minBitLength?: number;

    /**
     * Follow RFC 8617 exactly instead of the lenient default (default: false). In strict mode
     * ARC-Seal and ARC-Message-Signature tag lists must be valid RFC 6376 section 3.2 syntax
     * with lower case tag names and every required tag, instance values must be 1*2DIGIT from
     * 1 to 50 (and come first in ARC-Authentication-Results), ARC header fields with an
     * invalid instance fail the chain instead of being ignored, an ARC-Message-Signature
     * without c= is only verified as simple/simple, and the arc= result also reports
     * arc=none and smtp.remote-ip
     */
    strict?: boolean;

    /**
     * Client IP address, reported as smtp.remote-ip in strict mode (RFC 8617 section 6)
     */
    ip?: string;
}

/**
 * Seal creation data for createSeal()
 */
export interface ARCCreateSealData {
    /**
     * Parsed message headers, when `input` is false
     */
    headers?: any;

    /**
     * ARC chain data of the message, when `input` is false
     */
    arc?: ARCData | ARCSigningData;

    /**
     * Sealing options, with `bodyHash` (the relaxed/relaxed sha256 body hash) when `input` is false
     */
    seal: ARCSealOptions & { bodyHash?: string };

    /**
     * Follow the RFCs exactly (default: false, or `seal.strict`)
     */
    strict?: boolean;
}

/**
 * Verifies ARC chain in a message
 *
 * @param data - ARC chain data
 * @param opts - ARC verification options
 * @returns ARC verification result
 */
export function arc(data: ARCData, opts?: ARCOptions): Promise<ARCResult>;

/**
 * Seals a message with ARC headers
 *
 * @param input - RFC822 formatted message (stream, buffer, or string)
 * @param seal - ARC sealing options
 * @returns ARC headers to prepend
 */
export function sealMessage(input: MessageInput, seal: ARCSealOptions): Promise<Buffer>;

/**
 * Gets ARC chain from parsed headers and validates its structure. Throws for a chain that is not valid
 *
 * @param headers - Parsed message headers
 * @param opts - `strict` applies the RFC 8617 syntax rules, lenient acceptances are added to `warnings`
 * @returns ARC chain or false if no chain found
 */
export function getARChain(headers: any, opts?: { strict?: boolean; warnings?: string[] }): ARCChainEntry[] | false;

/**
 * Verifies ARC seal chain. Throws if any seal of the chain is not valid, including a chain whose
 * newest seal has cv=fail
 *
 * @param data - ARC chain data
 * @param opts - ARC verification options
 * @returns true if chain is valid, false if there is no chain
 */
export function verifyASChain(data: ARCData, opts: ARCOptions & { warnings?: string[] }): Promise<boolean>;

/**
 * Creates ARC seal headers
 *
 * @param input - RFC822 formatted message or false for pre-calculated data
 * @param data - Seal creation data
 * @returns Seal headers (empty when no set was created), the errors that say why, and what the
 *          default mode sealed that strict mode would have refused ('arc-instance-gap',
 *          'arc-cv-instance', and the DKIM signing warnings)
 */
export function createSeal(input: MessageInput | false, data: ARCCreateSealData): Promise<{ headers: string[]; errors: ARCSealError[]; warnings: string[] }>;

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
    dmarc?: DMARCResult;

    /**
     * Parsed message headers
     */
    headers?: any;

    /**
     * Require aligned DKIM signature
     */
    bimiWithAlignedDkim?: boolean;

    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver;

    /**
     * Format the Authentication-Results entry in the RFC 8601 section 2.2 form (default: false).
     * BIMI has no other strict-only rules, the draft checks apply in both modes
     */
    strict?: boolean;
}

/**
 * VMC (Verified Mark Certificate) validation result
 */
export interface VMCValidationResult {
    /**
     * Logo file fetch and validation result
     */
    location?: {
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
        error?: {
            /**
             * Human-readable error message
             */
            message: string;

            /**
             * Error code
             */
            code?: string;

            /**
             * Redirect URL if logo location redirected
             */
            redirect?: string;
        };

        /**
         * Base64-encoded SVG logo file content
         */
        logoFile?: string;

        /**
         * Hash algorithm used for logo verification (e.g., 'sha256')
         */
        hashAlgo?: string;

        /**
         * Hash value of the logo file
         */
        hashValue?: string;
    };

    /**
     * VMC certificate fetch and validation result
     */
    authority?: {
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
        error?: {
            /**
             * Human-readable error message
             */
            message: string;

            /**
             * Error code
             */
            code?: string;

            /**
             * Additional error details
             */
            details?: any;

            /**
             * Redirect URL if authority location redirected
             */
            redirect?: string;
        };

        /**
         * Parsed VMC certificate data
         */
        vmc?: any;

        /**
         * Whether the domain in the certificate matches the sender domain
         */
        domainVerified?: boolean;

        /**
         * Whether the logo hash in the certificate matches the fetched logo
         */
        hashMatch?: boolean;
    };
}

/**
 * BIMI data for VMC validation
 */
export interface BIMIData extends BIMIResult {
    locationPath?: Buffer;
    authorityPath?: Buffer;
}

/**
 * VMC validation options
 */
export interface VMCValidationOptions {
    /**
     * Custom VMC validation options passed to @postalsys/vmc
     */
    [key: string]: any;
}

/**
 * Resolves BIMI record and logo location for a domain
 *
 * @param opts - BIMI lookup options
 * @returns BIMI verification result
 */
export function bimi(opts: BIMIOptions): Promise<BIMIResult | false>;

/**
 * Validates BIMI VMC (Verified Mark Certificate) and logo file
 *
 * @param bimiData - BIMI data including location and authority URLs
 * @param opts - VMC validation options
 * @returns VMC validation result
 */
export function validateBimiVmc(bimiData: BIMIData | null, opts?: VMCValidationOptions): Promise<VMCValidationResult | false>;

/**
 * Validates BIMI SVG logo file
 *
 * @param logo - SVG logo file buffer
 * @throws Error if validation fails
 */
export function validateBimiSvg(logo: Buffer): void;

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
    id?: string | false;

    /**
     * Policy version (should be 'STSv1')
     */
    version?: string;

    /**
     * Policy mode ('enforce', 'testing', 'none')
     */
    mode: 'enforce' | 'testing' | 'none';

    /**
     * Maximum age in seconds
     */
    maxAge?: number;

    /**
     * List of allowed MX hostnames (may include wildcards like *.example.com)
     */
    mx?: string[];

    /**
     * Policy expiration timestamp
     */
    expires?: string;

    /**
     * Error encountered during policy fetch
     */
    error?: Error;
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
    warnings?: MTASTSWarning[];
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
    match?: string;

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
    resolver?: DNSResolver;

    /**
     * Apply the RFC 8461 rules exactly (default false)
     */
    strict?: boolean;

    /**
     * Overall time limit for the HTTPS policy request in milliseconds (default 60000)
     */
    timeout?: number;

    /**
     * Maximum size of the policy file in bytes (default 65536)
     */
    maxPolicySize?: number;
}

// Note: MTA-STS functions (resolvePolicy, fetchPolicy, parsePolicy, validateMx, getPolicy)
// are not exported from the main module. Import them directly from 'mailauth/lib/mta-sts'.
