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
     * Signing algorithm (default: 'rsa-sha256')
     * Supported: 'rsa-sha256', 'ed25519-sha256'
     */
    algorithm?: string;

    /**
     * Headers to include in signature
     */
    headerList?: string[];

    /**
     * Signing timestamp
     */
    signTime?: Date | string | number;
}

/**
 * Policy information attached to authentication status
 */
export interface AuthPolicy {
    /**
     * DKIM policy rules (e.g., 'weak-key' when key is undersized)
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
    result: 'pass' | 'fail' | 'neutral' | 'none' | 'temperror' | 'temperr' | 'permerror' | 'policy' | 'softfail' | 'skipped';
    comment?: string;
    header?: Record<string, any>;
    smtp?: {
        mailfrom?: string;
        helo?: string;
    };
    policy?: AuthPolicy;
}

/**
 * DKIM verification result for a single signature
 */
export interface DKIMResult {
    /**
     * Signature identifier
     */
    id?: string;

    /**
     * Signing domain
     */
    signingDomain: string;

    /**
     * Key selector
     */
    selector?: string;

    /**
     * Verification status
     */
    status: AuthStatus & {
        aligned?: boolean;
        underSized?: boolean;
    };

    /**
     * Authentication-Results formatted info
     */
    info: string;

    /**
     * Signature algorithm
     */
    algorithm?: string;

    /**
     * Canonicalization method
     */
    canonicalization?: string;

    /**
     * Signing timestamp
     */
    signingTime?: Date;

    /**
     * Signature expiration
     */
    expiration?: Date;
}

/**
 * DKIM verification results
 */
export interface DKIMVerifyResult {
    /**
     * Domain from From header
     */
    headerFrom: string[];

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
        parsed: Array<{ key: string; line: string }>;
        [key: string]: any;
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
     * Organization domain
     */
    domain: string;

    /**
     * DMARC policy ('none', 'quarantine', 'reject')
     */
    policy: string;

    /**
     * Policy for organizational domain
     */
    p: string;

    /**
     * Policy for subdomains
     */
    sp: string;

    /**
     * Percentage of messages subject to filtering (0-100)
     */
    pct?: number;

    /**
     * DMARC DNS record
     */
    rr?: string;

    /**
     * Verification status
     */
    status: AuthStatus;

    /**
     * Alignment results
     */
    alignment: {
        spf: {
            result: string | false;
            strict: boolean;
        };
        dkim: {
            result: string | false;
            strict: boolean;
            underSized?: boolean;
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
}

/**
 * BIMI verification result
 */
export interface BIMIResult {
    /**
     * Verification status
     */
    status: AuthStatus;

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
         * Additional comment (often contains IP in parentheses)
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
     * Signing algorithm (default: 'rsa-sha256')
     * Supported: 'rsa-sha256', 'rsa-sha1', 'ed25519-sha256'
     */
    algorithm?: string;

    /**
     * List of header fields to sign
     * Default includes From, Subject, Date, To, etc.
     */
    headerList?: string[];

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
     * Identity (i= tag)
     */
    identity?: string;

    /**
     * Multiple signature configurations
     */
    signatureData?: DKIMSignOptions[];
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
 * DKIM signing result
 */
export interface DKIMSignResult {
    /**
     * DKIM-Signature header(s) to prepend to message
     */
    signatures: string;

    /**
     * ARC chain information (if ARC signing was performed)
     */
    arc?: ARCSigningData;

    /**
     * Any errors encountered during signing
     */
    errors: Error[];
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
     * Any errors encountered during signing
     */
    errors: Error[] | null;
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
     * Domains that passed SPF
     */
    spfDomains?: string[];

    /**
     * Domains and alignment info from DKIM signatures
     */
    dkimDomains?: Array<{
        id?: string;
        domain: string;
        aligned?: boolean;
        underSized?: boolean;
    }>;

    /**
     * ARC verification result
     */
    arcResult?: ARCResult;

    /**
     * Custom DNS resolver function
     */
    resolver?: DNSResolver;
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
 * Gets ARC chain from parsed headers
 *
 * @param headers - Parsed message headers
 * @returns ARC chain or false if no chain found
 */
export function getARChain(headers: any): ARCChainEntry[] | false;

/**
 * Verifies ARC seal chain
 *
 * @param data - ARC chain data
 * @param opts - ARC verification options
 * @returns true if chain is valid
 */
export function verifyASChain(data: ARCData, opts: ARCOptions): Promise<boolean>;

/**
 * Creates ARC seal headers
 *
 * @param input - RFC822 formatted message or false for pre-calculated data
 * @param data - Seal creation data
 * @returns Seal headers
 */
export function createSeal(input: MessageInput | false, data: any): Promise<{ headers: string[] }>;

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
     */
    status: 'found' | 'renewed' | 'not_found' | 'errored';
}

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
}

// Note: MTA-STS functions (resolvePolicy, fetchPolicy, parsePolicy, validateMx, getPolicy)
// are not exported from the main module. Import them directly from 'mailauth/lib/mta-sts'.
