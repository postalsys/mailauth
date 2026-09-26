// Type definitions for mailauth/lib/mta-sts

/// <reference types="node" />

import { MTASTSOptions as BaseMTASTSOptions, MTASTSPolicy, MTASTSPolicyResult as BaseMTASTSPolicyResult, MTASTSValidationResult } from '../index';

/**
 * MTA-STS options
 */
export interface MTASTSOptions extends BaseMTASTSOptions {
    /**
     * Apply the RFC 8461 rules exactly (default false).
     *
     * - The TXT record must match the RFC 8461 3.1 ABNF (case-sensitive `v=STSv1`, `id` of 1 to 32 letters and digits)
     * - Only HTTP 200 is accepted and the Content-Type must be `text/plain`
     * - Policy field names and the `mode` value are case-sensitive, `max_age` must be 1 to 10 digits and `mx` must be `["*."] Domain`
     * - The Policy Host certificate must match through a DNS-ID subjectAltName, without CN fallback or partial-label wildcards
     * - An expired cached policy is not applied when a fetch fails
     *
     * In the default lax mode these are accepted and reported in the `warnings` array of the `getPolicy` result.
     */
    strict?: boolean;

    /**
     * Overall time limit for the HTTPS policy request in milliseconds (default 60000).
     * The socket idle timeout is 15 seconds or this value, whichever is smaller.
     */
    timeout?: number;

    /**
     * Maximum size of the policy file in bytes (default 65536). Larger responses fail with the `policy_too_large` error code.
     */
    maxPolicySize?: number;
}

/**
 * Markers for input that the default lax mode accepted but `strict: true` would reject
 *
 * - `txt-syntax`: the TXT record does not match the RFC 8461 3.1 syntax
 * - `http-status`: the policy was served with a 2xx status other than 200
 * - `content-type`: the policy was not served as `text/plain`
 * - `policy-syntax`: the policy file does not match the RFC 8461 3.2 syntax (field name or mode case, max_age format, mx pattern)
 * - `cert-identity`: the Policy Host certificate matched only through the CN or a partial-label wildcard
 * - `expired-cache`: an expired cached policy was returned because the policy could not be fetched
 */
export type MTASTSWarning = 'txt-syntax' | 'http-status' | 'content-type' | 'policy-syntax' | 'cert-identity' | 'expired-cache';

/**
 * MTA-STS policy fetch result
 */
export interface MTASTSPolicyResult extends BaseMTASTSPolicyResult {
    /**
     * Lax acceptance markers, only present when the default lax mode accepted something strict mode would reject
     */
    warnings?: MTASTSWarning[];
}

/**
 * MTA-STS MX validation options
 */
export interface MTASTSValidateOptions {
    /**
     * Accepted for API consistency. The matching rules are the same in both modes.
     */
    strict?: boolean;
}

/**
 * Resolves MTA-STS policy ID from DNS
 *
 * @param address - Email address or domain name
 * @param opts - MTA-STS options
 * @returns Policy ID or false if not found or not usable
 * @throws Error on DNS errors other than NXDOMAIN/NODATA, or with code `multi_sts_records` for multiple records
 */
export function resolvePolicy(address: string, opts?: MTASTSOptions): Promise<string | false>;

/**
 * Fetches and parses MTA-STS policy file from HTTPS
 *
 * @param domain - Domain name or email address
 * @param opts - MTA-STS options
 * @returns Parsed policy or false if the policy host has no address records
 * @throws Error if the policy can not be fetched or is invalid
 */
export function fetchPolicy(domain: string, opts?: MTASTSOptions): Promise<MTASTSPolicy | false>;

/**
 * Parses MTA-STS policy file content
 *
 * @param file - Policy file content
 * @param opts - Only `strict` is used
 * @returns Parsed policy
 * @throws Error if policy is invalid
 */
export function parsePolicy(file: Buffer | string, opts?: Pick<MTASTSOptions, 'strict'>): MTASTSPolicy;

/**
 * Validates MX hostname against MTA-STS policy.
 * This does not look at `policy.expires`, use `getPolicy` to refresh the policy.
 *
 * @param mx - MX hostname to validate
 * @param policy - MTA-STS policy
 * @param opts - Validation options
 * @returns Validation result
 */
export function validateMx(mx: string, policy: MTASTSPolicy, opts?: MTASTSValidateOptions): MTASTSValidationResult;

/**
 * Gets complete MTA-STS policy for a domain
 * Resolves DNS, fetches policy file, and handles caching
 *
 * @param domain - Domain name or email address
 * @param knownPolicy - Currently cached policy, the `policy` value of an earlier result
 * @param opts - MTA-STS options
 * @returns Policy fetch result, store its `policy` value as the new cached policy
 */
export function getPolicy(domain: string, knownPolicy?: MTASTSPolicy | null, opts?: MTASTSOptions): Promise<MTASTSPolicyResult>;
