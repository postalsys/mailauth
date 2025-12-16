// Type definitions for mailauth/lib/mta-sts

/// <reference types="node" />

import { MTASTSOptions, MTASTSPolicy, MTASTSPolicyResult, MTASTSValidationResult } from '../index';

/**
 * Resolves MTA-STS policy ID from DNS
 *
 * @param address - Email address or domain name
 * @param opts - MTA-STS options
 * @returns Policy ID or false if not found
 */
export function resolvePolicy(address: string, opts?: MTASTSOptions): Promise<string | false>;

/**
 * Fetches and parses MTA-STS policy file from HTTPS
 *
 * @param domain - Domain name
 * @param opts - MTA-STS options
 * @returns Parsed policy or false if not found
 */
export function fetchPolicy(domain: string, opts?: MTASTSOptions): Promise<MTASTSPolicy | false>;

/**
 * Parses MTA-STS policy file content
 *
 * @param file - Policy file content
 * @returns Parsed policy
 * @throws Error if policy is invalid
 */
export function parsePolicy(file: Buffer | string): MTASTSPolicy;

/**
 * Validates MX hostname against MTA-STS policy
 *
 * @param mx - MX hostname to validate
 * @param policy - MTA-STS policy
 * @returns Validation result
 */
export function validateMx(mx: string, policy: MTASTSPolicy): MTASTSValidationResult;

/**
 * Gets complete MTA-STS policy for a domain
 * Resolves DNS, fetches policy file, and handles caching
 *
 * @param domain - Domain name
 * @param knownPolicy - Currently cached policy
 * @param opts - MTA-STS options
 * @returns Policy fetch result
 */
export function getPolicy(domain: string, knownPolicy?: MTASTSPolicy, opts?: MTASTSOptions): Promise<MTASTSPolicyResult>;
