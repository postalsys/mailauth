// Type definitions for mailauth/lib/spf

import { SPFOptions as BaseSPFOptions, SPFResult as BaseSPFResult } from '../../index';

/**
 * SPF verification options
 */
export interface SPFOptions extends BaseSPFOptions {
    /**
     * Follow RFC 7208 exactly instead of the lenient default (default: false). Strict mode
     * validates the whole record before evaluation, rejects the c, r and t macros outside of
     * explanation text, counts void lookups per RFC 7208 section 4.6.4, discards records with
     * leading whitespace, and reports only the checked identity in Authentication-Results
     */
    strict?: boolean;

    /**
     * Maximum time in milliseconds for the whole evaluation. If exceeded, the result is
     * temperror (RFC 7208 section 4.6.4). No limit by default
     */
    maxElapsedTime?: number;
}

/**
 * SPF verification result
 */
export interface SPFResult extends BaseSPFResult {
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
 * Verifies SPF for a sender
 *
 * @param opts - SPF verification options
 * @returns SPF verification result
 */
export function spf(opts: SPFOptions): Promise<SPFResult>;
