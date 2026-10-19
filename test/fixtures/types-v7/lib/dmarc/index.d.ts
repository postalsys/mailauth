// Type definitions for mailauth/lib/dmarc

import { DMARCOptions, DMARCResult } from '../../index';

/**
 * Verifies DMARC policy for a message
 *
 * @param opts - DMARC verification options
 * @returns DMARC verification result, or false when the From header has no domain or more than one domain
 */
export function dmarc(opts: DMARCOptions & { strict?: boolean }): Promise<DMARCResult | false>;

/**
 * Verifies DMARC policy for a message, with details that dmarc() does not return
 *
 * @param opts - DMARC verification options
 */
export function evaluateDmarc(opts: DMARCOptions & { strict?: boolean }): Promise<{
    /**
     * The dmarc() result
     */
    response: DMARCResult | false;

    /**
     * Signing domains (normalized) of the DKIM signatures that aligned
     */
    dkimAligned?: Set<string>;

    /**
     * Why DMARC validation was not possible (RFC 9989 5.3.1), set when response is false
     */
    reason?: 'no-author-domain' | 'multiple-author-domains' | 'invalid-author-domain' | 'multiple-from-fields';

    /**
     * The Author Domains found, set when response is false
     */
    authorDomains?: string[];
}>;
