// Type definitions for mailauth/lib/dmarc

import { DMARCOptions, DMARCResult } from '../../index';

/**
 * Verifies DMARC policy for a message
 *
 * @param opts - DMARC verification options
 * @returns DMARC verification result
 */
export function dmarc(opts: DMARCOptions): Promise<DMARCResult | false>;
