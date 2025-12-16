// Type definitions for mailauth/lib/spf

import { SPFOptions, SPFResult } from '../../index';

/**
 * Verifies SPF for a sender
 *
 * @param opts - SPF verification options
 * @returns SPF verification result
 */
export function spf(opts: SPFOptions): Promise<SPFResult>;
