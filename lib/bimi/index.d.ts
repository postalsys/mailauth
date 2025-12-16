// Type definitions for mailauth/lib/bimi

import { BIMIOptions, BIMIResult, BIMIData, VMCValidationOptions, VMCValidationResult } from '../../index';

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
export function validateVMC(bimiData: BIMIData | null, opts?: VMCValidationOptions): Promise<VMCValidationResult | false>;
