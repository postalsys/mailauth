// Type definitions for mailauth/lib/dkim/verify

import { MessageInput, DKIMVerifyOptions, DKIMVerifyResult } from '../../index';

/**
 * Verifies DKIM signatures in an email message
 *
 * @param input - RFC822 formatted message (stream, buffer, or string)
 * @param options - DKIM verification options
 * @returns DKIM verification results
 */
export function dkimVerify(input: MessageInput, options?: DKIMVerifyOptions): Promise<DKIMVerifyResult>;
