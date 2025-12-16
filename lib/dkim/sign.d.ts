// Type definitions for mailauth/lib/dkim/sign

/// <reference types="node" />

import { Transform } from 'stream';
import { MessageInput, DKIMSignOptions, DKIMSignResult } from '../../index';

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
