// Type definitions for mailauth/lib/dkim/sign

/// <reference types="node" />

import { Transform } from 'stream';
import { MessageInput, DKIMSignOptions, DKIMSignResult, DKIMSignError, DKIMSignWarning } from '../../index';

/**
 * Signs an email message with DKIM signature(s)
 *
 * @param input - RFC822 formatted message (stream, buffer, or string)
 * @param options - DKIM signing options, including `strict`
 * @returns DKIM signature header(s), an empty string if none was created, plus errors and warnings
 */
export function dkimSign(input: MessageInput, options: DKIMSignOptions): Promise<DKIMSignResult>;

/**
 * Transform stream for DKIM signing
 * Prepends the DKIM-Signature header(s) to the message stream. When no signature could be
 * created the message is passed through unchanged
 */
export class DkimSignStream extends Transform {
    /**
     * Creates a DKIM signing stream
     *
     * @param options - DKIM signing options, including `strict`
     */
    constructor(options: DKIMSignOptions);

    /**
     * The signatures that could not be created, set when the stream ends
     */
    errors: DKIMSignError[] | null;

    /**
     * What was signed although strict mode would have refused it, set when the stream ends
     */
    warnings: DKIMSignWarning[] | null;
}
