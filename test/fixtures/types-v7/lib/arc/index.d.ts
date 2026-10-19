// Type definitions for mailauth/lib/arc

import { MessageInput, ARCData, ARCOptions, ARCResult, ARCSealOptions, ARCChainEntry, ARCCreateSealData, ARCSealError } from '../../index';

/**
 * Verifies ARC chain in a message
 *
 * @param data - ARC chain data
 * @param opts - ARC verification options
 * @returns ARC verification result
 */
export function arc(data: ARCData, opts?: ARCOptions): Promise<ARCResult>;

/**
 * Seals a message with ARC headers
 *
 * @param input - RFC822 formatted message (stream, buffer, or string)
 * @param seal - ARC sealing options
 * @returns ARC headers to prepend, empty if no set was created (use createSeal() to see why)
 */
export function sealMessage(input: MessageInput, seal: ARCSealOptions): Promise<Buffer>;

/**
 * Gets ARC chain from parsed headers and validates its structure. Throws for a chain that is not valid
 *
 * @param headers - Parsed message headers
 * @param opts - `strict` applies the RFC 8617 syntax rules, lenient acceptances are added to `warnings`
 * @returns ARC chain or false if no chain found
 */
export function getARChain(headers: any, opts?: { strict?: boolean; warnings?: string[] }): ARCChainEntry[] | false;

/**
 * Verifies ARC seal chain. Throws if any seal of the chain is not valid, including a chain whose
 * newest seal has cv=fail
 *
 * @param data - ARC chain data
 * @param opts - ARC verification options
 * @returns true if chain is valid, false if there is no chain
 */
export function verifyASChain(data: ARCData, opts: ARCOptions & { warnings?: string[] }): Promise<boolean>;

/**
 * Creates ARC seal headers
 *
 * @param input - RFC822 formatted message or false for pre-calculated data
 * @param data - Seal creation data
 * @returns Seal headers, empty if the ARC-Message-Signature could not be signed, any errors, and
 *          the instance (i=) of a created set
 */
export function createSeal(
    input: MessageInput | false,
    data: ARCCreateSealData
): Promise<{ headers: string[]; errors: ARCSealError[]; warnings: string[]; instance?: number }>;
