// Type definitions for mailauth/lib/arc

import { MessageInput, ARCData, ARCOptions, ARCResult, ARCSealOptions, ARCChainEntry } from '../../index';

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
 * @returns ARC headers to prepend
 */
export function sealMessage(input: MessageInput, seal: ARCSealOptions): Promise<Buffer>;

/**
 * Gets ARC chain from parsed headers
 *
 * @param headers - Parsed message headers
 * @returns ARC chain or false if no chain found
 */
export function getARChain(headers: any): ARCChainEntry[] | false;

/**
 * Verifies ARC seal chain
 *
 * @param data - ARC chain data
 * @param opts - ARC verification options
 * @returns true if chain is valid
 */
export function verifyASChain(data: ARCData, opts: ARCOptions): Promise<boolean>;

/**
 * Creates ARC seal headers
 *
 * @param input - RFC822 formatted message or false for pre-calculated data
 * @param data - Seal creation data
 * @returns Seal headers
 */
export function createSeal(input: MessageInput | false, data: any): Promise<{ headers: string[] }>;
