import verifyDmarc from './verify.js';
import type { DMARCVerifyOptions } from './verify.js';
import type { DMARCResult } from '../types.js';
const { evaluateDmarc } = verifyDmarc;

const dmarc = async (opts: DMARCVerifyOptions): Promise<DMARCResult | false> => verifyDmarc(opts);

export { dmarc, evaluateDmarc };
export type { DMARCVerifyOptions, DMARCEvaluateResult } from './verify.js';
