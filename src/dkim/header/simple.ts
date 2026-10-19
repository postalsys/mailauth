import { Buffer } from 'node:buffer';
import { stripSignatureValue, toLineBytes } from '../../tools.js';
import { buildSignatureOpts } from './signature-opts.js';
import type { CanonicalizedHeader, HeaderCanonicalizationOptions, SignatureOpts, SigningHeaderLines } from './signature-opts.js';

const formatSimpleLine = (line: string | Buffer, suffix?: string): Buffer => Buffer.concat([toLineBytes(line), Buffer.from(suffix ? suffix : '', 'binary')]);

// generate headers for signing
const simpleHeaders = (type: string, signingHeaderLines: SigningHeaderLines, options?: HeaderCanonicalizationOptions): CanonicalizedHeader => {
    let { signatureHeaderLine, strict } = options || {};
    let chunks: Buffer[] = [];

    for (let signedHeaderLine of signingHeaderLines.headers) {
        chunks.push(formatSimpleLine(signedHeaderLine.line, '\r\n'));
    }

    let opts: SignatureOpts | false = false;

    if (!signatureHeaderLine) {
        ({ opts, signatureHeaderLine } = buildSignatureOpts(type, signingHeaderLines, options));
    }

    // the strict mode reads the tag names of a signature header case-sensitively
    chunks.push(stripSignatureValue(formatSimpleLine(signatureHeaderLine), strict));

    return { canonicalizedHeader: Buffer.concat(chunks), signatureHeaderLine, dkimHeaderOpts: opts };
};

export { simpleHeaders };
