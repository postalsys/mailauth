import { Buffer } from 'node:buffer';
import { formatRelaxedLine, stripSignatureValue } from '../../tools.js';
import { buildSignatureOpts } from './signature-opts.js';
import type { CanonicalizedHeader, HeaderCanonicalizationOptions, SignatureOpts, SigningHeaderLines } from './signature-opts.js';

// generate headers for signing
const relaxedHeaders = (type: string, signingHeaderLines: SigningHeaderLines, options?: HeaderCanonicalizationOptions): CanonicalizedHeader => {
    let { signatureHeaderLine, strict } = options || {};
    let chunks: Buffer[] = [];

    for (let signedHeaderLine of signingHeaderLines.headers) {
        chunks.push(formatRelaxedLine(signedHeaderLine.line, '\r\n'));
    }

    let opts: SignatureOpts | false = false;

    if (!signatureHeaderLine) {
        ({ opts, signatureHeaderLine } = buildSignatureOpts(type, signingHeaderLines, options));
    }

    // the strict mode reads the tag names of a signature header case-sensitively
    chunks.push(stripSignatureValue(formatRelaxedLine(signatureHeaderLine), strict));

    return { canonicalizedHeader: Buffer.concat(chunks), signatureHeaderLine, dkimHeaderOpts: opts };
};

export { relaxedHeaders };
