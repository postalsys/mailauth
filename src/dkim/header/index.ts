import { relaxedHeaders } from './relaxed.js';
import { simpleHeaders } from './simple.js';
import type { CanonicalizedHeader, HeaderCanonicalizationOptions, SigningHeaderLines } from './signature-opts.js';

const generateCanonicalizedHeader = (type: string, signingHeaderLines: SigningHeaderLines, options?: HeaderCanonicalizationOptions): CanonicalizedHeader => {
    options = options || {};
    let canonicalization = (options.canonicalization || 'simple/simple').toString().split('/').shift()!.toLowerCase().trim();
    switch (canonicalization) {
        case 'simple':
            return simpleHeaders(type, signingHeaderLines, options);
        case 'relaxed':
            return relaxedHeaders(type, signingHeaderLines, options);
        default: {
            let error: Error & { canonicalization?: string } = new Error('Unknown header canonicalization');
            error.canonicalization = canonicalization;
            throw error;
        }
    }
};

export { generateCanonicalizedHeader };
