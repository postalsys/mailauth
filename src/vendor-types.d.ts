// Minimal declarations for the runtime dependencies that ship without type
// definitions. Only the members mailauth uses are declared.

declare module 'libmime' {
    export interface ParsedHeaderValue {
        value: string;
        params: { [key: string]: string };
    }
    export function parseHeaderValue(value: string): ParsedHeaderValue;
    export function foldLines(value: string, lineLength?: number, afterSpace?: boolean): string;
    const libmime: {
        parseHeaderValue: typeof parseHeaderValue;
        foldLines: typeof foldLines;
    };
    export default libmime;
}

declare module 'punycode.js' {
    export function toASCII(input: string): string;
    export function toUnicode(input: string): string;
    const punycode: {
        toASCII: typeof toASCII;
        toUnicode: typeof toUnicode;
    };
    export default punycode;
}

declare module '@postalsys/vmc' {
    // Certificate details of the VMC or CMC (lib/cert-info.js)
    export interface VMCCertificateInfo {
        subject: Record<string, string>;
        // DNS names from the subjectAltName extension
        subjectAltName: string[];
        fingerprint: string;
        serialNumber: string;
        validFrom: string | null;
        validTo: string | null;
        issuer: Record<string, string>;
    }
    // The logo data of the certificate (lib/parse-vmc.js), as vmc() returns it
    export interface VMCData {
        mediaType: string | undefined;
        hashAlgo: string | undefined;
        // hex encoded
        hashValue: string | undefined;
        // base64 encoded
        logoFile: string | undefined;
        validHash: boolean | undefined;
        type: 'VMC' | 'CMC';
        certificate: VMCCertificateInfo;
    }
    export interface VMCOptions {
        rootStore?: unknown;
        now?: Date | undefined;
    }
    export function vmc(pem: Buffer | string, options?: VMCOptions): Promise<VMCData>;
}
