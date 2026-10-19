import { writeToStream } from '../tools.js';
import { DkimSigner } from './dkim-signer.js';
import { Transform } from 'node:stream';
import { Buffer } from 'node:buffer';
import type { TransformCallback, TransformOptions, Writable } from 'node:stream';
import type { DKIMSignError, DKIMSignOptions, DKIMSignResult, DKIMSignWarning, MessageInput } from '../types.js';

/**
 * The signer a DkimSignStream writes the message to. It collects the signature headers, and
 * the errors and warnings when it has any
 */
export interface DkimSignStreamSigner extends Writable {
    signatureHeaders: string[];
    errors?: DKIMSignError[] | undefined;
    warnings?: DKIMSignWarning[] | undefined;
}

// The DKIM-Signature header lines to prepend to the message, each ending with a CRLF. An
// empty string when no signature was created: a lone CRLF in front of the message would be
// the empty line that ends the header section, and turn every header of it into body
const formatSignatures = (signatureHeaders: string[]): string => (signatureHeaders.length ? signatureHeaders.join('\r\n') + '\r\n' : '');

const dkimSign = async (input: MessageInput, options: DKIMSignOptions): Promise<DKIMSignResult> => {
    let dkimSigner = new DkimSigner(options);
    await writeToStream(dkimSigner, input);

    return {
        signatures: formatSignatures(dkimSigner.signatureHeaders),
        arc: dkimSigner.arc,
        errors: dkimSigner.errors,
        warnings: dkimSigner.warnings
    };
};

class DkimSignStream<Options = DKIMSignOptions> extends Transform {
    declare signer: DkimSignStreamSigner;
    declare chunks: Buffer[];
    declare chunklen: number;
    declare errors: DKIMSignError[] | null;
    declare warnings: DKIMSignWarning[] | null;
    declare finished: boolean;
    declare finishCb: TransformCallback | null;

    constructor(options: Options) {
        super(options as TransformOptions);
        this.signer = this.createSigner(options);

        this.chunks = [];
        this.chunklen = 0;

        this.errors = null;
        this.warnings = null;

        this.finished = false;
        this.finishCb = null;
        this.signer.on('end', () => this.finishStream());
        this.signer.on('finish', () => this.finishStream());
        this.signer.on('error', err => {
            this.finished = true;
            this.destroy(err);
        });
    }

    // the signer that collects the signature headers, a subclass can sign with a different protocol
    createSigner(options: Options): DkimSignStreamSigner {
        return new DkimSigner(options as DKIMSignOptions);
    }

    finishStream(): void {
        if (this.finished || !this.finishCb) {
            return;
        }
        this.finished = true;
        let done = this.finishCb;
        this.finishCb = null;

        this.errors = this.signer.errors as DKIMSignError[] | null;
        this.warnings = this.signer.warnings as DKIMSignWarning[] | null;

        let signatures = formatSignatures(this.signer.signatureHeaders);
        if (signatures) {
            this.push(Buffer.from(signatures));
        }
        this.push(Buffer.concat(this.chunks, this.chunklen));
        done();
    }

    override _transform(chunk: Buffer | string, encoding: BufferEncoding, done: TransformCallback) {
        if (!chunk || !chunk.length || this.finished) {
            return done();
        }

        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        this.chunks.push(chunk);
        this.chunklen += chunk.length;

        if (this.signer.write(chunk) === false) {
            // wait for drain
            return this.signer.once('drain', done);
        }
        done();
    }

    override _flush(done: TransformCallback): void {
        if (this.finished) {
            return done();
        }
        this.finishCb = done;
        this.signer.end();
    }
}

export { dkimSign, DkimSignStream, formatSignatures };
