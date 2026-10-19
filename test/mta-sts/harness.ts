// Local HTTPS server for the MTA-STS tests. No network access is needed: the mock resolver
// points the policy host to 127.0.0.1, and https.request is wrapped so that requests to
// port 443 go to the local server and trust only the test CA from test/fixtures/mta-sts.
// The TLS options set by lib/mta-sts.js (servername, rejectUnauthorized, checkServerIdentity)
// are left untouched.

import https from 'node:https';
import type http from 'node:http';
import type tls from 'node:tls';
import type { AddressInfo } from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'mta-sts');
const readFixture = (name: string): Buffer => fs.readFileSync(path.join(FIXTURES, name));

const CA = readFixture('ca.pem');

const POLICY = 'version: STSv1\r\nmode: enforce\r\nmx: mail.example.test\r\nmax_age: 86400\r\n';

const origRequest = https.request;

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

interface RecordedRequest {
    host: string | undefined;
    url: string | undefined;
    method: string | undefined;
}

type MockResolver = ((name: string, type: string) => Promise<any>) & { queries: string[] };

class PolicyServer {
    server: https.Server | null;
    port: number | null;
    requests: RecordedRequest[];
    sni: Array<string | false | null>;
    handler: Handler | null;

    constructor() {
        this.server = null;
        this.port = null;
        this.requests = [];
        this.sni = [];
        this.handler = null;
    }

    async start(): Promise<void> {
        this.server = https.createServer(this.credentials('good'), (req, res) => {
            this.requests.push({ host: req.headers.host, url: req.url, method: req.method });
            let handler = this.handler || PolicyServer.send(200, { 'Content-Type': 'text/plain' }, POLICY);
            handler(req, res);
        });
        this.server.on('secureConnection', (socket: tls.TLSSocket) => this.sni.push(socket.servername));
        // ignore aborted connections
        this.server.on('clientError', () => false);

        await new Promise<void>(resolve => this.server!.listen(0, '127.0.0.1', resolve));
        this.port = (this.server.address() as AddressInfo).port;

        const port = this.port;
        https.request = function (this: unknown, options: https.RequestOptions, callback?: (res: http.IncomingMessage) => void) {
            if (options.port !== 443 || !['127.0.0.1', '::1'].includes(options.host as string)) {
                throw new Error(`Test tried to connect to ${options.host}:${options.port}`);
            }
            return (origRequest as (...args: any[]) => http.ClientRequest).call(this, Object.assign({}, options, { port, ca: CA }), callback);
        } as typeof https.request;
    }

    credentials(certName: string): { key: Buffer; cert: Buffer } {
        return { key: readFixture(`${certName}.key`), cert: readFixture(`${certName}.pem`) };
    }

    useCert(certName: string): void {
        this.server!.setSecureContext(this.credentials(certName));
    }

    reset(): void {
        this.requests = [];
        this.sni = [];
        this.handler = null;
        this.useCert('good');
    }

    async stop(): Promise<void> {
        https.request = origRequest;
        if (this.server) {
            this.server.closeAllConnections();
            await new Promise(resolve => this.server!.close(resolve));
            this.server = null;
        }
    }

    static send(status: number, headers: http.OutgoingHttpHeaders, body: string | Buffer): Handler {
        return (req, res) => {
            res.writeHead(status, headers);
            res.end(body);
        };
    }
}

const dnsError = (code: string): NodeJS.ErrnoException => {
    let err: NodeJS.ErrnoException = new Error(`DNS error ${code}`);
    err.code = code;
    return err;
};

// mock resolver, table keys are "name|type"
const mockResolver = (table: Record<string, any>): MockResolver => {
    const queries: string[] = [];
    const resolver = (async (name: string, type: string) => {
        queries.push(`${name}|${type}`);
        const key = `${name.toLowerCase()}|${type}`;
        if (key in table) {
            const value = table[key];
            if (value instanceof Error) {
                throw value;
            }
            return typeof value === 'function' ? value() : value;
        }
        throw dnsError('ENOTFOUND');
    }) as MockResolver;
    resolver.queries = queries;
    return resolver;
};

export type { Handler, RecordedRequest, MockResolver };
export { PolicyServer, POLICY, mockResolver, dnsError };
