'use strict';

// Local HTTPS server for the MTA-STS tests. No network access is needed: the mock resolver
// points the policy host to 127.0.0.1, and https.request is wrapped so that requests to
// port 443 go to the local server and trust only the test CA from test/fixtures/mta-sts.
// The TLS options set by lib/mta-sts.js (servername, rejectUnauthorized, checkServerIdentity)
// are left untouched.

const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'mta-sts');
const readFixture = name => fs.readFileSync(path.join(FIXTURES, name));

const CA = readFixture('ca.pem');

const POLICY = 'version: STSv1\r\nmode: enforce\r\nmx: mail.example.test\r\nmax_age: 86400\r\n';

const origRequest = https.request;

class PolicyServer {
    constructor() {
        this.server = null;
        this.port = null;
        this.requests = [];
        this.sni = [];
        this.handler = null;
    }

    async start() {
        this.server = https.createServer(this.credentials('good'), (req, res) => {
            this.requests.push({ host: req.headers.host, url: req.url, method: req.method });
            let handler = this.handler || PolicyServer.send(200, { 'Content-Type': 'text/plain' }, POLICY);
            handler(req, res);
        });
        this.server.on('secureConnection', socket => this.sni.push(socket.servername));
        // ignore aborted connections
        this.server.on('clientError', () => false);

        await new Promise(resolve => this.server.listen(0, '127.0.0.1', resolve));
        this.port = this.server.address().port;

        const port = this.port;
        https.request = function (options, callback) {
            if (options.port !== 443 || !['127.0.0.1', '::1'].includes(options.host)) {
                throw new Error(`Test tried to connect to ${options.host}:${options.port}`);
            }
            return origRequest.call(this, Object.assign({}, options, { port, ca: CA }), callback);
        };
    }

    credentials(certName) {
        return { key: readFixture(`${certName}.key`), cert: readFixture(`${certName}.pem`) };
    }

    useCert(certName) {
        this.server.setSecureContext(this.credentials(certName));
    }

    reset() {
        this.requests = [];
        this.sni = [];
        this.handler = null;
        this.useCert('good');
    }

    async stop() {
        https.request = origRequest;
        if (this.server) {
            this.server.closeAllConnections();
            await new Promise(resolve => this.server.close(resolve));
            this.server = null;
        }
    }

    static send(status, headers, body) {
        return (req, res) => {
            res.writeHead(status, headers);
            res.end(body);
        };
    }
}

const dnsError = code => {
    let err = new Error(`DNS error ${code}`);
    err.code = code;
    return err;
};

// mock resolver, table keys are "name|type"
const mockResolver = table => {
    const queries = [];
    const resolver = async (name, type) => {
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
    };
    resolver.queries = queries;
    return resolver;
};

module.exports = { PolicyServer, POLICY, mockResolver, dnsError };
