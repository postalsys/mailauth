/* eslint @typescript-eslint/no-unused-expressions:0 */
// BIMI logo and evidence downloads against a local HTTPS server. No network access is needed: the
// dispatcher resolves every host name to 127.0.0.1 and trusts only the test CA from
// test/fixtures/mta-sts, whose "wild" certificate is valid for *.example.test.

import { describe, it, before, after, beforeEach } from 'node:test';
import { Buffer } from 'node:buffer';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import zlib from 'node:zlib';
import { Agent } from 'undici';
import { expect, config } from 'chai';

import { bimi, validateVMC } from '../../src/bimi/index.js';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

config.includeStack = true;

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'mta-sts');
const readFixture = (name: any) => fs.readFileSync(path.join(FIXTURES, name));

const LOGO =
    '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 10 10"><title>Example</title><rect width="10" height="10" fill="red"/></svg>';

const lookup = (hostname: any, options: any, callback: any) => {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }
    if (options && options.all) {
        return callback(null, [{ address: '127.0.0.1', family: 4 }]);
    }
    callback(null, '127.0.0.1', 4);
};

describe('BIMI download Tests', () => {
    let server: any;
    let plainServer: any;
    let port: any;
    let plainPort: any;
    let handler: any;
    let requests: any;
    let plainRequests: any;
    let dispatcher: any;

    before(async () => {
        server = https.createServer({ key: readFixture('wild.key'), cert: readFixture('wild.pem') }, (req, res) => {
            requests.push(req.url);
            handler(req, res);
        });
        server.on('clientError', () => false);
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        port = server.address().port;

        plainServer = http.createServer((req, res) => {
            plainRequests.push(req.url);
            res.end(LOGO);
        });
        await new Promise(resolve => plainServer.listen(0, '127.0.0.1', resolve));
        plainPort = plainServer.address().port;

        dispatcher = new Agent({ connect: { ca: readFixture('ca.pem'), lookup } });
    });

    after(async () => {
        await dispatcher.close();
        server.closeAllConnections();
        plainServer.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
        await new Promise(resolve => plainServer.close(resolve));
    });

    beforeEach(() => {
        requests = [];
        plainRequests = [];
        handler = (req: any, res: any) => res.end(LOGO);
    });

    const base = () => `https://bimi.example.test:${port}`;
    const download = (location: any, opts?: any) => validateVMC({ location, status: { header: {} } } as any, Object.assign({ dispatcher }, opts || {}));

    it('Should download a logo', async () => {
        const result: any = await download(`${base()}/logo.svg`);
        expect(result.location.success).to.be.true;
        expect(result.headers.indicator).to.exist;
        expect(requests).to.deep.equal(['/logo.svg']);
    });

    it('Should not follow a redirect to plain HTTP', async () => {
        handler = (req: any, res: any) => {
            res.writeHead(302, { Location: `http://bimi.example.test:${plainPort}/plain.svg` });
            res.end();
        };
        const result: any = await download(`${base()}/redirect`);
        expect(result.location.success).to.be.false;
        expect(result.location.error.code).to.equal('HTTP_REDIRECT_NOT_ALLOWED');
        expect(result.location.error.redirect).to.equal(`http://bimi.example.test:${plainPort}/plain.svg`);
        expect(result.headers).to.not.exist;
        expect(plainRequests).to.deep.equal([]);
    });

    it('Should not follow a redirect to an IP address', async () => {
        handler = (req: any, res: any) => {
            res.writeHead(301, { Location: `https://127.0.0.1:${port}/logo.svg` });
            res.end();
        };
        const result: any = await download(`${base()}/redirect`);
        expect(result.location.success).to.be.false;
        expect(result.location.error.code).to.equal('HTTP_REDIRECT_NOT_ALLOWED');
        expect(requests).to.deep.equal(['/redirect']);
    });

    it('Should follow a redirect to another HTTPS URL', async () => {
        handler = (req: any, res: any) => {
            if (req.url === '/redirect') {
                res.writeHead(302, { Location: '/logo.svg' });
                return res.end();
            }
            res.end(LOGO);
        };
        const result: any = await download(`${base()}/redirect`);
        expect(result.location.success).to.be.true;
        expect(requests).to.deep.equal(['/redirect', '/logo.svg']);
    });

    it('Should stop after too many redirects', async () => {
        handler = (req: any, res: any) => {
            res.writeHead(302, { Location: '/loop' });
            res.end();
        };
        const result: any = await download(`${base()}/loop`);
        expect(result.location.success).to.be.false;
        expect(result.location.error.code).to.equal('HTTP_REDIRECT_NOT_ALLOWED');
        expect(requests.length).to.equal(4);
    });

    it('Should reject a logo larger than the limit', async () => {
        handler = (req: any, res: any) => res.end(Buffer.alloc(5 * 1024 * 1024, 'a'));
        const result: any = await download(`${base()}/big`);
        expect(result.location.success).to.be.false;
        expect(result.location.error.code).to.equal('FILE_TOO_LARGE');
        expect(result.headers).to.not.exist;
    });

    it('Should stop reading a chunked response at the limit', async () => {
        handler = (req: any, res: any) => {
            res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
            res.write(Buffer.alloc(40 * 1024, 'a'));
            res.write(Buffer.alloc(40 * 1024, 'a'));
            // the response is never finished
        };
        const result: any = await download(`${base()}/chunked`, { timeout: 2000 });
        expect(result.location.success).to.be.false;
        expect(result.location.error.code).to.equal('FILE_TOO_LARGE');
    });

    it('Should use the maxLogoSize option', async () => {
        const result: any = await download(`${base()}/logo.svg`, { maxLogoSize: 16 });
        expect(result.location.success).to.be.false;
        expect(result.location.error.code).to.equal('FILE_TOO_LARGE');
    });

    it('Should limit the uncompressed size of an SVGZ logo', async () => {
        handler = (req: any, res: any) => res.end(zlib.gzipSync(Buffer.alloc(1024 * 1024, ' ')));
        const result: any = await download(`${base()}/logo.svgz`);
        expect(result.location.success).to.be.false;
        expect(result.location.error.code).to.equal('FILE_TOO_LARGE');
    });

    it('Should limit the size of the evidence document', async () => {
        handler = (req: any, res: any) => res.end(Buffer.alloc(300 * 1024, 'a'));
        const result: any = await validateVMC({ authority: `${base()}/vmc.pem`, status: { header: {} } } as any, { dispatcher });
        expect(result.authority.success).to.be.false;
        expect(result.authority.error.code).to.equal('FILE_TOO_LARGE');
    });

    it('Should time out a slow response', async () => {
        handler = (req: any, res: any) => {
            res.writeHead(200);
            res.write('<svg');
        };
        const result: any = await download(`${base()}/slow`, { timeout: 300 });
        expect(result.location.success).to.be.false;
        expect(result.location.error.code).to.equal('HTTP_REQUEST_TIMEOUT');
    });

    for (let url of [
        'https://127.0.0.1/logo.svg',
        'https://[::1]/logo.svg',
        'https://localhost/logo.svg',
        'https://2130706433/logo.svg',
        'https://intranet/logo.svg'
    ]) {
        it(`Should not download from ${url}`, async () => {
            const result: any = await download(url);
            expect(result.location.success).to.be.false;
            expect(result.location.error.code).to.equal('INVALID_URL');
            expect(requests).to.deep.equal([]);
        });
    }

    describe('Assertion Record URLs', () => {
        const dmarc = {
            status: { result: 'pass', header: { from: 'example.com', d: 'example.com' } },
            domain: 'example.com',
            policy: 'reject',
            record: { p: 'reject' },
            orgRecord: false
        };
        const lookupRecord = (record: any) =>
            bimi({
                dmarc,
                headers: { parsed: [{ key: 'from', line: 'From: a@example.com' }] },
                resolver: async (name: any) => {
                    if (name === 'default._bimi.example.com') {
                        return [[record]];
                    }
                    throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
                }
            } as any);

        for (let host of ['127.0.0.1', '[::1]', 'localhost', 'bimi.localhost', 'intranet']) {
            it(`Should fail an l= URL with the host ${host}`, async () => {
                const result: any = await lookupRecord(`v=BIMI1; l=https://${host}/logo.svg`);
                expect(result.status.result).to.equal('fail');
                expect(result.status.comment).to.equal('invalid location value in dns record');
            });

            it(`Should fail an a= URL with the host ${host}`, async () => {
                const result: any = await lookupRecord(`v=BIMI1; l=https://example.com/logo.svg; a=https://${host}/vmc.pem`);
                expect(result.status.result).to.equal('fail');
                expect(result.status.comment).to.equal('invalid authority value in dns record');
            });
        }

        it('Should accept a URL with a domain name', async () => {
            const result: any = await lookupRecord('v=BIMI1; l=https://images.example.com/logo.svg; a=https://images.example.com/vmc.pem');
            expect(result.status.result).to.equal('pass');
        });
    });
});
