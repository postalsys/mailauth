import { describe, it } from 'node:test';
import { expect } from 'chai';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// These tests exercise the compiled output in dist/ (built by the pretest script) through
// the package.json exports map, the way an installed copy of the package is loaded. Node
// resolves the package name to the package itself when it is used from inside the package.
const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..', '..');

// Non-literal specifiers keep TypeScript from resolving the built types at type-check time,
// when dist/ may not exist yet
const packageName: string = 'mailauth';
const subpath = (name: string) => packageName + '/lib/' + name;

const readJSON = (file: string) => JSON.parse(fs.readFileSync(file, 'utf8'));
const pkg = readJSON(path.join(root, 'package.json'));

// The module.exports of every lib/ module of the last CommonJS release (7.3.1), and the
// names an ES module import of it saw. Captured from the published tarball
const cjsShapes: Record<string, { type: string; keys?: string[]; props?: string[]; members?: Record<string, string> }> = readJSON(
    path.join(root, 'test', 'fixtures', 'cjs-shapes-v7.json')
);
const esmNamespaces: Record<string, string[]> = readJSON(path.join(root, 'test', 'fixtures', 'esm-namespaces-v7.json'));

// Exports added after 7.3.1. An addition keeps every existing caller working, listing them
// here keeps it deliberate: anything else that appears in or disappears from a module fails
const addedExports: Record<string, Record<string, string>> = {
    tools: { indexHeaderKeys: 'function' }
};

const expectedShape = (name: string) => {
    const shape = cjsShapes[name];
    const added = addedExports[name];
    if (!added) {
        return shape;
    }
    const members = { ...shape.members, ...added };
    return { ...shape, keys: Object.keys(members).sort(), members };
};

const shapeOf = (value: any) => {
    if (typeof value === 'function') {
        return {
            type: 'function',
            props: Object.getOwnPropertyNames(value)
                .filter(key => !['length', 'name', 'prototype', 'arguments', 'caller', 'default'].includes(key))
                .sort()
        };
    }
    let keys = Object.keys(value).sort();
    return { type: 'object', keys, members: Object.fromEntries(keys.map(key => [key, typeof value[key]])) };
};

describe('Built package', { timeout: 30 * 1000 }, () => {
    it('ships both module formats with type declarations', () => {
        for (const format of ['esm', 'cjs']) {
            expect(fs.existsSync(path.join(root, 'dist', format, 'mailauth.js')), format + ' entry point').to.be.true;
            expect(fs.existsSync(path.join(root, 'dist', format, 'mailauth.d.ts')), format + ' type declarations').to.be.true;
            expect(fs.existsSync(path.join(root, 'dist', format, 'spf', 'index.d.ts')), format + ' subpath declarations').to.be.true;
        }
        expect(readJSON(path.join(root, 'dist', 'esm', 'package.json'))).to.deep.equal({ type: 'module' });
        expect(readJSON(path.join(root, 'dist', 'cjs', 'package.json'))).to.deep.equal({ type: 'commonjs' });
    });

    it('maps every directory module to a ./lib subpath and every target exists', () => {
        const dirs = (fs.readdirSync(path.join(root, 'src'), { recursive: true }) as string[])
            .filter(name => name.endsWith(path.sep + 'index.ts') || name === 'index.ts')
            .map(name => path.dirname(name).split(path.sep).join('/'));
        expect(dirs.length).to.be.at.least(6);
        for (const dir of dirs) {
            const entry = pkg.exports['./lib/' + dir];
            expect(entry, 'package.json exports lacks ./lib/' + dir).to.be.an('object');
            expect(entry.import).to.equal('./dist/esm/' + dir + '/index.js');
            expect(entry.require).to.equal('./dist/cjs/' + dir + '/index.js');
        }
        for (const [name, entry] of Object.entries(pkg.exports)) {
            if (name.includes('*') || typeof entry === 'string') {
                continue;
            }
            for (const target of Object.values(entry as Record<string, string>)) {
                expect(fs.existsSync(path.join(root, target)), name + ' points at a missing file ' + target).to.be.true;
            }
        }
    });

    describe('CommonJS build', () => {
        it('loads the entry point with the same exports as the CommonJS release', () => {
            const mailauth = require(packageName);
            expect(require(path.join(root, pkg.main))).to.equal(mailauth);
            expect(shapeOf(mailauth)).to.deep.equal(cjsShapes.mailauth);
            // the default export is the module itself, and not enumerable
            expect(mailauth.default).to.equal(mailauth);
            expect(Object.keys(mailauth)).to.not.include('default');
        });

        // require('mailauth/lib/...') deep imports are used by EmailEngine, ZoneMTA, WildDuck and
        // the Haraka plugin, so every module keeps the exact module.exports shape it had
        for (const [name, expected] of Object.entries(cjsShapes)) {
            it(`require('mailauth/lib/${name}') keeps its module.exports shape`, () => {
                const mod = require(subpath(name));
                expect(shapeOf(mod)).to.deep.equal(expectedShape(name));
                // with and without the extension
                expect(require(subpath(name + '.js'))).to.equal(mod);
                if (expected.type === 'function') {
                    // modules that export a function keep a non-enumerable default alias for
                    // transpiled default imports
                    expect(mod.default).to.equal(mod);
                }
            });
        }

        it('resolves the directory subpaths to their index module', () => {
            for (const dir of ['arc', 'bimi', 'dkim/body', 'dkim/header', 'dmarc', 'spf']) {
                expect(require(subpath(dir))).to.equal(require(subpath(dir + '/index')));
            }
        });

        it('keeps the default-export modules default-only', () => {
            // scripts/build.js turns these into module.exports = function, so they must not gain
            // named exports
            for (const name of ['dmarc/verify', 'dmarc/get-dmarc-record', 'parse-dkim-headers', 'spf/macro', 'commands/report']) {
                expect(require(subpath(name))).to.be.a('function');
            }
        });
    });

    describe('ES module build', () => {
        it('imports the entry point with named exports and a default object', async () => {
            const mailauth = await import(packageName);
            for (const name of cjsShapes.mailauth.keys!) {
                expect(mailauth[name], name).to.be.a('function');
                expect(mailauth.default[name], 'default.' + name).to.equal(mailauth[name]);
            }
        });

        it('exposes every name the CommonJS release exposed to an ES module import', async () => {
            for (const [name, names] of Object.entries(esmNamespaces)) {
                const ns = await import(subpath(name + '.js'));
                const expected = names.filter(key => !['default', 'module.exports'].includes(key));
                for (const key of expected) {
                    expect(ns, name + ' lacks ' + key).to.have.property(key);
                }
                if (cjsShapes[name].type === 'function') {
                    expect(ns.default, name + ' default export').to.be.a('function');
                }
            }
        });

        it('exports the same runtime names from both builds', async () => {
            for (const name of Object.keys(cjsShapes)) {
                const cjs = require(subpath(name));
                const esm = await import(subpath(name + '.js'));
                if (typeof cjs === 'function') {
                    // a default-export module also names the properties of its function, so that
                    // named imports keep working for ES module consumers
                    const named = Object.keys(esm).filter(key => key !== 'default');
                    expect(named.sort(), name).to.deep.equal(shapeOf(cjs).props);
                    for (const key of named) {
                        expect(esm[key], name + ' ' + key).to.equal(esm.default[key]);
                    }
                } else {
                    const esmNames = Object.keys(esm)
                        .filter(key => key !== 'default')
                        .sort();
                    expect(esmNames, name).to.deep.equal(Object.keys(cjs).sort());
                }
            }
        });

        it('loads the ES module build as ES modules, not through the CommonJS one', async () => {
            const esm = await import(packageName);
            const cjs = require(packageName);
            expect(esm.authenticate).to.not.equal(cjs.authenticate);
        });
    });

    it('runs the command line entry from bin/', () => {
        expect(pkg.bin).to.deep.equal({ mailauth: 'bin/mailauth.cjs' });
        const bin = fs.readFileSync(path.join(root, pkg.bin.mailauth), 'utf8');
        expect(bin.startsWith('#!/usr/bin/env node\n')).to.be.true;
        expect(bin).to.include("require('../dist/cjs/cli.js')");
    });
});
