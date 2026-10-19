# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

mailauth is a Node.js library and CLI tool for email authentication. It implements SPF, DKIM, DKIM2, DMARC, ARC, BIMI, and MTA-STS. Written in TypeScript under `src/` and published as a dual package: ES modules in `dist/esm/` and CommonJS in `dist/cjs/`, each with its own type declarations. No native dependencies. Requires Node.js >= 22.19.0.

## Commands

- **Run all tests:** `npm test` (builds `dist/` first, then runs every `test/**/*-test.ts` with the Node.js test runner through tsx)
- **Run a single test file:** `node --import tsx --test test/dkim/body/relaxed-test.ts`
- **Run tests matching a name:** `node --import tsx --test --test-name-pattern="pattern" "test/**/*-test.ts"`
- **Lint and type-check:** `npm run lint` (`tsc --noEmit` over `src/` and `test/`, then ESLint with type-aware rules on `src/`)
- **Format:** `npm run format`, check with `npm run format:check` (Prettier)
- **Build:** `npm run build` (also runs on install from git and before publish through `prepare`)
- **CommonJS guard:** `npm run test:cjs` (see Platform constraints)
- **pkg binaries:** `npm run test:pkg` (slow, see Platform constraints)
- **Coverage (c8, source-mapped to `src/`, report in `coverage/`):** `npm run test:coverage`, fails below the thresholds in `.c8rc.json`
- **Mutation testing (StrykerJS, opt-in, slow, report in `reports/mutation/`):** `npm run mutation`. Not part of `npm test` or CI; `stryker.config.json` lists the mutated modules

## Code Style

- Source is ES module TypeScript, compiled twice from the same files: `tsconfig.esm.json` (`module: nodenext`) into `dist/esm/` and `tsconfig.cjs.json` (`module: commonjs`) into `dist/cjs/`. Code under `src/` must therefore not use `import.meta`, `require`, `module`, `exports`, `__dirname`, `__filename`, top-level `await`, or JSON imports.
- `tsconfig.base.json` is strict with `exactOptionalPropertyTypes`, `noImplicitOverride`, `isolatedModules` and `erasableSyntaxOnly` (no enums, no parameter properties, no runtime namespaces, no decorators).
- Relative imports carry the `.js` extension and point at a file (`'../tools.js'`, `'./spf/index.js'`), never at a directory.
- Node builtins use the `node:` prefix. Use a default import (`import https from 'node:https'`) when the whole module is used, so tests can still patch methods on it (the MTA-STS harness replaces `https.request`, the CLI tests preload a module that patches `node:dns`).
- Every optional property of an exported interface is written with an explicit `| undefined` (`strict?: boolean | undefined`), so consumers compiling with `exactOptionalPropertyTypes` can pass a value that may be undefined. `test/package/types-consumer-test.ts` sweeps every interface for it.
- Tests are TypeScript ES modules on `node:test` (`describe`/`it`) with chai `expect`. Derive `__dirname` with `path.dirname(fileURLToPath(import.meta.url))`. Timeouts are options (`it('name', { timeout: 10000 }, ...)`); a timeout on a `describe` is a budget for the whole suite, not per test.
- Prettier: 160 print width, 4-space indent, single quotes, no trailing commas, LF line endings. ESLint: the shared rule set (`../nodemailer/eslint.config.js` is the canonical form), repo-specific overrides at the end of `eslint.config.js`, each with a reason.
- No emojis, printable ASCII in code and docs.

## Platform constraints (IMPORTANT)

EmailEngine bundles mailauth into a single executable with [`@yao-pkg/pkg`](https://github.com/yao-pkg/pkg), and the mailauth CLI release binaries are built the same way (`npm run build-dist`). pkg snapshots a CommonJS `require()` graph and cannot load ES modules. ZoneMTA, WildDuck and the Haraka plugin `require()` mailauth and its deep modules. So:

- **The CommonJS build in `dist/cjs/` and every runtime dependency it pulls in must be genuinely CommonJS-loadable** with `require(esm)` switched off. Node 22+ loads ES modules through `require()` by default, which hides an ESM-only dependency until the pkg binary fails on it. A CommonJS entry that only wraps a dynamic `import()` does not count.
- Never upgrade a runtime dependency to an ESM-only major. Pin the last CommonJS major in `.ncurc.cjs` (`reject`, or a `target` of `minor`/`patch`) with a comment giving the reason. commander is held on 14.x for this reason.
- Check with `npm run test:cjs` after every dependency change. `test/package/cjs-smoke.cjs` runs under `--no-experimental-require-module`, requires the entry and every module of `dist/cjs/` through the exports map, runs DKIM, SPF, DMARC, ARC and `authenticate()`, and runs the CLI. It is plain JavaScript on purpose: tsx's loader would transpile an ES module and mask the failure.
- `npm run test:pkg` (`test/package/pkg-smoke.cjs`) packs the package with `npm pack`, installs the tarball into a scratch application, builds pkg binaries of that application and of the CLI, and runs them. CI runs it in the `pkg` job.
- Keep `require()`/`import` paths static so pkg can trace the graph.

## Export shapes

The CommonJS shapes are public API (`require('mailauth/lib/...')` deep imports are used by downstream projects). `test/fixtures/cjs-shapes-v7.json` records the `module.exports` of every module of the last CommonJS release (7.3.1) and `test/fixtures/esm-namespaces-v7.json` the names an ES module import of them saw; `test/package/package-test.ts` checks the build against both.

- Modules that were `module.exports = fn` (`dmarc/verify`, `dmarc/get-dmarc-record`, `parse-dkim-headers`, `spf/macro`, every `commands/*` except `resolver`) have a default export. `scripts/build.js` rewrites their CommonJS output so `require()` returns the function itself (with a non-enumerable `.default` alias). Extra values are attached as properties of the function (`getDmarcRecord.parseDmarcRecord`) and may also be exported by name for ES module consumers, but only as mirrors of those properties: the build loads every such module and fails when a named export is not a property of the default export.
- `src/mailauth.ts` (the entry) has named exports plus a default export object; in the CommonJS build its `default` is the module itself, non-enumerable.
- Everything else uses named exports only.
- `package.json` `exports` maps `.`, every directory module (`./lib/spf`, `./lib/dkim/body`, ...) and the `./lib/*` patterns to both builds; `typesVersions` covers the node10 resolution. A new directory module under `src/` needs its `./lib/<name>` entry (the package test checks this).
- Public types live in `src/types.ts` and are re-exported from the entry. The hand-written declarations of 7.x are kept in `test/fixtures/types-v7/` as the compatibility contract: `test/package/types-consumer-test.ts` checks that every function and class is still assignable to its old declared type and every old type name still exists. A deliberate change to that contract goes into its `intendedChanges` list with the reason.

## Architecture

### Entry Point

`src/mailauth.ts` exports `authenticate()` (the main all-in-one function) and the individual protocol functions. The `authenticate` pipeline runs in order: DKIM verify, SPF, ARC, DMARC, BIMI, each step feeding results to the next.

### Protocol Modules

- **`src/dkim/`** - DKIM signing (`sign.ts`, `dkim-signer.ts`, `DkimSignStream`) and verification (`verify.ts`, `dkim-verifier.ts`). Body canonicalization in `body/`, header canonicalization in `header/`. `message-parser.ts` is the streaming RFC 5322 parser that signing, verification and DKIM2 build on.
- **`src/dkim2/`** - DKIM2 (experimental, draft-ietf-dkim-dkim2-spec-06) signing, verification and hashing.
- **`src/spf/`** - SPF verification (`spf-verify.ts`), macro expansion (`macro.ts`), record syntax (`syntax.ts`). Entry point `index.ts`.
- **`src/dmarc/`** - DMARC verification (`verify.ts`), DNS record discovery (`get-dmarc-record.ts`), Author Domain extraction (`author-domain.ts`).
- **`src/arc/`** - ARC chain validation and sealing. `trustlist.ts` lists commonly trusted ARC sealers.
- **`src/bimi/`** - BIMI record resolution, VMC validation and SVG validation (`validate-svg.ts`). Depends on DMARC passing.
- **`src/mta-sts.ts`** - MTA-STS policy fetching and MX validation (standalone, not part of the authenticate pipeline).

### Shared Utilities

- **`src/tools.ts`** - DNS helpers, key parsing, header formatting, stream utilities, domain alignment checks
- **`src/parse-dkim-headers.ts`** - Parses structured DKIM/ARC header fields
- **`src/parse-received.ts`** - Parses Received headers
- **`src/types.ts`** - public option and result types
- **`src/vendor-types.d.ts`** - minimal declarations for the runtime dependencies without types (libmime, punycode.js, @postalsys/vmc)
- **`src/package-info.ts`** - generated by `scripts/build.js` from `package.json` (name, version, homepage), gitignored. Never import `package.json` from `src/`.

### CLI

`bin/mailauth.cjs` calls `run()` from the CommonJS build of `src/cli.ts` (commander, subcommands `report`, `sign`, `seal`, `spf`, `vmc`, `bodyhash`, `dkim2-sign`, `dkim2-verify`, `dkim2-hash`, `license`). Command implementations are in `src/commands/`.

### Tests

Tests mirror the `src/` structure under `test/`. Property-based tests (fast-check) live in `test/property/` and run with a fixed seed as part of `npm test`; set `FC_NUM_RUNS=5000` (more cases) and `FC_SEED=random` (new inputs) to search harder locally. Independent reference implementations used as test oracles are in `test/helpers/` (`dkim-reference.ts`, `dkim2-reference.ts`, `arc-reference.ts`, `rfc5322-reference.ts`, `auth-results-reference.ts`). Test fixtures in `test/fixtures/` include sample emails, DNS response caches, keys and RFC test suites. Many tests use mock DNS resolvers that return fixture data instead of making real DNS queries. `test/property/pipeline-fuzz-test.ts` fuzzes the whole `authenticate()` pipeline: a correctly signed and sealed message is damaged in transit-like ways and every DNS answer comes from a generated zone (valid, slightly wrong or hostile keys and policies, DNS errors, records split into odd character-strings); the result must settle within a bounded number of DNS queries, use only the defined result values, produce well-formed header fields, and not depend on how a streamed message is chunked. Raise `FC_NUM_RUNS` with `FC_SEED=random` for a soak run after touching the pipeline. `test/package/` checks the built `dist/` output: module shapes in both formats, the shipped declarations, the CommonJS guard and the pkg binaries.

`scripts/runtime-diff.js <baseline-dir> [files]` compares the JavaScript that `src/` compiles to with a baseline copy of the sources (types and comments erased, both formatted the same way). Use it to prove that a typing or refactoring change leaves the emitted code alone.

### Key Design Pattern

All protocol functions accept an optional `resolver` parameter (async function matching the `dns.promises.resolve` signature) for DNS lookups. This enables testing with mock DNS and allows consumers to implement caching or custom resolution.

## Releases

Version numbers, changelogs, and releases are managed automatically by release-please via GitHub Actions. Do not manually edit `package.json` version, `CHANGELOG.md`, or release-related files. The `prepare` script builds `dist/` before publish; build output is never committed.
