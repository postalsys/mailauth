# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

mailauth is a Node.js library and CLI tool for email authentication. It implements SPF, DKIM, DMARC, ARC, BIMI, and MTA-STS protocols. Pure JavaScript, no native dependencies. Requires Node.js >= 22.19.0.

## Commands

- **Run all tests (lint + mocha):** `npm test`
- **Run a single test file:** `npx mocha test/dkim/body/relaxed-test.js --reporter spec`
- **Run tests matching a pattern:** `npx mocha --recursive "./test/**/*.js" --reporter spec --grep "pattern"`
- **Coverage (c8, report in `coverage/`):** `npm run coverage`, then `npm run coverage:check` to enforce the thresholds in `.c8rc.json`
- **Mutation testing (StrykerJS, opt-in, about 15 minutes, report in `reports/mutation/`):** `npm run mutation`. Not part of `npm test` or CI; `stryker.config.json` lists the mutated modules
- **Lint only:** `npx eslint "lib/**/*.js" "test/**/*.js"`
- **Format code:** `npm run format` (uses Prettier)

## Code Style

- CommonJS (`require`/`module.exports`), not ES modules
- `'use strict'` at top of every file
- Mocha + Chai (expect style) for tests
- Prettier: 160 print width, 4-space indent, single quotes, no trailing commas, LF line endings
- ESLint: unused vars prefixed with `_`, `no-console` allowed

## Architecture

### Entry Point

`lib/mailauth.js` — exports `authenticate()` (the main all-in-one function) and individual protocol functions. The `authenticate` pipeline runs in order: DKIM verify → SPF → ARC → DMARC → BIMI, each step feeding results to the next.

### Protocol Modules

Each protocol lives in its own directory under `lib/`:

- **`lib/dkim/`** — DKIM signing (`sign.js`, `dkim-signer.js`, `DkimSignStream`) and verification (`verify.js`, `dkim-verifier.js`). Body canonicalization in `body/` (relaxed/simple), header canonicalization in `header/` (relaxed/simple). `message-parser.js` is the streaming RFC822 parser used by both signing and verification.
- **`lib/spf/`** — SPF verification (`spf-verify.js`), macro expansion (`macro.js`). Entry point `index.js` wraps the verifier.
- **`lib/dmarc/`** — DMARC verification (`verify.js`) and DNS record fetching (`get-dmarc-record.js`). Takes DKIM and SPF results as input.
- **`lib/arc/`** — ARC chain validation and seal creation. `trustlist.js` contains known ARC trust anchors.
- **`lib/bimi/`** — BIMI record resolution and SVG validation (`validate-svg.js`). Depends on DMARC passing.
- **`lib/mta-sts.js`** — MTA-STS policy fetching and MX validation (standalone, not part of authenticate pipeline).

### Shared Utilities

- **`lib/tools.js`** — DNS helpers, key parsing, header formatting, stream utilities, domain alignment checks
- **`lib/parse-dkim-headers.js`** — Parses structured DKIM/ARC header fields
- **`lib/parse-received.js`** — Parses Received headers

### CLI

`bin/mailauth.js` — commander-based CLI with subcommands: `report`, `sign`, `seal`, `spf`, `vmc`, `bodyhash`. Command implementations in `lib/commands/`.

### Tests

Tests mirror the `lib/` structure under `test/`. Property-based tests (fast-check) live in `test/property/` and run with a fixed seed as part of `npm test`; set `FC_NUM_RUNS=5000` (more cases) and `FC_SEED=random` (new inputs) to search harder locally. Independent reference implementations used as test oracles are in `test/helpers/` (`dkim-reference.js`, `arc-reference.js`, `rfc5322-reference.js`, `auth-results-reference.js`). Test fixtures in `test/fixtures/` include sample emails, DNS response caches, keys, and RFC test suite YAML files. Many tests use mock DNS resolvers that return fixture data instead of making real DNS queries.

### Type Definitions

`index.d.ts` and per-module `.d.ts` files provide TypeScript type definitions for consumers.

### Key Design Pattern

All protocol functions accept an optional `resolver` parameter (async function matching `dns.promises.resolve` signature) for DNS lookups. This enables testing with mock DNS and allows consumers to implement caching or custom resolution.

## Releases

Version numbers, changelogs, and releases are managed automatically by release-please via GitHub Actions. Do not manually edit `package.json` version, `CHANGELOG.md`, or release-related files.
