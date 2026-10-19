#!/usr/bin/env node

'use strict';

// The command line entry. It loads the CommonJS build on purpose: the CLI is bundled
// into @yao-pkg/pkg binaries, which can only load a CommonJS module graph.

const path = require('node:path');
const { run } = require('../dist/cjs/cli.js');

run(process.argv, { root: path.join(__dirname, '..') });
