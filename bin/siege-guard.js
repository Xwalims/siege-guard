#!/usr/bin/env node
'use strict';

// The exit code must be passed out of main(), or the CLI always reports success
// even when it denied every request.
process.exitCode = require('../src/cli.js').main(process.argv.slice(2));