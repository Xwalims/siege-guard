'use strict';

/**
 * CLI for siege-guard.
 *
 * Three commands:
 *   simulate   run a synthetic attack through the guard and print the verdict
 *   inspect    print the resolved configuration and every threshold
 *   explain    render a decision record supplied as JSON on stdin
 *
 * Exit codes:
 *   0  success
 *   1  simulate finished and the defence denied traffic (that is a pass)
 *   2  usage or IO error
 */

const { SiegeGuard, ALLOW, THROTTLE, CHALLENGE, BLOCK, DEFAULTS } = require('./guard.js');
const { renderDecision, renderReport } = require('./explain.js');

const USAGE = `siege-guard -- adaptive application-layer DoS defence

Usage:
  siege-guard simulate [options]   run a synthetic attack, print the verdicts
  siege-guard inspect [options]    print the resolved configuration
  siege-guard explain              read a decision record as JSON on stdin

Options:
  --limit <cost>        budget in cost units per window   (default ${DEFAULTS.limit})
  --window <ms>         window width in milliseconds      (default ${DEFAULTS.windowMs})
  --ipv6-prefix <n>     IPv6 rate-limit prefix            (default ${DEFAULTS.ipv6Prefix})
  --ipv4-prefix <n>     IPv4 rate-limit prefix            (default ${DEFAULTS.ipv4Prefix})
  --block-score <0..1>  bot score that hard-blocks        (default ${DEFAULTS.blockScore})
  --challenge-score <0..1>  bot score that challenges      (default ${DEFAULTS.challengeScore})
  --strikes <n>         excesses before a hard block      (default ${DEFAULTS.strikesToBlock})
  --block-on-scan       turn a scan verdict into a block  (default off)
  --json                machine-readable output
  --quiet               suppress the human-readable output
  -h, --help            show this message

Exit codes: 0 ok, 1 traffic was denied, 2 usage or IO error.`;

/**
 * Parse argv into an options object.
 *
 * Every flag is validated here rather than deep inside the guard, so a typo
 * produces "unknown option" instead of a silently ignored setting.
 *
 * @param {string[]} argv
 * @returns {{command: string, options: object, errors: string[]}}
 */
function parseArgs(argv) {
  const options = {};
  const errors = [];
  let command = '';

  const numeric = { '--limit': 'limit', '--window': 'windowMs', '--ipv6-prefix': 'ipv6Prefix',
    '--ipv4-prefix': 'ipv4Prefix', '--block-score': 'blockScore',
    '--challenge-score': 'challengeScore', '--strikes': 'strikesToBlock' };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') {
      command = 'help';
      continue;
    }
    if (arg === '--json' || arg === '--quiet') {
      options[arg.slice(2)] = true;
      continue;
    }
    if (arg === '--block-on-scan') {
      options.blockOnScan = true;
      continue;
    }
    if (numeric[arg]) {
      const value = Number(argv[i + 1]);
      i += 1;
      if (!Number.isFinite(value)) {
        errors.push(`${arg} needs a number, got ${JSON.stringify(argv[i])}`);
      } else {
        options[numeric[arg]] = value;
      }
      continue;
    }
    if (arg.startsWith('-')) {
      errors.push(`unknown option ${arg}`);
      continue;
    }
    if (!command) command = arg;
    else errors.push(`unexpected argument ${JSON.stringify(arg)}`);
  }

  return { command, options, errors };
}

/**
 * One synthetic hostile request stream, with a simulated clock.
 *
 * This is the demonstration: real request shapes, a real clock, and the real
 * guard deciding. Nothing is generated here that the middleware would not see.
 *
 * @param {SiegeGuard} guard
 * @param {number} startAt
 * @returns {Array<{at: number, label: string, url: string, action: string, reason: string}>}
 */
function syntheticAttack(guard, startAt) {
  const steps = [];
  let now = startAt;

  /** Record one request and advance the clock a little. */
  const hit = (label, req, gap = 40) => {
    now += gap;
    const decision = guard.check(req);
    steps.push({
      at: now - startAt,
      label,
      url: req.url,
      action: decision.action,
      reason: decision.reason,
    });
  };

  const browser = (url, address) => ({
    method: 'GET', url, httpVersion: '1.1',
    socket: { remoteAddress: address },
    headers: {
      Host: 'oakwall.net',
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0 Safari/537.36',
      Accept: 'text/html,application/xhtml+xml',
      'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
      'Accept-Encoding': 'gzip, deflate, br',
      'Sec-Fetch-Mode': 'navigate',
    },
  });

  const scanner = (url, address) => ({
    method: 'GET', url, httpVersion: '1.1',
    socket: { remoteAddress: address },
    headers: { Host: 'oakwall.net' },
  });

  // 1. Honest traffic from a real browser.
  for (const path of ['/', '/catalog', '/catalog', '/product/1', '/about']) {
    hit('browser', browser(path, '203.0.113.7'));
  }

  // 2. A scanner enumerating paths, with no browser-shaped headers at all.
  //    It is served and charged a surcharge, not banned: a fingerprint alone is
  //    not evidence, and pretending otherwise would be the bug this package had.
  for (const path of ['/.env', '/wp-login.php', '/api/admin', '/api/users', '/.git/HEAD']) {
    hit('scanner', scanner(path, '198.51.100.23'));
  }

  // 2b. The same scanner that forges every header this package checks. It gets
  //     a fingerprint of 0.00 and is indistinguishable from Chrome, which is
  //     exactly why a fingerprint may not convict.
  const forged = (url, address) => ({
    method: 'GET', url, httpVersion: '1.1',
    socket: { remoteAddress: address },
    headers: {
      Host: 'oakwall.net',
      'User-Agent':
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
      'Accept-Encoding': 'gzip, deflate, br',
      'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none', 'Sec-Fetch-User': '?1',
      'Upgrade-Insecure-Requests': '1', Connection: 'keep-alive',
    },
  });
  for (const path of ['/.env', '/.git/config', '/wp-config.php.bak']) {
    hit('forged-scanner', forged(path, '198.51.100.77'));
  }

  // 3. An L7 flood from one host: many cheap requests, then a burst of writes.
  for (let i = 0; i < 60; i += 1) {
    hit('flood', browser(`/static/chunk${i}.js`, '192.0.2.66'), 5);
  }
  for (let i = 0; i < 20; i += 1) {
    const req = browser('/api/domains', '192.0.2.66');
    req.method = 'POST';
    hit('flood-write', req, 5);
  }

  // 4. The same flood rotated across a whole IPv6 /64. Every address is new,
  //    which defeats per-address limiting, and must not produce new budget.
  //    300 requests at cost 5 is 1500, comfortably past the default budget of
  //    1000, so a working limiter must stop this in the middle.
  for (let i = 1; i <= 300; i += 1) {
    hit('ipv6-rotate', browser('/api/data', `2001:db8::${i.toString(16)}`), 3);
  }

  // 5. Credential stuffing against the auth endpoint, priced at 100 each.
  for (let i = 0; i < 25; i += 1) {
    const req = browser('/api/auth/login', '198.51.100.99');
    req.method = 'POST';
    hit('credential-stuffing', req, 10);
  }

  return steps;
}

/** Render the simulate output as an aligned table. */
function renderSimulation(steps, report) {
  const lines = [];
  lines.push('siege-guard simulate');
  lines.push('====================');
  lines.push('');
  const header = ['  time', 'source', 'path', 'verdict', 'why'];
  lines.push(header.join(' '));
  lines.push('  ' + '-'.repeat(94));

  let previous = null;
  for (const step of steps) {
    // Print the first request of each source, then only the transitions, so the
    // output shows the shape of the defence instead of 400 near-identical lines.
    if (previous && previous.label === step.label && previous.action === step.action) continue;
    lines.push(
      [
        `  ${String(step.at).padStart(5)}ms`,
        step.label.padEnd(21),
        step.url.slice(0, 24).padEnd(24),
        step.action.toUpperCase().padEnd(8),
        step.reason.slice(0, 58),
      ].join(' ')
    );
    previous = step;
  }

  lines.push('');
  lines.push(renderReport(report));
  lines.push('');
  lines.push('What this run showed');
  lines.push('---------------------');
  const bySource = new Map();
  for (const step of steps) {
    const row = bySource.get(step.label) ||
      { total: 0, allow: 0, throttle: 0, challenge: 0, block: 0 };
    row.total += 1;
    if (step.action === ALLOW) row.allow += 1;
    else if (step.action === THROTTLE) row.throttle += 1;
    else if (step.action === CHALLENGE) row.challenge += 1;
    else row.block += 1;
    bySource.set(step.label, row);
  }
  for (const [label, row] of bySource) {
    lines.push(
      `  ${label.padEnd(21)} ${String(row.total).padStart(4)} requests  ` +
        `${String(row.allow).padStart(4)} allowed  ${String(row.throttle).padStart(4)} throttled  ` +
        `${String(row.challenge).padStart(4)} challenged  ${String(row.block).padStart(4)} blocked`
    );
  }
  return lines.join('\n');
}

/**
 * The simulate command.
 *
 * @param {object} options
 * @param {object} io
 * @returns {number} exit code
 */
function commandSimulate(options, io) {
  let now = 1_700_000_000_000;
  // A challenge hook is wired on purpose: it is what suspicion earns now that
  // it can no longer earn a ban. Without it the run would show fingerprints
  // doing nothing at all, which is not what this package does.
  const guard = new SiegeGuard({
    ...options,
    challenge: () => 'prove you are a browser',
    now: () => now,
  });
  const steps = syntheticAttack(guard, now);
  const report = guard.report();

  if (options.json) {
    io.out(JSON.stringify({ steps, report }, null, 2) + '\n');
  } else if (!options.quiet) {
    io.out(renderSimulation(steps, report) + '\n');
  }

  const denied = report.throttled + report.challenged + report.blocked;
  return denied > 0 ? 1 : 0;
}

/**
 * The inspect command.
 *
 * @param {object} options
 * @param {object} io
 * @returns {number}
 */
function commandInspect(options, io) {
  const resolved = { ...DEFAULTS, ...options };
  if (options.json) {
    io.out(JSON.stringify(resolved, null, 2) + '\n');
    return 0;
  }
  const lines = ['siege-guard configuration', '======================='];
  for (const [key, value] of Object.entries(resolved)) {
    if (typeof value === 'function') continue;
    lines.push(`  ${key.padEnd(22)} ${JSON.stringify(value)}`);
  }
  lines.push('');
  lines.push('Scope: application layer (L7). Volumetric L3/L4 floods are not');
  lines.push('addressed here and need an upstream scrubbing provider or anycast.');
  io.out(lines.join('\n') + '\n');
  return 0;
}

/**
 * The explain command.
 *
 * @param {object} options
 * @param {object} io
 * @returns {number}
 */
function commandExplain(options, io) {
  let text = '';
  try {
    text = io.read();
  } catch (error) {
    io.err(`cannot read stdin: ${error.message}\n`);
    return 2;
  }
  let record;
  try {
    record = JSON.parse(text);
  } catch (error) {
    io.err(`stdin is not valid JSON: ${error.message}\n`);
    return 2;
  }
  try {
    io.out(renderDecision(record) + '\n');
  } catch (error) {
    io.err(`cannot render the decision: ${error.message}\n`);
    return 2;
  }
  return 0;
}

/**
 * Entry point.
 *
 * @param {string[]} argv arguments after the node binary and script
 * @param {object} [io] injected streams, for tests
 * @returns {number} process exit code
 */
function main(argv, io = {}) {
  const out = io.out || ((text) => process.stdout.write(text));
  const err = io.err || ((text) => process.stderr.write(text));
  const read = io.read || (() => (io.stdin !== undefined ? io.stdin : require('node:fs').readFileSync(0, 'utf8')));
  const context = { out, err, read };

  const { command, options, errors } = parseArgs(argv);
  if (errors.length > 0) {
    for (const message of errors) err(`error: ${message}\n`);
    err('\n' + USAGE);
    return 2;
  }

  switch (command) {
    case 'help':
      out(USAGE + '\n');
      return 0;
    case '':
      // No command is a mistake, so the help text belongs on stderr where a
      // caller capturing stdout for data will not see it as output.
      err(USAGE + '\n');
      return 2;
    case 'simulate':
      return commandSimulate(options, context);
    case 'inspect':
      return commandInspect(options, context);
    case 'explain':
      return commandExplain(options, context);
    default:
      err(`error: unknown command ${JSON.stringify(command)}\n\n${USAGE}\n`);
      return 2;
  }
}

module.exports = Object.freeze({
  main,
  parseArgs,
  commandSimulate,
  commandInspect,
  commandExplain,
  renderSimulation,
  syntheticAttack,
  USAGE,
});