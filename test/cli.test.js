'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const cli = require('../src/cli.js');

const BIN = path.join(__dirname, '..', 'bin', 'siege-guard.js');

/** Run the real binary and capture everything. */
function run(args, input) {
  const result = spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    input: input === undefined ? '' : input,
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

// ---------------------------------------------------------------------------
// Exit codes, through the real process boundary
// ---------------------------------------------------------------------------

test('simulate exits 1 because the defence denies traffic', () => {
  const result = run(['simulate']);
  assert.equal(result.status, 1, `expected exit 1, got ${result.status}`);
  assert.match(result.stdout, /siege-guard simulate/);
});

test('inspect exits 0', () => {
  const result = run(['inspect']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /windowMs\s+60000/);
});

test('help exits 0 and lists the commands', () => {
  const result = run(['--help']);
  assert.equal(result.status, 0);
  for (const command of ['simulate', 'inspect', 'explain']) {
    assert.match(result.stdout, new RegExp(command));
  }
});

test('no command at all is a usage error', () => {
  const result = run([]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Usage:/);
});

test('an unknown command exits 2', () => {
  const result = run(['bogus']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown command/);
});

test('an unknown option exits 2 and names the option', () => {
  const result = run(['inspect', '--nonsense']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--nonsense/);
});

test('a non-numeric value for a numeric option exits 2', () => {
  const result = run(['simulate', '--limit', 'lots']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--limit needs a number/);
});

test('quiet suppresses the human output but keeps the exit code', () => {
  const result = run(['simulate', '--quiet']);
  assert.equal(result.status, 1, 'the denial must still be reported through the exit code');
  assert.equal(result.stdout, '');
});

test('json emits parseable output', () => {
  const result = run(['inspect', '--json']);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.limit, 1000);
  assert.equal(parsed.ipv6Prefix, 64);
});

test('simulate --json emits the steps and the report', () => {
  const result = run(['simulate', '--json']);
  assert.equal(result.status, 1);
  const parsed = JSON.parse(result.stdout);
  assert.ok(Array.isArray(parsed.steps));
  assert.ok(parsed.steps.length > 0);
  assert.equal(typeof parsed.report.decisions, 'number');
  assert.ok(parsed.report.blocked > 0, 'the demo must actually block something');
});

test('flags change the resolved configuration', () => {
  const result = run(['inspect', '--json', '--limit', '25', '--ipv6-prefix', '48', '--strikes', '9']);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.limit, 25);
  assert.equal(parsed.ipv6Prefix, 48);
  assert.equal(parsed.strikesToBlock, 9);
});

test('a smaller budget blocks more aggressively', () => {
  const generous = run(['simulate', '--json', '--limit', '100000']);
  const tight = run(['simulate', '--json', '--limit', '100']);
  const generousReport = JSON.parse(generous.stdout).report;
  const tightReport = JSON.parse(tight.stdout).report;
  assert.ok(
    tightReport.blocked > generousReport.blocked,
    `tight ${tightReport.blocked} should exceed generous ${generousReport.blocked}`
  );
});

test('block-on-scan is accepted as a flag', () => {
  const result = run(['simulate', '--json', '--block-on-scan', '--block-score', '0.99']);
  assert.equal(result.status, 1);
  const parsed = JSON.parse(result.stdout);
  assert.ok(parsed.report.decisions > 0);
});

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------

test('explain renders a decision record read from stdin', () => {
  const record = {
    action: 'block',
    status: 403,
    reason: 'budget exceeded 3 times: used 1000 of 1000 cost',
    retryAfterMs: 300000,
    identity: { normalized: '2001:db8::', family: 6, subnetSize: '18446744073709551616', prefix: 64, mapped: false },
    cost: { cost: 5, class: 'apiRead', reason: 'public API read' },
    fingerprint: { score: 0, reason: 'looks like an ordinary browser' },
    entropy: { samples: 12, entropy: 1.2, novelty: 0.1 },
    circuit: { state: 'closed', reason: 'circuit closed' },
    budget: { used: 1000, limit: 1000 },
  };
  const result = run(['explain'], JSON.stringify(record));
  assert.equal(result.status, 0);
  assert.match(result.stdout, /BLOCK\s+2001:db8::/);
  assert.match(result.stdout, /budget exceeded 3 times/);
  assert.match(result.stdout, /18446744073709551616/);
  assert.match(result.stdout, /after 300s/);
});

test('explain rejects invalid JSON with exit 2', () => {
  const result = run(['explain'], 'not json at all');
  assert.equal(result.status, 2);
  assert.match(result.stderr, /not valid JSON/);
});

test('explain survives a record missing every optional field', () => {
  const result = run(['explain'], JSON.stringify({ action: 'allow', reason: 'fine' }));
  assert.equal(result.status, 0);
  assert.match(result.stdout, /ALLOW/);
  assert.match(result.stdout, /fine/);
});

// ---------------------------------------------------------------------------
// Argument parsing, in process
// ---------------------------------------------------------------------------

test('parseArgs separates the command from the options', () => {
  const { command, options, errors } = cli.parseArgs(['simulate', '--limit', '5']);
  assert.equal(command, 'simulate');
  assert.equal(options.limit, 5);
  assert.deepEqual(errors, []);
});

test('parseArgs reports every problem it finds', () => {
  const { errors } = cli.parseArgs(['inspect', '--bogus', '--limit', 'x']);
  assert.equal(errors.length, 2);
  assert.match(errors[0], /--bogus/);
  assert.match(errors[1], /--limit/);
});

test('parseArgs rejects a stray positional argument', () => {
  const { errors } = cli.parseArgs(['simulate', 'extra']);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /unexpected argument/);
});

test('main returns 2 rather than throwing on bad input', () => {
  let out = '';
  let err = '';
  const code = cli.main(['inspect', '--bogus'], {
    out: (t) => {
      out += t;
    },
    err: (t) => {
      err += t;
    },
  });
  assert.equal(code, 2);
  assert.match(err, /--bogus/);
});

test('main writes to the injected streams', () => {
  let out = '';
  const code = cli.main(['inspect'], {
    out: (t) => {
      out += t;
    },
    err: () => {},
  });
  assert.equal(code, 0);
  assert.match(out, /siege-guard configuration/);
});

// ---------------------------------------------------------------------------
// The simulated attack itself
// ---------------------------------------------------------------------------

test('the simulation covers every kind of hostile traffic', () => {
  let now = 1_700_000_000_000;
  const { SiegeGuard } = require('../src/index.js');
  const guard = new SiegeGuard({ now: () => now });
  const steps = cli.syntheticAttack(guard, now);
  const labels = new Set(steps.map((s) => s.label));
  for (const expected of ['browser', 'scanner', 'flood', 'flood-write', 'ipv6-rotate', 'credential-stuffing']) {
    assert.ok(labels.has(expected), `the simulation is missing ${expected}`);
  }
});

test('the simulation refuses a scanner without touching the budget', () => {
  let now = 1_700_000_000_000;
  const { SiegeGuard } = require('../src/index.js');
  const guard = new SiegeGuard({ now: () => now });
  const steps = cli.syntheticAttack(guard, now);
  const scannerSteps = steps.filter((s) => s.label === 'scanner');
  assert.ok(scannerSteps.length > 0);
  assert.ok(
    scannerSteps.every((s) => s.action === 'block'),
    'every scanner request must be blocked'
  );
  assert.match(scannerSteps[0].reason, /fingerprint/);
});

test('the IPv6 rotation stops even though every address is new', () => {
  let now = 1_700_000_000_000;
  const { SiegeGuard } = require('../src/index.js');
  const guard = new SiegeGuard({ now: () => now });
  const steps = cli.syntheticAttack(guard, now);
  const rotated = steps.filter((s) => s.label === 'ipv6-rotate');
  assert.equal(rotated.length, 300);
  const allowed = rotated.filter((s) => s.action === 'allow').length;
  assert.ok(allowed < 300, `a rotating flood must be stopped, but ${allowed} of 300 passed`);
  assert.equal(guard.window.keys.size <= 4, true, '300 addresses must not become 300 budgets');
});

test('the honest visitor is never disturbed', () => {
  let now = 1_700_000_000_000;
  const { SiegeGuard } = require('../src/index.js');
  const guard = new SiegeGuard({ now: () => now });
  const steps = cli.syntheticAttack(guard, now);
  const visitor = steps.filter((s) => s.label === 'browser');
  assert.ok(visitor.length > 0);
  assert.ok(
    visitor.every((s) => s.action === 'allow'),
    `an honest visitor was refused: ${JSON.stringify(visitor.filter((s) => s.action !== 'allow'))}`
  );
});

test('credential stuffing dies on ten attempts, not a thousand', () => {
  let now = 1_700_000_000_000;
  const { SiegeGuard } = require('../src/index.js');
  const guard = new SiegeGuard({ now: () => now });
  const steps = cli.syntheticAttack(guard, now);
  const stuffing = steps.filter((s) => s.label === 'credential-stuffing');
  const allowed = stuffing.filter((s) => s.action === 'allow').length;
  assert.ok(allowed <= 11, `only ${allowed} login attempts should be served, not ${allowed} of ${stuffing.length}`);
});

test('the simulation renders a table and a summary', () => {
  let now = 1_700_000_000_000;
  const { SiegeGuard } = require('../src/index.js');
  const guard = new SiegeGuard({ now: () => now });
  const steps = cli.syntheticAttack(guard, now);
  const text = cli.renderSimulation(steps, guard.report());
  assert.match(text, /What this run showed/);
  assert.match(text, /ipv6-rotate/);
  assert.match(text, /siege-guard state/);
});

test('the rendered table shows transitions, not every request', () => {
  let now = 1_700_000_000_000;
  const { SiegeGuard } = require('../src/index.js');
  const guard = new SiegeGuard({ now: () => now });
  const steps = cli.syntheticAttack(guard, now);
  const text = cli.renderSimulation(steps, guard.report());
  const rowCount = (text.match(/^\s+\d+ms\s/gm) || []).length;
  assert.ok(rowCount < steps.length, `expected fewer rows than steps, got ${rowCount} of ${steps.length}`);
  assert.ok(rowCount >= 6, 'the table must still show the important transitions');
});