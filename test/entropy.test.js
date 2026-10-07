'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { PathEntropyTracker, shannonEntropy, SCAN_ENTROPY, SCAN_NOVELTY } = require('../src/entropy.js');

// A human reading a site: few distinct paths, revisited constantly.
const BENIGN_TRACE = [
  '/', '/', '/', '/catalog', '/catalog', '/catalog', '/product/1',
  '/product/1', '/', '/catalog', '/product/2', '/product/1', '/about', '/about',
];

// A directory enumerator: every path touched exactly once, none repeated.
const HOSTILE_TRACE = [
  '/.env', '/wp-login.php', '/api/admin', '/api/users', '/backup.sql',
  '/.git/HEAD', '/phpmyadmin', '/admin/config', '/api/debug', '/server-status',
  '/.aws/credentials', '/config.php', '/id_rsa', '/.htaccess',
];

/** Final verdict of a trace, after it has been fully replayed. */
function runTrace(trace, options = {}) {
  const tracker = new PathEntropyTracker(options);
  let verdict;
  for (const path of trace) verdict = tracker.observe('client', path);
  return verdict;
}

test('Shannon entropy of a uniform distribution equals log2 of its size', () => {
  assert.equal(shannonEntropy([1, 1, 1, 1]), 2);
  assert.equal(shannonEntropy([1, 1, 1, 1, 1, 1, 1, 1]), 3);
  assert.equal(shannonEntropy([10, 10, 10, 10]), 2);
});

test('Shannon entropy of a degenerate distribution is zero', () => {
  assert.equal(shannonEntropy([100]), 0);
  assert.equal(shannonEntropy([]), 0);
  assert.equal(shannonEntropy([0, 0, 0]), 0);
});

test('entropy grows as a distribution spreads out', () => {
  const tight = shannonEntropy([90, 5, 5]);
  const loose = shannonEntropy([34, 33, 33]);
  assert.ok(tight < loose, `${tight} should be below ${loose}`);
});

test('the benign trace stays below the scan threshold', () => {
  const verdict = runTrace(BENIGN_TRACE);
  assert.equal(verdict.isScan, false, `a human was flagged as a scanner: ${verdict.reason}`);
});

test('the hostile trace crosses the scan threshold', () => {
  const verdict = runTrace(HOSTILE_TRACE);
  assert.equal(verdict.isScan, true, `a scanner passed as human: ${verdict.reason}`);
});

test('the separation between benign and hostile traces is wide', () => {
  const benign = runTrace(BENIGN_TRACE);
  const hostile = runTrace(HOSTILE_TRACE);
  // Novelty separates them cleanly: a human re-requests known paths, an
  // enumerator never repeats.
  const margin = hostile.novelty - benign.novelty;
  assert.ok(
    margin >= 0.4,
    `novelty margin is only ${margin.toFixed(3)} (benign ${benign.novelty}, hostile ${hostile.novelty})`
  );
  assert.ok(
    hostile.novelty >= SCAN_NOVELTY,
    `hostile novelty ${hostile.novelty} must reach the threshold ${SCAN_NOVELTY}`
  );
  assert.ok(
    benign.novelty < SCAN_NOVELTY,
    `benign novelty ${benign.novelty} must stay below ${SCAN_NOVELTY}`
  );
});

test('entropy for a trace of unique paths approaches log2 of its length', () => {
  const trace = Array.from({ length: 16 }, (_, i) => `/p${i}`);
  const verdict = runTrace(trace);
  assert.ok(
    Math.abs(verdict.entropy - Math.log2(16)) < 0.01,
    `expected log2(16)=4, got ${verdict.entropy}`
  );
});

test('the recorded thresholds sit between the two measured traces', () => {
  const benign = runTrace(BENIGN_TRACE);
  const hostile = runTrace(HOSTILE_TRACE);
  // The entropy threshold must not be below what a human produces, or every
  // repeat-heavy client gets flagged; and not above what an enumerator reaches.
  assert.ok(
    SCAN_ENTROPY <= hostile.entropy,
    `SCAN_ENTROPY ${SCAN_ENTROPY} exceeds what a scanner reaches ${hostile.entropy}`
  );
});

test('no verdict is offered before enough distinct paths are seen', () => {
  const tracker = new PathEntropyTracker();
  for (let i = 0; i < 7; i += 1) {
    const v = tracker.observe('c', `/p${i}`);
    assert.equal(v.isScan, false);
    assert.match(v.reason, /need 8 distinct paths/);
  }
  const v = tracker.observe('c', '/p7');
  assert.equal(v.samples, 8);
  assert.notEqual(v.reason, undefined);
});

test('high entropy alone is not enough without novelty', () => {
  // An API client that walks a wide resource tree but keeps returning to known
  // paths: spread out, yet not enumerating anything. The trace is long enough
  // to push entropy above SCAN_ENTROPY, so the only reason it is not a scan is
  // that novelty stays low.
  const tracker = new PathEntropyTracker();
  const trace = [
    ...Array.from({ length: 24 }, (_, i) => `/api/resource${i}`),
    ...Array.from({ length: 36 }, (_, i) => `/api/resource${i % 4}`),
  ];
  let verdict;
  for (const path of trace) verdict = tracker.observe('c', path);
  assert.equal(verdict.isScan, false, `flagged a repeating API client: ${verdict.reason}`);
  assert.ok(
    verdict.entropy >= SCAN_ENTROPY,
    `this trace must exceed SCAN_ENTROPY to exercise the branch, got ${verdict.entropy}`
  );
  assert.ok(
    verdict.novelty < SCAN_NOVELTY,
    `novelty must stay low for the reason to be about repeats, got ${verdict.novelty}`
  );
  assert.match(verdict.reason, /known ones repeat/);
});

test('identities are tracked separately', () => {
  const tracker = new PathEntropyTracker();
  for (const p of HOSTILE_TRACE) tracker.observe('scanner', p);
  const verdict = tracker.score('innocent');
  assert.equal(verdict.isScan, false);
  assert.equal(verdict.samples, 0);
});

test('history is bounded so memory cannot grow without limit', () => {
  const tracker = new PathEntropyTracker({ history: 16 });
  for (let i = 0; i < 500; i += 1) tracker.observe('c', `/p${i}`);
  assert.equal(tracker.state.get('c').order.length, 16);
  assert.ok(tracker.state.get('c').seen.size <= 16);
});

test('a forgotten path is remembered as novel if it comes back', () => {
  const tracker = new PathEntropyTracker({ history: 4 });
  for (const p of ['/a', '/b', '/c', '/d', '/e']) tracker.observe('c', p);
  // '/a' was pushed out of the window, so returning to it counts as novel.
  const v = tracker.observe('c', '/a');
  assert.equal(v.samples >= 4, true);
});

test('reset forgets an identity completely', () => {
  const tracker = new PathEntropyTracker();
  for (const p of HOSTILE_TRACE) tracker.observe('c', p);
  assert.equal(tracker.reset('c'), true);
  assert.equal(tracker.score('c').samples, 0);
  assert.equal(tracker.reset('c'), false);
});

// ---------------------------------------------------------------------------
// sweep() must actually drop identities
//
// It used to test `entry.lastSeen`, which no code path ever wrote. The field
// was `undefined` on every entry, so the guard condition could never be true and
// the method returned 0 for every input -- 20,000 identities and ten hours of
// idle time still left all 20,000 resident, which is the slow DoS the README
// tells operators to call sweep() to prevent. These tests pin the three
// properties the old code had none of: a stale identity is dropped, a fresh one
// is not, and an ignored (static) request still counts as activity.
// ---------------------------------------------------------------------------

test('sweep drops identities that have gone idle', () => {
  let t = 1_000_000;
  const tracker = new PathEntropyTracker({ now: () => t, sweepKeepMs: 300_000 });
  for (let i = 0; i < 50; i += 1) tracker.observe(`10.0.0.${i}`, `/p/${i}`);
  assert.equal(tracker.state.size, 50);

  // An identity with no usable timestamp is the old code's failure mode, so it
  // is asserted directly rather than left to the shape of the entry object.
  assert.equal(
    tracker.state.get('10.0.0.0').lastSeen,
    t,
    'observe() must stamp the identity, or sweep has nothing to compare against',
  );

  t += 299_000;
  assert.equal(tracker.sweep(), 0, 'an identity inside the keep window must be kept');
  assert.equal(tracker.state.size, 50);

  t += 2_000;
  assert.equal(tracker.sweep(), 50, 'every idle identity must be dropped');
  assert.equal(tracker.state.size, 0);
});

test('sweep keeps an identity that is still active', () => {
  let t = 1_000_000;
  const tracker = new PathEntropyTracker({ now: () => t, sweepKeepMs: 10_000 });
  tracker.observe('quiet', '/a');
  t += 60_000;
  tracker.observe('loud', '/b');
  // Only the re-stamped identity survives, even though the sweep is a single
  // pass over the same map.
  assert.equal(tracker.sweep(10_000, t), 1);
  assert.equal(tracker.state.has('quiet'), false);
  assert.equal(tracker.state.has('loud'), true);
});

test('an identity that only requests ignored assets is still tracked and sweepable', () => {
  // Static assets never enter the sample, so an entry built only from them has
  // an empty `order`. It is still a real client, and before this fix it was a
  // permanent leak with nothing to sweep it: `samples` was 0, but the identity
  // had to be countable for the memory claim in the README to be true.
  let t = 1_000_000;
  const tracker = new PathEntropyTracker({ now: () => t, sweepKeepMs: 1_000 });
  const verdict = tracker.observe('assets', '/app.4f2a91.js');
  assert.equal(verdict.ignored, true);
  assert.equal(verdict.samples, 0, 'an ignored path must not enter the sample');
  assert.equal(tracker.state.size, 1, 'but the identity must still be held so it can be swept');
  t += 2_000;
  assert.equal(tracker.sweep(1_000, t), 1);
  assert.equal(tracker.state.size, 0);
});

test('an entry with no timestamp is dropped rather than kept forever', () => {
  // The precise old failure: `lastSeen` absent meant the old condition was
  // false, so the entry survived every sweep. Unknown liveness must not mean
  // immortal.
  const tracker = new PathEntropyTracker({ now: () => 1_000 });
  tracker.state.set('legacy', {
    order: [],
    seen: new Set(),
    requests: 0,
    novel: 0,
  });
  assert.equal(tracker.sweep(1_000_000, 2_000_000), 1);
  assert.equal(tracker.state.has('legacy'), false);
});

test('a scan verdict names the numbers that produced it', () => {
  const verdict = runTrace(HOSTILE_TRACE);
  assert.match(verdict.reason, /entropy [\d.]+ >= 3\.4/);
  assert.match(verdict.reason, /novelty [\d.]+ >= 0\.6/);
});

test('the entropy of a long uniform trace never exceeds log2 of its length', () => {
  for (const n of [8, 16, 64, 256]) {
    const trace = Array.from({ length: n }, (_, i) => `/p${i}`);
    const verdict = runTrace(trace);
    assert.ok(
      verdict.entropy <= Math.log2(n) + 0.001,
      `${n} paths gave entropy ${verdict.entropy}, above log2(${n})`
    );
  }
});

// ---------------------------------------------------------------------------
// Static assets must not look like an enumeration
// ---------------------------------------------------------------------------

test('hashed static asset names are not treated as a scan', () => {
  // A bundler or CDN emits /assets/app.<hash>.js, so a single-page app produces
  // hundreds of distinct paths. Flagging that as enumeration challenges ordinary
  // users, which is how a limiter gets switched off.
  const tracker = new PathEntropyTracker();
  const trace = Array.from({ length: 60 }, (_, i) =>
    `/assets/chunk.${i.toString(16).padStart(8, '0')}.js`
  );
  let verdict;
  for (const p of trace) verdict = tracker.observe('c', p);
  assert.equal(verdict.isScan, false, `legitimate asset loading flagged: ${verdict.reason}`);
  assert.equal(verdict.ignored, true);
  assert.equal(verdict.samples, 0, 'ignored paths must not enter the sample');
});

test('a real scanner reaching for non-static paths is still caught', () => {
  // The ignore list must not become a blind spot: these are the paths an
  // enumerator actually wants.
  const tracker = new PathEntropyTracker();
  const trace = [
    '/.env', '/wp-login.php', '/api/admin', '/api/users', '/backup.sql',
    '/.git/HEAD', '/phpmyadmin', '/config.php', '/id_rsa', '/.htaccess',
    '/server-status', '/api/debug', '/.aws/credentials', '/proc/self/environ',
    '/wp-config.php', '/admin/login',
  ];
  let verdict;
  for (const p of trace) verdict = tracker.observe('c', p);
  assert.equal(verdict.isScan, true, `an enumerator passed: ${verdict.reason}`);
});

test('a mixed trace of assets and one real probe stays below the threshold', () => {
  const tracker = new PathEntropyTracker();
  const trace = [
    '/app.css', '/app.js', '/logo.png', '/a1.woff2', '/b2.woff2',
    '/app.css', '/app.js', '/logo.png', '/.env',
  ];
  let verdict;
  for (const p of trace) verdict = tracker.observe('c', p);
  assert.equal(verdict.isScan, false, `one probe among assets flagged: ${verdict.reason}`);
});

test('an operator can supply their own ignore patterns', () => {
  const tracker = new PathEntropyTracker({
    ignorePatterns: [/^\/health/, /\.js$/],
  });
  for (const p of ['/health/live', '/health/ready', '/a.js', '/b.js']) {
    assert.equal(tracker.observe('c', p).ignored, true, `${p} should be ignored`);
  }
  const probe = tracker.observe('c', '/api/admin');
  assert.notEqual(probe.ignored, true, 'a path outside the patterns must be tracked');
});

test('a string pattern is accepted as well as a RegExp', () => {
  const tracker = new PathEntropyTracker({ ignorePatterns: ['^/internal/'] });
  assert.equal(tracker.observe('c', '/internal/debug').ignored, true);
  assert.notEqual(tracker.observe('c', '/api/x').ignored, true);
});
