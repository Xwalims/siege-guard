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