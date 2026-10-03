'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { SlidingWindow } = require('../src/window.js');

// ---------------------------------------------------------------------------
// The window must not be burst-exploited at a boundary. This is the test that
// proves the sliding window is real rather than a fixed window in disguise.
// ---------------------------------------------------------------------------

test('sliding window cannot be burst-exploited at a minute boundary', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 300 });
  const endOfMinute = 59_999; // inside window 0
  const startOfNext = 60_000; // inside window 1

  let allowedFirst = 0;
  for (let i = 0; i < 300; i += 1) {
    if (w.consume('attacker', 1, endOfMinute).allowed) allowedFirst += 1;
  }
  assert.equal(allowedFirst, 300, 'the first 300 must all fit');

  // A fixed window would admit another 300 here. The older bucket still holds
  // almost all of its weight at t=60000, so nothing is admitted.
  let allowedSecond = 0;
  for (let i = 0; i < 300; i += 1) {
    if (w.consume('attacker', 1, startOfNext).allowed) allowedSecond += 1;
  }
  assert.equal(
    allowedSecond,
    0,
    'a fixed window would admit 300 more here; the sliding window must not'
  );

  // Total cost admitted over the two seconds must never exceed the limit.
  assert.ok(
    w.used('attacker', startOfNext) <= 300,
    `total admitted ${w.used('attacker', startOfNext)} must not exceed the limit 300`
  );
});

test('sliding window admits again once the old bucket actually ages out', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 300 });
  for (let i = 0; i < 300; i += 1) w.consume('k', 1, 59_999);
  assert.equal(w.consume('k', 1, 60_000).allowed, false);
  // Half a window later, half of the old bucket has expired.
  const mid = w.consume('k', 1, 90_000);
  assert.equal(mid.allowed, true, 'half the window has passed, so some budget is back');
  assert.ok(mid.used < 300 && mid.used > 0, `expected a partial window, got ${mid.used}`);
});

test('sliding window interpolates smoothly as the older bucket ages out', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 100_000 });
  // Fill near the END of window 0, so the cost lands in the bucket that will
  // become the "older" one. Filling at t=0 would put everything in the current
  // bucket, which is not yet decaying.
  for (let i = 0; i < 500; i += 1) w.consume('k', 100, 59_000);

  const samples = [60_000, 75_000, 90_000].map((t) => w.used('k', t));
  const [a, b, c] = samples;
  assert.ok(a > b && b > c, `decay must be monotonic, got ${samples.join(', ')}`);
  // 15s into the next window, 15/60 of the older bucket has expired: 0.75 left.
  assert.ok(Math.abs(a * 0.75 - b) < 1, `expected ${a * 0.75}, got ${b}`);
  // 30s in, half remains.
  assert.ok(Math.abs(a * 0.5 - c) < 1, `expected ${a * 0.5}, got ${c}`);
});

test('clock going backwards never grants free quota', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 100 });
  w.consume('k', 100, 1_000_000); // spend the whole budget
  assert.equal(w.consume('k', 1, 1_000_000).allowed, false);
  // Step the clock backwards by five seconds: a naive computation makes the
  // older bucket gain weight and hands out free quota.
  const back = w.consume('k', 1, 995_000);
  assert.equal(back.allowed, false, 'a backwards clock must not restore budget');
  assert.ok(back.used <= 100, 'reported usage must not exceed the limit');
});

test('several backwards steps in a row never restore budget', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 50 });
  w.consume('k', 50, 500_000);
  let admitted = 0;
  for (let step = 1; step <= 20; step += 1) {
    if (w.consume('k', 5, 500_000 - step * 1000).allowed) admitted += 1;
  }
  assert.equal(admitted, 0, 'no request may be admitted while the budget is spent');
});

// ---------------------------------------------------------------------------
// Cost weighting
// ---------------------------------------------------------------------------

test('cost weighting makes cheap and expensive requests spend the same budget', () => {
  const cheap = new SlidingWindow({ windowMs: 60_000, limit: 1000 });
  const expensive = new SlidingWindow({ windowMs: 60_000, limit: 1000 });
  let cheapAllowed = 0;
  for (let i = 0; i < 1000; i += 1) if (cheap.consume('k', 1, 0).allowed) cheapAllowed += 1;
  let expensiveAllowed = 0;
  for (let i = 0; i < 20; i += 1) if (expensive.consume('k', 50, 0).allowed) expensiveAllowed += 1;
  assert.equal(cheapAllowed, 1000);
  assert.equal(expensiveAllowed, 20, '1000 cheap requests must equal 20 expensive ones');
  assert.equal(cheap.used('k', 0), expensive.used('k', 0));
});

test('a single request over the limit is refused rather than partially admitted', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 100 });
  const r = w.consume('k', 500, 0);
  assert.equal(r.allowed, false);
  assert.equal(w.used('k', 0), 0, 'a refused request must not consume budget');
});

test('a denied request reports a retry delay inside one window', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 10 });
  for (let i = 0; i < 10; i += 1) w.consume('k', 1, 0);
  const r = w.consume('k', 1, 0);
  assert.equal(r.allowed, false);
  assert.ok(r.retryAfterMs > 0 && r.retryAfterMs <= 60_000, `got ${r.retryAfterMs}`);
});

test('identities are isolated from each other', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 10 });
  for (let i = 0; i < 10; i += 1) w.consume('a', 1, 0);
  assert.equal(w.consume('a', 1, 0).allowed, false);
  assert.equal(w.consume('b', 1, 0).allowed, true, 'a second identity must have its own budget');
});

test('sweep drops idle identities and keeps active ones', () => {
  let t = 1_000_000;
  const w = new SlidingWindow({ windowMs: 1000, limit: 100, now: () => t });
  w.consume('stale', 1, t);
  t += 5000;
  w.consume('fresh', 1, t);
  const removed = w.sweep(t);
  assert.equal(removed, 1);
  assert.equal(w.keys.has('stale'), false);
  assert.equal(w.keys.has('fresh'), true);
});

test('snapshot sorts the hottest identity first', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 1000 });
  w.consume('cool', 10, 0);
  w.consume('hot', 900, 0);
  const snap = w.snapshot(0);
  assert.equal(snap.entries[0].key, 'hot');
  assert.equal(snap.keys, 2);
});