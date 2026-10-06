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

test('a denied request reports a retry delay a client can actually use', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 10 });
  for (let i = 0; i < 10; i += 1) w.consume('k', 1, 0);
  const r = w.consume('k', 1, 0);
  assert.equal(r.allowed, false);
  assert.ok(r.retryAfterMs > 0, `got ${r.retryAfterMs}`);

  // The budget was spent at t=0, so the charge sits in a bucket that only starts
  // decaying once the window rolls over at t=60000. It must then decay to 9 of
  // 10, which frees exactly one unit at t=66000 -- not at t=60000. The old
  // expectation of "<= one window" described a promise the window could not
  // keep: a client obeying it was refused again. Check the promise instead.
  assert.equal(r.retryAfterMs, 66_000, 'the delay must be when the cost actually fits');

  const atDelay = new SlidingWindow({ windowMs: 60_000, limit: 10 });
  atDelay.keys.set('k', cloneState(w.keys.get('k')));
  assert.equal(
    atDelay.consume('k', 1, r.retryAfterMs).allowed,
    true,
    'a client that obeys retryAfterMs must be admitted'
  );
});

// ---------------------------------------------------------------------------
// Denials ACROSS A WINDOW BOUNDARY.
//
// The single-window case above never populates state.older, so it never reaches
// the branch that solves for the retry delay from the older bucket. A window
// object only gets an `older` bucket when traffic is admitted into one window
// while the previous window's bucket still exists -- i.e. across a boundary.
// Every test below therefore deliberately crosses one.
// ---------------------------------------------------------------------------

/** Fill a window, then cross the boundary so an `older` bucket exists. */
function crossedWindow({ limit, olderCost, newerCost, windowMs = 60_000 }) {
  const w = new SlidingWindow({ windowMs, limit });
  if (olderCost > 0) {
    let left = olderCost;
    while (left > 0) {
      const chunk = Math.min(10, left);
      assert.equal(w.consume('k', chunk, windowMs - 1).allowed, true);
      left -= chunk;
    }
  }
  if (newerCost > 0) {
    let left = newerCost;
    while (left > 0) {
      const chunk = Math.min(10, left);
      assert.equal(w.consume('k', chunk, windowMs + 1).allowed, true);
      left -= chunk;
    }
  }
  return w;
}

test('a denial after the window rolled over does not throw', () => {
  const w = crossedWindow({ limit: 100, olderCost: 30, newerCost: 70 });
  const r = w.consume('k', 1, 60_100);
  assert.equal(r.allowed, false, 'the budget is spent');
  assert.equal(r.reason, 'budget-exhausted');
  assert.ok(r.retryAfterMs > 0, 'a denial must still tell the client when to retry');
  assert.ok(r.used <= 100, `reported usage ${r.used} must not exceed the limit`);
});

test('a denial after the window rolled over reports no cost it was not charged', () => {
  const w = crossedWindow({ limit: 100, olderCost: 30, newerCost: 70 });
  const r = w.consume('k', 1, 60_100);
  // At t=60100 the 30 spent in window 0 has decayed by 100/60000, so the real
  // figure is 99.95. It must never be reported as more than the limit, and
  // `remaining` must be exactly what is left -- not clamped to zero.
  assert.ok(r.used <= 100, `used ${r.used} must not exceed the limit`);
  assert.ok(Math.abs(r.used - 99.95) < 1e-9, `expected 99.95, got ${r.used}`);
  assert.ok(
    Math.abs(r.remaining - (100 - r.used)) < 1e-9,
    `remaining ${r.remaining} does not match limit - used`
  );
});

/**
 * The delay has one promise to keep: a client that waits exactly retryAfterMs
 * and retries must be ADMITTED. Waiting longer is merely annoying; being
 * refused at the promised time means the 429 lied about its own expiry.
 *
 * The check below brute-forces the real accept path rather than restating the
 * formula, so it fails if the maths drifts away from the window's behaviour.
 */
function assertRetryHonoured(state, spend, now, limit, windowMs = 60_000) {
  const denied = (() => {
    const probe = new SlidingWindow({ windowMs, limit });
    probe.keys.set('k', cloneState(state));
    return probe.consume('k', spend, now);
  })();
  assert.equal(
    denied.allowed,
    false,
    `expected a denial at t=${now} ` +
      `(used ${denied.used.toFixed(2)} of ${limit}, spend ${spend}, ` +
      `older ${state.older.cost}, newer ${state.newer.cost})`
  );

  const retryAt = now + denied.retryAfterMs;
  const atRetry = new SlidingWindow({ windowMs, limit });
  atRetry.keys.set('k', cloneState(state));
  const retried = atRetry.consume('k', spend, retryAt);
  assert.equal(
    retried.allowed,
    true,
    `waited ${denied.retryAfterMs}ms as instructed and was refused again ` +
      `(used ${denied.used.toFixed(2)} of ${limit}, spend ${spend})`
  );
}

function cloneState(state) {
  return {
    older: state.older ? { ...state.older } : null,
    newer: state.newer ? { ...state.newer } : null,
  };
}

test('a honoured retry delay really does admit the client when it returns', () => {
  const W = 60_000;
  // One case per shape the delay has to handle: the older bucket decayed far
  // enough to fit on its own, the older bucket is nearly gone, the newer bucket
  // must decay on its own after the roll-over, and the older bucket is empty.
  const cases = [
    { limit: 100, olderCost: 30, newerCost: 70, spend: 1, now: 60_100 },
    { limit: 100, olderCost: 20, newerCost: 80, spend: 5, now: 62_000 },
    { limit: 100, olderCost: 50, newerCost: 60, spend: 5, now: 75_000 },
    { limit: 50, olderCost: 10, newerCost: 45, spend: 5, now: 65_000 },
    { limit: 25, olderCost: 0, newerCost: 20, spend: 10, now: 20_000 },
    { limit: 200, olderCost: 60, newerCost: 150, spend: 60, now: 95_000 },
    // The newer bucket alone already exceeds the budget, so the delay can only
    // come from that bucket decaying over the window AFTER the roll-over.
    { limit: 100, olderCost: 0, newerCost: 100, spend: 10, now: 30_000 },
    { limit: 50, olderCost: 5, newerCost: 50, spend: 20, now: 90_000 },
    // Late in the window, where the older bucket has decayed but the newer one
    // is already at the limit.
    { limit: 100, olderCost: 95, newerCost: 100, spend: 1, now: 115_000 },
    { limit: 100, olderCost: 99, newerCost: 100, spend: 1, now: 119_999 },
    { limit: 40, olderCost: 30, newerCost: 40, spend: 1, now: 118_500 },
  ];
  for (const { limit, olderCost, newerCost, spend, now } of cases) {
    const index = Math.floor(now / W);
    assertRetryHonoured(
      { older: { index: index - 1, cost: olderCost }, newer: { index, cost: newerCost } },
      spend,
      now,
      limit
    );
  }
});

test('a honoured retry delay ignores buckets that have already slid out', () => {
  // state.older is a full window stale here, so weighted() must discard it and
  // charge only the live newer bucket. If the delay were derived from the
  // stale bucket instead, it would be computed from cost nobody is being
  // charged for -- and the client would be told to wait out time that was
  // already free.
  const W = 60_000;
  const limit = 100;
  const now = 150_000;
  const index = Math.floor(now / W);
  assertRetryHonoured(
    { older: { index: index - 2, cost: 90 }, newer: { index, cost: 95 } },
    10,
    now,
    limit
  );
  assertRetryHonoured(
    { older: { index: index - 2, cost: 40 }, newer: { index, cost: 99 } },
    40,
    now,
    limit
  );
});

test('the retry delay is the shortest one that works, not merely a long one', () => {
  // A delay far longer than necessary is its own defect: it stalls a legitimate
  // client for a budget that was actually available. Pin it to the true value.
  const W = 60_000;
  const limit = 100;
  const now = 60_100;
  const state = { older: { index: 0, cost: 30 }, newer: { index: 1, cost: 70 } };
  const denied = (() => {
    const probe = new SlidingWindow({ windowMs: W, limit });
    probe.keys.set('k', cloneState(state));
    return probe.consume('k', 1, now);
  })();
  assert.equal(denied.allowed, false);

  // One millisecond early must still be refused; that is what makes the delay
  // minimal rather than merely safe.
  const early = new SlidingWindow({ windowMs: W, limit });
  early.keys.set('k', cloneState(state));
  assert.equal(
    early.consume('k', 1, now + denied.retryAfterMs - 1).allowed,
    false,
    'the delay is longer than the first moment the request would fit'
  );

  const onTime = new SlidingWindow({ windowMs: W, limit });
  onTime.keys.set('k', cloneState(state));
  assert.equal(onTime.consume('k', 1, now + denied.retryAfterMs).allowed, true);
});

test('a request larger than the whole budget still reports a delay without throwing', () => {
  const w = new SlidingWindow({ windowMs: 60_000, limit: 100 });
  const r = w.consume('k', 5000, 0);
  assert.equal(r.allowed, false);
  assert.ok(r.retryAfterMs > 0, 'an impossible request must still answer with a delay');
  assert.ok(w.used('k', 0) === 0, 'a refused request must not consume budget');
});

test('the sliding window is still not burst-exploitable after the retry change', () => {
  // Guards the interaction: the new delay must not have relaxed admission.
  const w = new SlidingWindow({ windowMs: 60_000, limit: 300 });
  for (let i = 0; i < 300; i += 1) w.consume('attacker', 1, 59_999);
  let admitted = 0;
  for (let i = 0; i < 300; i += 1) {
    if (w.consume('attacker', 1, 60_000).allowed) admitted += 1;
  }
  assert.equal(admitted, 0, 'the boundary burst must still be refused');
  assert.ok(w.used('attacker', 60_000) <= 300);
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