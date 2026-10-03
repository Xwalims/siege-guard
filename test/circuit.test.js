'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { CircuitBreaker, SUCCESSES_TO_CLOSE, HALF_OPEN_PROBES } = require('../src/circuit.js');

/** A breaker with a controllable clock, so no test has to sleep. */
function makeBreaker(overrides = {}) {
  let now = 1_000_000;
  const breaker = new CircuitBreaker({
    failureRatio: 0.5,
    minSamples: 10,
    windowMs: 10_000,
    cooldownMs: 5_000,
    ...overrides,
    now: () => now,
  });
  return {
    breaker,
    advance: (ms) => {
      now += ms;
    },
    get now() {
      return now;
    },
  };
}

test('a healthy origin stays closed and allows traffic', () => {
  const { breaker } = makeBreaker();
  for (let i = 0; i < 20; i += 1) {
    assert.equal(breaker.allow().allow, true);
    breaker.onSuccess();
  }
  assert.equal(breaker.state, 'closed');
  assert.equal(breaker.stats().failures, 0);
});

test('enough failures trip the breaker open', () => {
  const { breaker } = makeBreaker();
  for (let i = 0; i < 12; i += 1) {
    breaker.allow();
    breaker.onFailure();
  }
  assert.equal(breaker.state, 'open');
});

test('an open breaker refuses without sending anything to the origin', () => {
  const { breaker } = makeBreaker();
  for (let i = 0; i < 12; i += 1) breaker.onFailure();
  const decision = breaker.allow();
  assert.equal(decision.allow, false);
  assert.equal(decision.state, 'open');
  assert.match(decision.reason, /cooldown/);
});

test('fewer failures than the ratio leaves the breaker closed', () => {
  const { breaker } = makeBreaker();
  for (let i = 0; i < 10; i += 1) breaker.onSuccess();
  for (let i = 0; i < 4; i += 1) breaker.onFailure();
  assert.equal(breaker.state, 'closed', '40% failures must not trip a 50% breaker');
  assert.ok(breaker.stats().ratio < 0.5);
});

test('too few samples is not enough to trip regardless of the ratio', () => {
  const { breaker } = makeBreaker({ minSamples: 20 });
  for (let i = 0; i < 5; i += 1) breaker.onFailure();
  assert.equal(breaker.state, 'closed', '5 failures out of a minimum of 20 samples');
  assert.ok(breaker.stats().samples < 20);
});

test('the breaker moves to half-open once the cooldown expires', () => {
  const h = makeBreaker();
  for (let i = 0; i < 12; i += 1) h.breaker.onFailure();
  assert.equal(h.breaker.state, 'open');
  h.advance(5_001);
  assert.equal(h.breaker.allow().state, 'half-open');
});

test('the cooldown is not over before it expires', () => {
  const h = makeBreaker();
  for (let i = 0; i < 12; i += 1) h.breaker.onFailure();
  h.advance(4_999);
  assert.equal(h.breaker.allow().allow, false, 'still inside the cooldown');
  h.advance(2);
  assert.equal(h.breaker.allow().allow, true, 'cooldown has passed');
});

test('the full cycle closed -> open -> half-open -> closed completes', () => {
  const h = makeBreaker();
  assert.equal(h.breaker.state, 'closed');
  for (let i = 0; i < 12; i += 1) h.breaker.onFailure();
  assert.equal(h.breaker.state, 'open');
  h.advance(5_001);
  assert.equal(h.breaker.allow().state, 'half-open');
  h.breaker.onSuccess();
  h.breaker.onSuccess();
  assert.equal(h.breaker.state, 'closed', `${SUCCESSES_TO_CLOSE} successes must close it`);
  assert.equal(h.breaker.allow().allow, true);
});

test('half-open does not let a flood through', () => {
  const h = makeBreaker();
  for (let i = 0; i < 12; i += 1) h.breaker.onFailure();
  h.advance(5_001);
  const allowed = [];
  for (let i = 0; i < HALF_OPEN_PROBES + 3; i += 1) allowed.push(h.breaker.allow().allow);
  assert.equal(allowed.filter(Boolean).length, HALF_OPEN_PROBES);
  // The origin must not be hit by a flood the instant it recovers.
  assert.ok(allowed.slice(HALF_OPEN_PROBES).every((x) => x === false));
});

test('one failure in half-open re-opens the breaker', () => {
  const h = makeBreaker();
  for (let i = 0; i < 12; i += 1) h.breaker.onFailure();
  h.advance(5_001);
  h.breaker.allow();
  h.breaker.onSuccess();
  assert.equal(h.breaker.state, 'half-open');
  h.breaker.allow();
  h.breaker.onFailure();
  assert.equal(h.breaker.state, 'open', 'a failed probe must re-open immediately');
});

test('old outcomes leave the window', () => {
  const h = makeBreaker({ windowMs: 1_000 });
  for (let i = 0; i < 10; i += 1) h.breaker.onFailure();
  assert.equal(h.breaker.stats().samples, 10);
  h.advance(5_000);
  assert.equal(h.breaker.stats().samples, 0, 'failures older than the window must be forgotten');
  // The state stays open until traffic arrives: a breaker must not recover on
  // its own, because nothing has proved the origin healthy yet. The next
  // request is what moves it to half-open.
  assert.equal(h.breaker.state, 'open', 'the state must not change without traffic');
  assert.equal(h.breaker.allow().state, 'half-open');
  h.breaker.onSuccess();
  h.breaker.onSuccess();
  assert.equal(h.breaker.state, 'closed', 'a recovered origin must close the breaker');
});

test('snapshot reports the cooldown that is left', () => {
  const h = makeBreaker({ cooldownMs: 10_000 });
  for (let i = 0; i < 12; i += 1) h.breaker.onFailure();
  h.advance(3_000);
  const snap = h.breaker.snapshot();
  assert.equal(snap.state, 'open');
  assert.equal(snap.cooldownRemainingMs, 7_000);
});

test('reset forces the breaker closed for an operator override', () => {
  const { breaker } = makeBreaker();
  for (let i = 0; i < 12; i += 1) breaker.onFailure();
  assert.equal(breaker.state, 'open');
  breaker.reset();
  assert.equal(breaker.state, 'closed');
  assert.equal(breaker.allow().allow, true);
});

test('the failure ratio is computed over the window only', () => {
  const h = makeBreaker({ windowMs: 1_000 });
  for (let i = 0; i < 6; i += 1) h.breaker.onFailure();
  h.advance(1_500);
  for (let i = 0; i < 6; i += 1) h.breaker.onSuccess();
  const stats = h.breaker.stats();
  assert.equal(stats.samples, 6);
  assert.equal(stats.failures, 0);
});