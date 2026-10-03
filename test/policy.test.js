'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { judge, mayBlock, BLOCK_BASES, CHALLENGE_BASES, DEFAULT_PRICE_MULTIPLIER } = require('../src/policy.js');
const { fingerprint, browserRequest, scannerRequest } = require('../src/signals.js');
const { PathEntropyTracker } = require('../src/entropy.js');

const OPTIONS = {
  limit: 1000,
  challengeScore: 0.35,
  blockScore: 0.6,
  strikesToBlock: 3,
  maxCostPerRequest: 0,
  blockOnScan: false,
};

/** A print that scores as high as this package can produce. */
const worstCase = () => fingerprint({ headers: { Host: 'example.com' } });

// ---------------------------------------------------------------------------
// The central invariant
// ---------------------------------------------------------------------------

test('the highest possible fingerprint score cannot produce a block', () => {
  // Six forged headers, a perfect 0.77 score, and a budget that is nowhere near
  // exhausted. The verdict must not be a block, because nothing here is evidence.
  const result = judge({
    fingerprint: worstCase(),
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 0, limit: 1000 },
    cost: 5,
    strikes: 0,
    options: OPTIONS,
  });
  assert.equal(result.blockBases.length, 0, `block bases: ${JSON.stringify(result.blockBases)}`);
  assert.equal(result.verdict, 'challenge');
});

test('a fingerprint of 1.0 still cannot block', () => {
  const maxed = { score: 1, keys: Object.keys(worstCase().signals), signals: worstCase().signals, reason: 'all' };
  const result = judge({
    fingerprint: maxed,
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 1, limit: 1000 },
    cost: 5,
    strikes: 0,
    options: OPTIONS,
  });
  assert.equal(result.blockBases.length, 0);
  assert.ok(!result.blockBases.includes('fingerprint'));
});

test('fingerprint is never a block basis, whatever the score', () => {
  for (const score of [0, 0.34, 0.35, 0.6, 0.9, 1]) {
    const result = judge({
      fingerprint: { score, signals: {}, keys: [], reason: 'test' },
      entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
      budget: { used: 0, limit: 1000 },
      cost: 5,
      strikes: 0,
      options: OPTIONS,
    });
    assert.ok(
      !result.blockBases.includes('fingerprint'),
      `score ${score} produced a fingerprint block basis`
    );
  }
});

test('mayBlock rejects a fingerprint-only basis and accepts the real ones', () => {
  assert.equal(mayBlock(['fingerprint']), false);
  assert.equal(mayBlock(['high-novelty']), false);
  assert.equal(mayBlock([BLOCK_BASES.BUDGET]), true);
  assert.equal(mayBlock([BLOCK_BASES.CIRCUIT]), true);
  assert.equal(mayBlock([BLOCK_BASES.CEILING]), true);
  assert.equal(mayBlock([]), false);
});

// ---------------------------------------------------------------------------
// What independent evidence actually earns
// ---------------------------------------------------------------------------

test('an exhausted budget is a block basis', () => {
  const result = judge({
    fingerprint: { score: 0, signals: {}, keys: [], reason: 'clean' },
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 1000, limit: 1000 },
    cost: 50,
    strikes: 0,
    options: OPTIONS,
  });
  assert.ok(result.blockBases.includes(BLOCK_BASES.BUDGET));
  assert.equal(result.verdict, 'block');
});

test('enough strikes is a block basis on its own', () => {
  const result = judge({
    fingerprint: { score: 0, signals: {}, keys: [], reason: 'clean' },
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 100, limit: 1000 },
    cost: 5,
    strikes: 3,
    options: OPTIONS,
  });
  assert.ok(result.blockBases.includes(BLOCK_BASES.BUDGET));
});

test('a cost above the ceiling is a block basis', () => {
  const result = judge({
    fingerprint: { score: 0, signals: {}, keys: [], reason: 'clean' },
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 0, limit: 1000 },
    cost: 500,
    strikes: 0,
    options: { ...OPTIONS, maxCostPerRequest: 100 },
  });
  assert.ok(result.blockBases.includes(BLOCK_BASES.CEILING));
  assert.equal(result.verdict, 'block');
});

test('a clean request is allowed with no bases at all', () => {
  const result = judge({
    fingerprint: fingerprint(browserRequest()),
    entropy: { isScan: false, samples: 3, entropy: 1.0, novelty: 0.1 },
    budget: { used: 10, limit: 1000 },
    cost: 5,
    strikes: 0,
    options: OPTIONS,
  });
  assert.equal(result.verdict, 'allow');
  assert.deepEqual(result.blockBases, []);
  assert.deepEqual(result.challengeBases, []);
  assert.equal(result.priceMultiplier, 1);
});

// ---------------------------------------------------------------------------
// Suspicion buys a challenge and a surcharge, nothing more
// ---------------------------------------------------------------------------

test('a score above challengeScore earns a challenge', () => {
  const result = judge({
    fingerprint: worstCase(),
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 0, limit: 1000 },
    cost: 5,
    strikes: 0,
    options: OPTIONS,
  });
  assert.ok(result.challengeBases.includes(CHALLENGE_BASES.FINGERPRINT));
  assert.equal(result.verdict, 'challenge');
});

test('a scan verdict earns a challenge, not a ban, by default', () => {
  const result = judge({
    fingerprint: fingerprint(browserRequest()),
    entropy: { isScan: true, samples: 16, entropy: 4.0, novelty: 1.0 },
    budget: { used: 0, limit: 1000 },
    cost: 5,
    strikes: 0,
    options: OPTIONS,
  });
  assert.ok(result.challengeBases.includes(CHALLENGE_BASES.NOVELTY));
  assert.equal(result.verdict, 'challenge');
  assert.equal(result.blockBases.length, 0, 'entropy alone must not block while blockOnScan is off');
});

test('blockOnScan makes an entropy verdict fatal, as an explicit opt-in', () => {
  const result = judge({
    fingerprint: fingerprint(browserRequest()),
    entropy: { isScan: true, samples: 16, entropy: 4.0, novelty: 1.0 },
    budget: { used: 0, limit: 1000 },
    cost: 5,
    strikes: 0,
    options: { ...OPTIONS, blockOnScan: true },
  });
  assert.ok(result.blockBases.includes(BLOCK_BASES.SCAN));
  assert.equal(result.verdict, 'block');
});

test('suspicion raises the price of a request', () => {
  const cheap = judge({
    fingerprint: fingerprint(browserRequest()),
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 0, limit: 1000 },
    cost: 5, strikes: 0, options: OPTIONS,
  });
  const suspicious = judge({
    fingerprint: { score: 0.4, signals: {}, keys: [], reason: 'x' },
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 0, limit: 1000 },
    cost: 5, strikes: 0, options: OPTIONS,
  });
  const verySuspicious = judge({
    fingerprint: worstCase(),
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 0, limit: 1000 },
    cost: 5, strikes: 0, options: OPTIONS,
  });
  assert.equal(cheap.priceMultiplier, DEFAULT_PRICE_MULTIPLIER.none);
  assert.equal(suspicious.priceMultiplier, DEFAULT_PRICE_MULTIPLIER.suspicious);
  assert.equal(verySuspicious.priceMultiplier, DEFAULT_PRICE_MULTIPLIER.verySuspicious);
  assert.ok(verySuspicious.priceMultiplier > suspicious.priceMultiplier);
});

test('a price multiplier alone never blocks', () => {
  const result = judge({
    fingerprint: worstCase(),
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 999, limit: 1000 },
    cost: 5, strikes: 0, options: OPTIONS,
  });
  assert.equal(result.blockBases.length, 0);
});

test('the evidence string says why a fingerprint is not enough', () => {
  const result = judge({
    fingerprint: worstCase(),
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 0, limit: 1000 },
    cost: 5, strikes: 0, options: OPTIONS,
  });
  assert.match(result.evidence, /alone is not evidence/);
});

test('judge handles a request with no entropy history', () => {
  const result = judge({
    fingerprint: fingerprint(scannerRequest()),
    entropy: undefined,
    budget: { used: 0, limit: 1000 },
    cost: 1, strikes: 0, options: OPTIONS,
  });
  assert.ok(result.verdict);
  assert.ok(Array.isArray(result.blockBases));
});

test('a guard without options still returns a sane verdict', () => {
  const result = judge({
    fingerprint: worstCase(),
    entropy: { isScan: false, samples: 0, entropy: 0, novelty: 0 },
    budget: { used: 0, limit: 0 },
    cost: 5, strikes: 0,
  });
  assert.equal(result.blockBases.length, 0, 'a zero limit must not synthesise a block');
});