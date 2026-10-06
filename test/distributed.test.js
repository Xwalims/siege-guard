'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { InMemoryStore, RedisStore, ResilientStore, STORE_METHODS } = require('../src/store.js');
const { SiegeGuard } = require('../src/guard.js');

const BROWSER = {
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0 Safari/537.36',
  Accept: 'text/html,application/xhtml+xml',
  'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
  'Accept-Encoding': 'gzip, deflate, br',
  'Sec-Fetch-Mode': 'navigate',
  Host: 'example.com',
};

const req = (address = '198.51.100.1') => ({
  method: 'GET',
  url: '/',
  httpVersion: '1.1',
  socket: { remoteAddress: address },
  headers: { ...BROWSER },
});

// ---------------------------------------------------------------------------
// The interface every store implements
// ---------------------------------------------------------------------------

test('every store implements the documented interface', () => {
  const store = new InMemoryStore();
  for (const method of STORE_METHODS) {
    assert.equal(typeof store[method], 'function', `InMemoryStore lacks ${method}`);
  }
});

test('RedisStore refuses to exist without a client', () => {
  assert.throws(() => new RedisStore({}), /client/);
  assert.throws(() => new RedisStore(), /client/);
});

test('ResilientStore refuses to exist without a primary', () => {
  assert.throws(() => new ResilientStore({}), /primary/);
});

// ---------------------------------------------------------------------------
// The window semantics
// ---------------------------------------------------------------------------

test('a shared store enforces one budget', () => {
  const store = new InMemoryStore();
  let allowed = 0;
  for (let i = 0; i < 400; i += 1) {
    if (store.spend('k', 5, 60_000, 100, 1_000_000).allowed) allowed += 1;
  }
  assert.equal(allowed, 20, '100 budget at cost 5 is 20 requests, whatever asks');
});

test('a shared store cannot be burst-exploited at the boundary', () => {
  const store = new InMemoryStore();
  let admitted = 0;
  for (let i = 0; i < 300; i += 1) {
    if (store.spend('k', 1, 60_000, 300, 59_999).allowed) admitted += 1;
  }
  assert.equal(admitted, 300);
  // A fixed window would admit another 300 here.
  assert.equal(store.spend('k', 1, 60_000, 300, 60_000).allowed, false);
});

test('a shared store reports when to retry', () => {
  const store = new InMemoryStore();
  for (let i = 0; i < 20; i += 1) store.spend('k', 5, 60_000, 100, 1_000_000);
  const denied = store.spend('k', 5, 60_000, 100, 1_000_000);
  assert.equal(denied.allowed, false);
  assert.ok(denied.retryAfterMs > 0 && denied.retryAfterMs <= 60_000, `got ${denied.retryAfterMs}`);
});

test('a shared store ages entries out of the window', () => {
  const store = new InMemoryStore();
  for (let i = 0; i < 20; i += 1) store.spend('k', 5, 60_000, 100, 1_000_000);
  assert.equal(store.spend('k', 5, 60_000, 100, 1_000_000).allowed, false);
  // Move past the window entirely.
  assert.equal(store.spend('k', 5, 60_000, 100, 1_100_000).allowed, true);
});

test('a shared store isolates identities', () => {
  const store = new InMemoryStore();
  for (let i = 0; i < 20; i += 1) store.spend('a', 5, 60_000, 100, 1_000_000);
  assert.equal(store.spend('a', 5, 60_000, 100, 1_000_000).allowed, false);
  assert.equal(store.spend('b', 5, 60_000, 100, 1_000_000).allowed, true);
});

test('peek reports the current spend without changing it', () => {
  const store = new InMemoryStore();
  for (let i = 0; i < 4; i += 1) store.spend('k', 5, 60_000, 100, 1_000_000);
  assert.equal(store.peek('k', 60_000, 1_000_000).used, 20);
  assert.equal(store.peek('k', 60_000, 1_000_000).used, 20, 'peek must be side-effect free');
  assert.equal(store.peek('unknown', 60_000, 1_000_000).used, 0);
});

test('reset clears one identity', () => {
  const store = new InMemoryStore();
  store.spend('k', 5, 60_000, 100, 1_000_000);
  assert.equal(store.reset('k'), true);
  assert.equal(store.reset('k'), false);
  assert.equal(store.peek('k', 60_000, 1_000_000).used, 0);
});

test('sweep removes idle keys and keeps active ones', () => {
  const store = new InMemoryStore();
  store.spend('stale', 5, 60_000, 100, 1_000_000);
  store.spend('fresh', 5, 60_000, 100, 1_100_000);
  const removed = store.sweep(1_100_000, 60_000);
  assert.equal(removed, 1);
  assert.equal(store.windows.has('stale'), false);
  assert.equal(store.windows.has('fresh'), true);
});

// ---------------------------------------------------------------------------
// The bug this module exists to fix
// ---------------------------------------------------------------------------

test('four in-process guards give an attacker four budgets', () => {
  // This is the failure being fixed. It is asserted rather than avoided, so the
  // reason src/store.js exists cannot be quietly forgotten.
  const guards = [0, 1, 2, 3].map(() => new SiegeGuard({ now: () => 1_000_000, limit: 100 }));
  let allowed = 0;
  for (let i = 0; i < 400; i += 1) {
    if (guards[i % 4].check(req()).action === 'allow') allowed += 1;
  }
  assert.equal(allowed, 80, 'four instances at a limit of 100 serve four times as much');
});

test('four guards sharing a store give an attacker one budget', async () => {
  const shared = new InMemoryStore();
  const guards = [0, 1, 2, 3].map(
    () => new SiegeGuard({ now: () => 1_000_000, limit: 100, store: shared })
  );
  let allowed = 0;
  for (let i = 0; i < 400; i += 1) {
    const decision = await guards[i % 4].checkAsync(req());
    if (decision.action === 'allow') allowed += 1;
  }
  assert.equal(allowed, 20, 'a shared store serves exactly what one instance would');
});

test('concurrent spends on a shared store cannot oversubscribe', async () => {
  // The whole point of doing the arithmetic server side: four instances asking
  // at the same instant must not each find room for one more request.
  const shared = new InMemoryStore();
  const guards = [0, 1, 2, 3].map(
    () => new SiegeGuard({ now: () => 1_000_000, limit: 40, store: shared })
  );
  const decisions = await Promise.all(
    Array.from({ length: 40 }, (_, i) => guards[i % 4].checkAsync(req()))
  );
  const allowed = decisions.filter((d) => d.action === 'allow').length;
  assert.equal(allowed, 8, `40 budget at cost 5 is 8 requests, got ${allowed}`);
});

test('a guard with a shared store refuses the synchronous path', () => {
  const guard = new SiegeGuard({ now: () => 1_000_000, store: new InMemoryStore() });
  assert.throws(() => guard.check(req()), /checkAsync/);
});

test('checkAsync without a shared store is a clear error', async () => {
  const guard = new SiegeGuard({ now: () => 1_000_000 });
  await assert.rejects(() => guard.checkAsync(req()), /checkAsync needs a shared store/);
});

test('the cost ceiling is enforced on the shared-store path too', async () => {
  // check() refused an over-ceiling request at step 4, before any budget work.
  // checkAsync() had no equivalent and simply allowed it, so the one shape an
  // operator actually deploys -- a process with a shared Redis budget -- accepted
  // unbounded-cost requests that the in-process path rejected. Same policy, same
  // request, opposite answers.
  //
  // `costs` is a per-class table, not a callable, so the ceiling is crossed by
  // pricing an API read at 100 against a ceiling of 10.
  const ceiling = {
    now: () => 1_000_000,
    limit: 1_000_000,
    maxCostPerRequest: 10,
    costs: { apiRead: 100 },
  };
  const expensive = { ...req(), url: '/api/thing' };

  const single = new SiegeGuard(ceiling);
  assert.equal(single.inspect(expensive).cost.cost, 100, 'sanity: the request is priced over the ceiling');
  const local = single.check(expensive);
  assert.equal(local.action, 'block', 'in-process path must refuse an over-ceiling request');
  assert.deepEqual(local.bases, ['cost-ceiling']);

  const shared = new SiegeGuard({ ...ceiling, store: new InMemoryStore() });
  const distributed = await shared.checkAsync(expensive);
  assert.equal(distributed.action, 'block', 'shared-store path must refuse it identically');
  assert.equal(distributed.status, 403);
  assert.deepEqual(distributed.bases, ['cost-ceiling']);
});

test('an over-ceiling request costs the identity nothing', async () => {
  // The ceiling is refused before budget work, so it must not spend the budget
  // of whoever sent it -- otherwise one over-priced request could lock an honest
  // client out by exhausting a budget it was never allowed to draw on.
  const store = new InMemoryStore();
  const guard = new SiegeGuard({
    now: () => 1_000_000,
    limit: 1_000_000,
    maxCostPerRequest: 10,
    costs: { apiRead: 100 },
    store,
  });
  for (let i = 0; i < 5; i += 1) {
    const decision = await guard.checkAsync({ ...req(), url: '/api/thing' });
    assert.equal(decision.action, 'block');
  }
  assert.equal((await store.peek(identityKeyFor('198.51.100.1'), 60_000, 1_000_000)).used, 0);
});

test('check() and checkAsync() apply the same decision steps in the same order', () => {
  // The two bodies are near-copies by design, which is exactly why a step can
  // quietly exist in one and not the other: the cost ceiling was enforced by
  // check() only, so a shared-store deployment allowed what an in-process one
  // refused. The steps are listed here rather than derived from the source, so
  // a new step has to be added to both lists deliberately and the diff stays
  // reviewable. Order is asserted too, because "circuit after the ceiling"
  // changes what an operator sees during an origin outage.
  const steps = [
    'details.circuit.allow',            // 1. origin is failing
    'details.blockedUntil > now',       // 2. a previous excess earned a block
    'judge({',                          // 3. combine signals, never convict on one
    'maxCostPerRequest > 0',            // 4. the operator's cost ceiling
    '!budget.allowed',                  // 5. the budget was actually exceeded
    "verdict.verdict === 'challenge'",  // 6. ask for proof, affordably
    'options.blockOnScan',              // 7. an operator may make a scan fatal
  ];

  const source = require('node:fs').readFileSync(require.resolve('../src/guard.js'), 'utf8');
  const sync = sliceBody(source, '  check(req, options = {}) {', '\n  async checkAsync');
  const async_ = sliceBody(source, '  async checkAsync(req, options = {}) {', '\n  /**\n   * Record an excess');

  const positions = (body) =>
    steps.map((token) => body.indexOf(token));

  const a = positions(sync);
  const b = positions(async_);
  for (let i = 0; i < steps.length; i += 1) {
    assert.notEqual(a[i], -1, `check() is missing step ${i + 1}: ${steps[i]}`);
    assert.notEqual(b[i], -1, `checkAsync() is missing step ${i + 1}: ${steps[i]}`);
  }
  assert.deepEqual(a, [...a].sort((x, y) => x - y), 'check() applies the steps out of order');
  assert.deepEqual(b, [...b].sort((x, y) => x - y), 'checkAsync() applies the steps out of order');

  // Every block basis the guard can emit must be reachable on both paths, or a
  // 403 that one path can produce is a 403 the other cannot explain.
  const bases = [...new Set([...sync.matchAll(/BLOCK_BASES\.(\w+)/g)].map((m) => m[1]))].sort();
  const sharedBases = [...new Set([...async_.matchAll(/BLOCK_BASES\.(\w+)/g)].map((m) => m[1]))].sort();
  assert.deepEqual(sharedBases, bases, 'the two paths can emit different block bases');
});

function sliceBody(source, start, end) {
  const from = source.indexOf(start);
  assert.notEqual(from, -1, `could not find ${start.trim()}`);
  const to = source.indexOf(end, from + start.length);
  assert.notEqual(to, -1, `could not find the end of ${start.trim()}`);
  return source.slice(from, to);
}

// The identity key the guard derives from a socket address, without reaching into
// guard internals: if this drifts, the assertion above stops testing anything.
function identityKeyFor(address) {
  const { identityOf } = require('../src/identity.js');
  return identityOf(address, {}).normalized;
}

test('the report says whether the budget is shared', () => {
  const local = new SiegeGuard({ now: () => 1_000_000 });
  assert.equal(local.report().budgetScope, 'in-process');
  const shared = new SiegeGuard({ now: () => 1_000_000, store: new InMemoryStore() });
  assert.equal(shared.report().budgetScope, 'shared');
  assert.equal(shared.report().instances, null);
});

test('sweep reaches the shared store and returns a promise for it', async () => {
  const guard = new SiegeGuard({ now: () => 1_000_000, store: new InMemoryStore() });
  const removed = guard.sweep();
  assert.ok(removed.store instanceof Promise, 'a shared sweep must be awaitable');
  assert.equal(typeof (await removed.store), 'number');
});

test('a local sweep has no store field to await', () => {
  const guard = new SiegeGuard({ now: () => 1_000_000 });
  const removed = guard.sweep();
  assert.equal(removed.store, null);
});

// ---------------------------------------------------------------------------
// Degradation
// ---------------------------------------------------------------------------

test('a failing primary falls back to memory and says so', async () => {
  const failing = {
    async spend() {
      throw new Error('ECONNREFUSED 127.0.0.1:6379');
    },
    async peek() {
      throw new Error('ECONNREFUSED');
    },
    async reset() {
      throw new Error('x');
    },
    async sweep() {
      throw new Error('x');
    },
  };
  const store = new ResilientStore({ primary: failing, now: () => 1000 });
  const result = await store.spend('k', 5, 60_000, 100, 1000);
  assert.equal(result.backend, 'memory-fallback');
  assert.equal(result.degraded, true, 'degradation must be visible, not silent');
  assert.match(result.error, /ECONNREFUSED/);
  assert.equal(store.degraded, true);
});

test('the fallback still enforces a limit, so the site stays up and guarded', async () => {
  const failing = {
    async spend() {
      throw new Error('down');
    },
    async peek() {
      throw new Error('down');
    },
    async reset() {
      throw new Error('down');
    },
    async sweep() {
      throw new Error('down');
    },
  };
  const store = new ResilientStore({ primary: failing, now: () => 1000 });
  let allowed = 0;
  for (let i = 0; i < 100; i += 1) {
    const r = await store.spend('k', 5, 60_000, 100, 1000);
    if (r.allowed) allowed += 1;
  }
  assert.equal(allowed, 20, 'the local fallback must still stop the flood');
});

test('the primary is retried after the cooldown', async () => {
  let fail = true;
  const flaky = {
    async spend() {
      if (fail) throw new Error('down');
      return { allowed: true, used: 5, retryAfterMs: 0, backend: 'redis' };
    },
    async peek() {
      return { used: 0, backend: 'redis' };
    },
    async reset() {
      return true;
    },
    async sweep() {
      return 0;
    },
  };
  let now = 1000;
  const store = new ResilientStore({ primary: flaky, now: () => now, retryAfterMs: 5000 });
  assert.equal((await store.spend('k', 5, 100, 100, now)).backend, 'memory-fallback');
  fail = false;
  now += 6000;
  assert.equal(
    (await store.spend('k', 5, 100, 100, now)).backend,
    'redis',
    'the shared backend must be retried after the cooldown'
  );
});

test('a healthy primary is used directly', async () => {
  const healthy = new InMemoryStore();
  const store = new ResilientStore({ primary: healthy, now: () => 1000 });
  const result = await store.spend('k', 5, 100, 100, 1000);
  assert.equal(result.backend, 'memory');
  assert.equal(store.degraded, false);
});

// ---------------------------------------------------------------------------
// The Redis script
// ---------------------------------------------------------------------------

test('the Redis script is a single atomic unit', () => {
  const store = new RedisStore({ client: {} });
  const script = store.SPEND_SCRIPT;
  assert.match(script, /ZREMRANGEBYSCORE/, 'the window must be trimmed server side');
  assert.match(script, /used \+ cost > limit/, 'the budget test happens server side');
  assert.ok(
    script.indexOf('used + cost > limit') < script.indexOf('ZADD'),
    'the check must come before the write, in one script, or the gate is racy'
  );
});

test('the Redis store never blocks the server with KEYS', () => {
  const store = new RedisStore({ client: {} });
  assert.match(store.sweep.toString(), /scan/);
  assert.ok(!/client\.keys\(/.test(store.sweep.toString()));
});

test('the Redis store namespacing keeps identities apart', () => {
  const a = new RedisStore({ client: {}, prefix: 'sgw' });
  const b = new RedisStore({ client: {}, prefix: 'other' });
  assert.notEqual(a.keyFor('x'), b.keyFor('x'));
  assert.equal(a.keyFor('1.2.3.4'), 'sgw:1.2.3.4');
});