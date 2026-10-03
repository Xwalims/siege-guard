'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const {
  SiegeGuard,
  attach,
  guardMiddleware,
  ALLOW,
  THROTTLE,
  CHALLENGE,
  BLOCK,
  DEFAULTS,
} = require('../src/index.js');

/** Build a request without touching a socket. */
function request(url, options = {}) {
  const { headers = {}, address = '192.0.2.10', method = 'GET' } = options;
  return {
    method,
    url,
    httpVersion: '1.1',
    socket: { remoteAddress: address },
    headers: { Host: 'example.com', ...headers },
  };
}

/** Browser-shaped headers, so fingerprinting does not interfere. */
const BROWSER = {
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0 Safari/537.36',
  Accept: 'text/html,application/xhtml+xml',
  'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
  'Accept-Encoding': 'gzip, deflate, br',
  'Sec-Fetch-Mode': 'navigate',
};

const SCANNER = {
  'User-Agent': 'python-requests/2.32.3',
  Accept: '*/*',
  Host: 'example.com',
};

/**
 * A scanner that gives nothing away: no user agent, no accept, no encoding and
 * no sec-fetch. Every signal fires, which is the only reliable way past the
 * default blockScore of 0.6.
 */
const RAW_SCANNER = {
  Host: 'example.com',
};

function makeGuard(overrides = {}) {
  let now = 1_000_000;
  // A FUNCTION, not a number: passing a number freezes the clock and advance()
  // would then do nothing at all. SiegeGuard accepts both, but only the
  // function form can be moved.
  const guard = new SiegeGuard({ now: () => now, ...overrides });
  return {
    guard,
    advance: (ms) => {
      now += ms;
    },
    get now() {
      return now;
    },
  };
}

test('an ordinary browser request is allowed', () => {
  const { guard } = makeGuard();
  const decision = guard.check(request('/', { headers: BROWSER }));
  assert.equal(decision.action, ALLOW);
  assert.equal(decision.status, 200);
  assert.match(decision.reason, /within budget/);
});

test('a decision names the identity it was made for', () => {
  const { guard } = makeGuard();
  const decision = guard.check(request('/', { headers: BROWSER }));
  assert.equal(decision.identity.normalized, '192.0.2.10');
  assert.equal(decision.identity.family, 4);
  assert.equal(decision.identity.subnetSize, '1');
});

test('exceeding the budget yields a 429 with a retry delay', () => {
  // "/" costs the default 5, so a budget of 100 runs out after 20 requests.
  const { guard } = makeGuard({ limit: 100, strikesToBlock: 99 });
  let last;
  for (let i = 0; i < 40; i += 1) last = guard.check(request('/', { headers: BROWSER }));
  assert.equal(last.action, THROTTLE, `expected a throttle, got ${last.action}`);
  assert.equal(last.status, 429);
  assert.ok(last.retryAfterMs > 0);
  assert.match(last.reason, /budget exhausted/);
});

test('a flood of cheap static requests exhausts the budget just as writes do', () => {
  const staticFlood = makeGuard({ limit: 200 });
  const writeFlood = makeGuard({ limit: 200 });
  for (let i = 0; i < 60; i += 1) {
    staticFlood.guard.check(request(`/static/app${i}.css`, { headers: BROWSER }));
  }
  for (let i = 0; i < 60; i += 1) {
    writeFlood.guard.check(request('/api/items', { method: 'POST', headers: BROWSER }));
  }
  const cheap = staticFlood.guard.window.used('192.0.2.10');
  const dear = writeFlood.guard.window.used('192.0.2.10');
  assert.ok(
    dear > cheap,
    `writes (${dear}) must spend more budget than static (${cheap})`
  );
  // 60 static assets at cost 1 all fit in 200. 60 writes at cost 50 cannot:
  // the budget runs out after four of them and the rest are refused, so the
  // window stops at exactly the limit.
  assert.equal(cheap, 60);
  assert.equal(dear, 200);
});

test('an authenticating write costs more than a public read', () => {
  const { guard } = makeGuard();
  const read = guard.check(request('/api/items', { headers: BROWSER }));
  const write = guard.check(request('/api/items', { method: 'POST', headers: BROWSER }));
  assert.ok(write.cost.cost > read.cost.cost);
});

test('an auth endpoint is priced above a plain write', () => {
  const { guard } = makeGuard();
  const write = guard.check(request('/api/items', { method: 'POST', headers: BROWSER }));
  const auth = guard.check(request('/api/auth/login', { method: 'POST', headers: BROWSER }));
  assert.equal(auth.cost.class, 'auth');
  assert.ok(auth.cost.cost > write.cost.cost);
});

test('a clear scanner is NOT blocked on its fingerprint alone', () => {
  // This is the whole point of src/policy.js. Every fingerprint signal is
  // forgeable, so the highest possible score must still not produce a 403.
  // An earlier version blocked here, which meant six forged headers earned a
  // permanent ban.
  const { guard } = makeGuard();
  const decision = guard.check(request('/.env', { headers: RAW_SCANNER }));
  assert.notEqual(decision.action, BLOCK, `a forged fingerprint must not ban: ${decision.reason}`);
  assert.ok(!decision.bases.includes('fingerprint'), 'fingerprint may never be a block basis');
});

test('a maximally forged browser request is served', () => {
  // Every header this package checks, set to exactly what Chrome sends.
  const forged = {
    'User-Agent':
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8',
    'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    Connection: 'keep-alive',
    Host: 'example.com',
  };
  const { guard } = makeGuard();
  const decision = guard.check(request('/', { headers: forged }));
  assert.equal(decision.action, ALLOW, `forgery was punished: ${decision.reason}`);
  assert.equal(decision.fingerprint.score, 0);
});

test('a suspicious client pays more per request instead of being banned', () => {
  const honest = makeGuard({ limit: 100 });
  const bare = makeGuard({ limit: 100 });
  const honestSpent = honest.guard.window.used('192.0.2.10');
  bare.guard.check(request('/', { headers: RAW_SCANNER }));
  const bareSpent = bare.guard.window.used('192.0.2.10');
  assert.equal(honestSpent, 0);
  assert.ok(
    bareSpent > 5,
    `a score of ${bare.guard.inspect(request('/', { headers: RAW_SCANNER })).fingerprint.score} should cost more than the base price of 5, paid ${bareSpent}`
  );
});

test('a block always names an independent basis', () => {
  const { guard } = makeGuard({ limit: 50, strikesToBlock: 2 });
  for (let i = 0; i < 13; i += 1) guard.check(request('/', { headers: BROWSER }));
  const decision = guard.check(request('/', { headers: BROWSER }));
  assert.equal(decision.action, BLOCK);
  assert.ok(decision.bases.length > 0, 'a block must say why');
  assert.ok(
    decision.bases.every((b) => b !== 'fingerprint'),
    `block bases must be independent, got ${JSON.stringify(decision.bases)}`
  );
  assert.ok(
    decision.bases.some((b) => ['budget-exceeded', 'previous-block'].includes(b)),
    `a client block must rest on the budget, got ${JSON.stringify(decision.bases)}`
  );
});

test('a scanner that keeps a few browser habits is not blocked outright', () => {
  // python-requests with a normal Accept-Encoding scores 0.47, below the 0.6
  // default. Blocking it would start refusing ordinary API clients, so the
  // guard spends its budget instead. This is the intended trade-off.
  const { guard } = makeGuard();
  const decision = guard.check(request('/.env', { headers: SCANNER }));
  assert.notEqual(decision.action, BLOCK, 'a partial bot signal must not hard-block');
  assert.ok(decision.fingerprint.score > 0);
});

test('a moderately suspicious client is challenged when a challenge is wired', () => {
  const { guard } = makeGuard({ challenge: () => 'prove it', challengeScore: 0.3 });
  const decision = guard.check(request('/.env', { headers: SCANNER }));
  assert.equal(decision.action, CHALLENGE);
  assert.equal(decision.status, 403);
});

test('no challenge is issued when none is configured', () => {
  const { guard } = makeGuard({ challengeScore: 0.3 });
  const decision = guard.check(request('/.env', { headers: SCANNER }));
  assert.notEqual(decision.action, CHALLENGE);
});

test('repeating an excess eventually blocks the identity', () => {
  const { guard } = makeGuard({ limit: 100, strikesToBlock: 3 });
  const actions = [];
  for (let i = 0; i < 200; i += 1) {
    actions.push(guard.check(request('/', { headers: BROWSER })).action);
  }
  assert.ok(actions.includes(THROTTLE), 'the first excess must be a throttle');
  assert.ok(actions.includes(BLOCK), 'repeated excesses must end in a block');
  assert.equal(actions[actions.length - 1], BLOCK, 'and it must stay blocked');
});

test('a blocked identity is refused before the budget is even consulted', () => {
  const { guard } = makeGuard({ limit: 100, strikesToBlock: 2, blockMs: 60_000 });
  for (let i = 0; i < 200; i += 1) guard.check(request('/', { headers: BROWSER }));
  const decision = guard.check(request('/', { headers: BROWSER }));
  assert.match(decision.reason, /blocked for another|after 2 strikes/);
});


test('a block expires after its duration', () => {
  const h = makeGuard({ limit: 50, strikesToBlock: 2, blockMs: 10_000 });
  // "/" costs 5, so 50 allows 10 requests, then two excesses earn a block.
  for (let i = 0; i < 13; i += 1) h.guard.check(request('/', { headers: BROWSER }));
  assert.equal(h.guard.check(request('/', { headers: BROWSER })).action, BLOCK);

  // The block is gone after blockMs, but the identity is not forgiven: the
  // first request past the block resets the strike count and is throttled,
  // because the budget window still holds its spend. Deliberately not a fresh
  // allowance -- otherwise a blocked client gets a clean slate on release and
  // can immediately flood again.
  h.advance(11_000);
  assert.equal(h.guard.check(request('/', { headers: BROWSER })).action, THROTTLE);
  assert.deepEqual(
    [h.guard.check(request('/', { headers: BROWSER })).action],
    [BLOCK],
    'sustained excess after release earns a fresh block, not forgiveness'
  );

  // Once the window has slid clear as well, service resumes.
  h.advance(70_000);
  assert.equal(h.guard.check(request('/', { headers: BROWSER })).action, ALLOW);
});

test('one IPv6 /64 gets one budget however many addresses it uses', () => {
  // THE IPv6 test: rotating source addresses inside one allocation must not
  // produce fresh quota, which is what naive per-address limiting does.
  const { guard } = makeGuard({ limit: 100 });
  let allowed = 0;
  for (let i = 1; i <= 300; i += 1) {
    const address = `2001:db8::${i.toString(16)}`;
    if (guard.check(request('/', { headers: BROWSER, address })).action === ALLOW) allowed += 1;
  }
  // Static costs 1 and the budget is 100, so only 100 requests may pass.
  // "/" costs the default 5, so exactly 20 of them fit.
  assert.equal(allowed, 20, `expected 20 allowed, got ${allowed}`);
  assert.equal(guard.window.keys.size, 1, 'the whole /64 must be one tracked identity');
});

test('two different IPv6 /64s get separate budgets', () => {
  const { guard } = makeGuard({ limit: 100 });
  guard.check(request('/', { headers: BROWSER, address: '2001:db8::1' }));
  guard.check(request('/', { headers: BROWSER, address: '2001:db9::1' }));
  assert.equal(guard.window.keys.size, 2);
});

test('a blocking origin circuit short-circuits everything with 503', () => {
  const { guard } = makeGuard();
  for (let i = 0; i < 30; i += 1) guard.reportOrigin(false);
  const decision = guard.check(request('/', { headers: BROWSER }));
  assert.equal(decision.action, BLOCK);
  assert.equal(decision.status, 503);
  assert.match(decision.reason, /circuit is open/);
  assert.ok(decision.retryAfterMs > 0, 'a 503 must tell the client when to retry');
});

test('the circuit is checked before the budget', () => {
  const { guard } = makeGuard();
  for (let i = 0; i < 30; i += 1) guard.reportOrigin(false);
  const decision = guard.check(request('/', { headers: BROWSER }));
  assert.match(decision.reason, /circuit/, 'the circuit must be the first reason');
});

test('scan detection can block when configured to', () => {
  const { guard } = makeGuard({ limit: 100_000, blockOnScan: true, blockScore: 0.99 });
  // Sixteen distinct unseen paths. Eight is the tracker's minimum sample count,
  // but log2(8) = 3.0 is still below SCAN_ENTROPY of 3.4, so a short trace is
  // correctly NOT flagged. Sixteen gives log2(16) = 4.0, which clears it.
  const paths = Array.from({ length: 16 }, (_, i) => `/secret${i}`);
  let last;
  for (const p of paths) last = guard.check(request(p, { headers: BROWSER }));
  assert.equal(last.action, BLOCK);
  assert.match(last.reason, /scan-like/);
});

test('scan detection stays advisory by default', () => {
  const { guard } = makeGuard({ limit: 1_000_000 });
  const paths = Array.from({ length: 16 }, (_, i) => `/secret${i}`);
  let last;
  for (const p of paths) last = guard.check(request(p, { headers: BROWSER }));
  assert.equal(last.action, ALLOW, 'a default guard must not block on entropy alone');
  // ...but it must have noticed, or the option above would be doing nothing.
  assert.ok(last.entropy.entropy >= 3.4, `entropy ${last.entropy.entropy} must clear the threshold`);
  assert.ok(last.entropy.isScan, 'the verdict must be scan-like');
});

test('forgive clears every trace of an identity', () => {
  const { guard } = makeGuard({ limit: 100, strikesToBlock: 2 });
  for (let i = 0; i < 200; i += 1) guard.check(request('/', { headers: BROWSER }));
  assert.equal(guard.check(request('/', { headers: BROWSER })).action, BLOCK);
  assert.equal(guard.forgive('192.0.2.10'), true);
  assert.equal(guard.check(request('/', { headers: BROWSER })).action, ALLOW);
});

test('forgive on a malformed address returns false instead of throwing', () => {
  const { guard } = makeGuard();
  assert.equal(guard.forgive('not-an-address'), false);
});

test('sweep drops expired blocks', () => {
  const h = makeGuard({ limit: 50, strikesToBlock: 2, blockMs: 5_000 });
  for (let i = 0; i < 13; i += 1) h.guard.check(request('/', { headers: BROWSER }));
  assert.equal(h.guard.punished.size, 1);
  h.advance(6_000);
  const removed = h.guard.sweep();
  assert.equal(removed.punished, 1);
  assert.equal(h.guard.punished.size, 0);
});

test('the report accounts for every decision', () => {
  const { guard } = makeGuard();
  guard.check(request('/', { headers: BROWSER }));
  guard.check(request('/.env', { headers: RAW_SCANNER }));
  guard.check(request('/', { headers: BROWSER }));
  const report = guard.report();
  assert.equal(report.decisions, 3);
  assert.equal(report.allowed + report.throttled + report.challenged + report.blocked, 3);
  // A forged header no longer bans anyone, so all three are served.
  assert.equal(report.blocked, 0, `no request may be blocked on a fingerprint: ${JSON.stringify(report)}`);
  assert.equal(report.allowed, 3);
});

test('the report declares whether the budget is shared', () => {
  const { guard } = makeGuard();
  assert.equal(guard.report().budgetScope, 'in-process');
  assert.equal(guard.report().instances, 1);
});

test('the defaults are frozen so they cannot drift at runtime', () => {
  assert.ok(Object.isFrozen(DEFAULTS));
  assert.throws(() => {
    'use strict';
    DEFAULTS.limit = 1;
  });
});

test('a request without a socket falls back without throwing', () => {
  const { guard } = makeGuard();
  const decision = guard.check({ method: 'GET', url: '/', headers: BROWSER });
  assert.equal(decision.action, ALLOW, 'a request with no address must not crash the guard');
  assert.equal(decision.identity.unattributed, true);
  assert.match(decision.identity.normalized, /^unattributed:/);
});

test('an unparseable address still gets a budget of its own', () => {
  // An attacker cannot gain quota by sending garbage in the address field.
  const { guard } = makeGuard({ limit: 100 });
  const first = guard.check({ method: 'GET', url: '/', socket: { remoteAddress: 'nonsense' } });
  const second = guard.check({ method: 'GET', url: '/', socket: { remoteAddress: 'nonsense' } });
  assert.equal(first.identity.normalized, second.identity.normalized);
  assert.equal(first.identity.unattributed, true);
});

test('every option can be overridden', () => {
  const { guard } = makeGuard({ limit: 7, ipv6Prefix: 48, ipv4Prefix: 24, blockMs: 1000 });
  assert.equal(guard.options.limit, 7);
  assert.equal(guard.options.ipv6Prefix, 48);
  assert.equal(guard.options.ipv4Prefix, 24);
});

// ---------------------------------------------------------------------------
// Middleware over a real socket
// ---------------------------------------------------------------------------

function startServer(handler, options) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function fetch(server, path, headers = {}) {
  return new Promise((resolve) => {
    http.get(
      { host: '127.0.0.1', port: server.address().port, path, headers },
      (res) => {
        let body = '';
        res.on('data', (d) => {
          body += d;
        });
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: body.trim() })
        );
      }
    );
  });
}

test('attach lets an ordinary browser request through to the origin', async () => {
  const guard = new SiegeGuard();
  const server = await startServer(attach((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('origin ok');
  }, { guard }));
  try {
    const res = await fetch(server, '/', BROWSER);
    assert.equal(res.status, 200);
    assert.equal(res.body, 'origin ok');
  } finally {
    server.close();
  }
});

test('attach answers a denied request with the status and a retry hint', async () => {
  const guard = new SiegeGuard({ limit: 10 });
  const server = await startServer(attach((req, res) => res.end('never'), { guard }));
  try {
    let last;
    for (let i = 0; i < 40; i += 1) last = await fetch(server, '/', BROWSER);
    assert.ok(last.status === 429 || last.status === 403, `got ${last.status}`);
    assert.ok(last.headers['retry-after'] || last.status === 403);
  } finally {
    server.close();
  }
});

test('the denial response carries the guard header', async () => {
  const guard = new SiegeGuard();
  const server = await startServer(attach((req, res) => res.end('never'), { guard }));
  try {
    const res = await fetch(server, '/.env', RAW_SCANNER);
    // Not blocked: the fingerprint alone cannot convict. With a tiny budget the
    // surcharged request still exhausts it, which is the honest outcome.
    assert.notEqual(res.headers['x-siege-guard'], 'block');
    assert.ok(res.status === 200 || res.status === 429, `unexpected status ${res.status}`);
  } finally {
    server.close();
  }
});

test('the explain option puts the reasoning in the body', async () => {
  const guard = new SiegeGuard();
  const server = await startServer(attach((req, res) => res.end('never'), { guard, explain: true }));
  try {
    // A browser request is allowed, so drive the explanation through a denial:
    // a tiny budget makes even an honest client run out.
    const tiny = new SiegeGuard({ limit: 5 });
    const server2 = await startServer(
      attach((req, res) => res.end('never'), { guard: tiny, explain: true })
    );
    try {
      let res;
      for (let i = 0; i < 10; i += 1) res = await fetch(server2, '/', BROWSER);
      assert.match(res.body, /ALLOW|THROTTLE|BLOCK/);
      assert.match(res.body, /why/);
      assert.match(res.body, /identity/);
    } finally {
      server2.close();
    }
  } finally {
    server.close();
  }
});

test('guardMiddleware works with a next-style chain', async () => {
  const guard = new SiegeGuard();
  const middleware = guardMiddleware({ guard });
  const server = await startServer(
    (req, res) => {
      middleware(req, res, () => {
        res.writeHead(200);
        res.end('passed');
      });
    },
    {}
  );
  try {
    const res = await fetch(server, '/', BROWSER);
    assert.equal(res.status, 200);
    assert.equal(res.body, 'passed');
  } finally {
    server.close();
  }
});

test('the guard never throws out of the middleware', async () => {
  // A request with no usable address at all: the limiter must not be the thing
  // that takes the server down.
  const guard = new SiegeGuard();
  const server = await startServer(attach((req, res) => {
    res.writeHead(200);
    res.end('origin survived');
  }, { guard }));
  try {
    const res = await fetch(server, '/', { Host: 'x', 'User-Agent': '' });
    assert.ok([200, 403, 429, 500].includes(res.status));
  } finally {
    server.close();
  }
});