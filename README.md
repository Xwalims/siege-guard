# siege-guard

Adaptive **application-layer (L7) DoS defence** for Node HTTP servers. Sliding-window
cost-weighted rate limiting, IPv6-aware client identity, path-entropy scanner detection
and a circuit breaker for a failing origin.

Zero dependencies. Node 20+.

```
npm install siege-guard
```

## What this does not stop

Read this first, because it is the part that matters.

**A volumetric L3/L4 flood does not reach this code.** If someone sends 300 Gbit/s of UDP
at your IP, no application logic stops it: the packets are answered by the network before
your process sees them. That is the job of an upstream scrubbing provider (Cloudflare,
AWS Shield, Pathosphere) or anycast routing.

What this *does* stop is the traffic that actually costs you CPU and database time:

| Attack | Handled here |
| --- | --- |
| L7 request flood from one or many hosts | yes, cost-weighted budget |
| Credential stuffing against a login endpoint | yes, auth routes priced highest |
| Directory enumeration and vulnerability scanning | yes, fingerprint plus path entropy |
| IPv6 address rotation to dodge a rate limit | yes, prefix-based identity |
| A failing origin being hammered by retries | yes, circuit breaker |
| Volumetric L3/L4 flood | **no** — needs upstream scrubbing |

## Quick start

```js
const http = require('node:http');
const { attach } = require('siege-guard');

const server = http.createServer(attach((req, res) => {
  res.end('ok');
}, { limit: 1000 }));
```

With a framework that has a `next`, use the middleware form:

```js
const { guardMiddleware } = require('siege-guard');
app.use(guardMiddleware({ limit: 5000, strikesToBlock: 5 }));
```

## See it working

```
$ node examples/attack-demo.js
```

Real output, verbatim:

```
3. An L7 flood from one host
----------------------------
  static flood            400 requests   400 allowed    0 throttled    0 challenged     0 blocked
                         400 requests at cost 1 each
  write flood              40 requests    12 allowed    2 throttled    0 challenged    26 blocked
                         40 requests at cost 50 each: 2000 for the same budget

  the same budget served 400 cheap requests but only 12 writes. Cost weighting is the
  difference between "400 requests" and "how much work did I actually ask for".

4. The same flood, rotated across one IPv6 /64
----------------------------------------------
  rotated                 300 requests   200 allowed    2 throttled    0 challenged    98 blocked
                         300 DIFFERENT source addresses, one allocation

  every request came from a different address, and all of them shared the key
  2001:db8:: (a /64 is 18446744073709551616 addresses).
  200 were served and the rest refused. A limiter keyed on the full
  address would have served all 300, because it would have seen 300 new clients.
```

Three hundred requests from three hundred different source addresses, and the guard
stopped at request 200. A limiter keyed on the full address would have served all of them,
because it would have believed it had seen three hundred distinct new clients.

## The five algorithms

### 1. Sliding window, not a fixed window

The obvious limiter is "at most N requests per 60 seconds". It is defeated at the boundary:
with N = 300, a client sends 300 requests in the last second of one minute and 300 in the
first second of the next, and has made 600 in about two seconds without ever breaking the
rule as written.

This keeps two adjacent buckets and interpolates. The count moves continuously, so a
boundary burst lands on a non-zero fraction of the previous bucket and cannot exceed the
limit.

```
sliding window cannot be burst-exploited at a minute boundary
```

is the test that proves it, and it fails against a fixed-window implementation.

Clock going backwards is clamped to zero. An NTP step must never hand out free quota, and
the naive computation does exactly that: the older bucket gains weight instead of losing it.

### 2. IPv6-aware identity

This is the part naive limiters get wrong. Keying on the remote address is correct on IPv4
and useless on IPv6. A single allocation is typically a **/64 — 18 446 744 073 709 551 616
addresses**. An attacker rotates through them at will and every address gets a fresh budget,
so the limiter's memory grows without bound while the attack continues.

Identity is computed on a **prefix**, not an address:

| Prefix | Addresses | Use for |
| --- | --- | --- |
| /64 | 2^64 | residential ISP, mobile, cloud VMs — the default |
| /56 | 2^56 | an ISP handing a /56 to one large site |
| /48 | 2^48 | a datacentre, one RIR block |

IPv4 defaults to /32, one host. `::ffff:127.0.0.1` is unwrapped to IPv4 first, so a
dual-stack server does not collapse four million IPv4 clients into one bucket.

```js
const { identityOf } = require('siege-guard');

identityOf('2001:db8::1');
// { normalized: '2001:db8::', family: 6, subnetSize: '18446744073709551616', prefix: 64 }
```

`subnetSize` is a string on purpose: 2^64 does not fit a double, and printing
`1.8446744073709552e+19` in the diagnostic that is supposed to explain the diagnostic would
be a bug.

**Every prefix operation is cross-checked against Python's `ipaddress`.**

```
$ python3 scripts/cross-check.py
IPv6 masking: 156 cells compared, 0 mismatch(es)
IPv4 masking: 64 cells compared, 0 mismatch(es)
identityOf: 21 address(es) checked, 0 problem(s)

all prefix operations agree with Python's ipaddress
```

This harness exists because hand-written expectations got it wrong twice during
development — `2001:db8:0:1::abcd` was assumed to sit inside `2001:db8::/64`, and
`2001:db8:ff::1` was assumed to share a /56 with `2001:db8::1`. Both assumptions were
wrong. Asking a standard library beats reasoning harder.

### 3. Cost-weighted budgets

Requests are not equal. A cached stylesheet costs a disk read the kernel may serve from
cache; a database write costs a transaction. Counting both as 1 lets a flood of cheap
requests through while the server burns its budget doing almost nothing.

| Class | Cost | Example |
| --- | --- | --- |
| `static` | 1 | `/app.css` |
| `apiRead` | 5 | `GET /api/items` |
| `apiReadAuthed` | 15 | authenticated read |
| `apiWrite` | 50 | `POST /api/items` |
| `auth` | 100 | `/api/auth/login` |

With a budget of 1000 that is 1000 static requests, 200 writes, or **ten login attempts**.
Ordering matters: `/api/auth/login` is priced as `auth`, not as a generic write, because a
POST is not automatically the most expensive thing on your site.

### 4. Path-entropy scan detection

A human reads three pages and returns to them. An enumerator touches `/api/admin`,
`/api/users`, `/.env`, `/wp-login`, each exactly once.

Two measurements separate them:

- **Shannon entropy** over recently requested paths — low when one path dominates.
- **Novelty ratio** — the share of recent paths never seen before. A human's falls, an
  enumerator's stays at 1.0.

Thresholds are not guessed. `test/entropy.test.js` drives a bundled benign trace and a
bundled hostile trace through the module and asserts the separation, so a future change
that moved the boundary into the overlap would fail the build.

| | entropy | novelty | verdict |
| --- | --- | --- | --- |
| human trace | below threshold | low | not a scan |
| scanner trace | 3.91 | 1.00 | scan |
| API client on a wide tree | 4.58 | low | not a scan |

Entropy alone is not enough, which is why the third row exists: a legitimate client walking
a resource tree also produces high entropy, and only novelty distinguishes it from
enumeration.

Note the minimum sample count is 8, and `log2(8) = 3.0` is still below the 3.4 threshold,
so a short trace is correctly **not** flagged. Sixteen distinct paths give 4.0 and clear it.

### 5. HTTP client fingerprinting, honestly limited

A full client fingerprint (JA3/JA4) is built from the TLS ClientHello. Node's `http` module
does not expose it — by the time a handler runs, the handshake is finished and its bytes are
gone. Reading it needs a TLS-terminating proxy, a native addon, or a TLS library that hands
over the raw handshake.

So this works with what a plain Node server can actually see, and says so rather than
pretending:

| Signal | Weight | Fires when |
| --- | --- | --- |
| `noSecFetch` | 0.22 | no `sec-fetch-*` at all; browsers always send some |
| `missingUserAgent` | 0.20 | user agent empty or absent |
| `knownBotUserAgent` | 0.15 | names a known scanner or non-browser client |
| `alphabeticalHeaders` | 0.18 | headers arrive sorted, a hash-map artefact |
| `flatAcceptLanguage` | 0.05 | one language, no q-values |
| `missingAcceptEncoding` | 0.05 | no `accept-encoding` |
| `missingAccept` | 0.05 | no `accept` |
| `rawSocket` | 0.10 | none of the above, and no user agent |

Measured on the demo traces:

```
ordinary browser      0.00   looks like an ordinary browser
python-requests       0.47   below the 0.6 block threshold
bare socket           0.77   every signal fires
```

The header-order check reads `rawHeaders`, the actual wire order. An earlier version
filtered through a list that was itself alphabetical and compared the filtered list against
itself, so every request passed and the signal was decorative.

Limits, stated plainly: a determined attacker can forge all of these, they raise the cost of
a casual scan rather than authenticating anyone, and behind a CDN the browser-shaped signals
describe the CDN. Pass `behindProxy: true` and the package discounts them.

## The circuit breaker

Without one, an origin that starts returning 500s attracts *more* traffic: every client
retries, health checks pile on, and the retries consume the capacity needed to recover.

```
closed ──failure ratio over window──> open ──cooldown──> half-open ──2 successes──> closed
```

`half-open` allows exactly 3 probes, not unlimited traffic, so the origin is not flooded the
instant it recovers. One failed probe re-opens it immediately. The breaker never recovers on
its own: nothing has proved the origin healthy until a request arrives and succeeds.

Report outcomes with `guard.reportOrigin(ok)` from your handler.

## Every decision explains itself

A DoS defence you cannot debug is a DoS defence somebody will disable during an incident.

```js
const { renderDecision } = require('siege-guard');

console.log(renderDecision(decision));
```

```
ALLOW  203.0.113.7  (200)
  why      within budget: 15 of 1000 cost used
  budget   15 of 1000 cost used  (2%)
  request  5 cost  (default: unclassified path)
  client   score 0.00  looks like an ordinary browser
  paths    entropy 0.00, novelty 0.00, 1 distinct
  identity IPv4 /32  covers 1 address(es)
```

```
BLOCK  2001:db8::  (403)
  why      budget exceeded 3 times: used 1000 of 1000 cost
  budget   1000 of 1000 cost used  (100%)
  request  5 cost  (apiRead: public API read)
  client   score 0.00  looks like an ordinary browser
  identity IPv6 /64  covers 18446744073709551616 addresses
  retry    after 300s
```

The same record works as JSON through the CLI:

```
$ echo "$DECISION" | siege-guard explain
```

## Decisions and their order

`ALLOW` · `THROTTLE` (429 + `Retry-After`) · `CHALLENGE` (403, when a challenge hook is
configured) · `BLOCK` (403, or 503 when the circuit is open)

The order is deliberate: circuit, then an existing block, then fingerprint, then the budget,
then the scan verdict. Cheap and decisive checks come before arithmetic, so an attack that
trips the breaker never reaches the counting.

Repeated excesses earn a strike; `strikesToBlock` (default 3) earns a block lasting `blockMs`
(default 5 minutes). A released identity is **not** forgiven — the first request past a block
resets the strike count and is throttled, so a client cannot flood again the moment it is let
back in.

## CLI

```
$ siege-guard simulate
```

```
  time source path verdict why
  ----------------------------------------------------------------------------------------------
     40ms browser               /                        ALLOW    within budget: 5 of 1000 cost used
    240ms scanner               /.env                    BLOCK    client fingerprint 0.77 >= 0.6: fired: noSecFetch, missing
    405ms flood                 /static/chunk0.js        ALLOW    within budget: 1 of 1000 cost used
    705ms flood-write           /api/domains             ALLOW    within budget: 110 of 1000 cost used
    795ms flood-write           /api/domains             THROTTLE budget exhausted: 960 of 1000 cost used, 50 requested
    803ms ipv6-rotate           /api/data                ALLOW    within budget: 5 of 1000 cost used
   1403ms ipv6-rotate           /api/data                THROTTLE budget exhausted: 1000 of 1000 cost used, 5 requested
   1409ms ipv6-rotate           /api/data                BLOCK    budget exceeded 3 times: used 1000 of 1000 cost
   1710ms credential-stuffing   /api/auth/login          ALLOW    within budget: 100 of 1000 cost used
   1810ms credential-stuffing   /api/auth/login          THROTTLE budget exhausted: 1000 of 1000 cost used, 100 requested
   1830ms credential-stuffing   /api/auth/login          BLOCK    budget exceeded 3 times: used 1000 of 1000 cost
```

```
What this run showed
---------------------
  browser                  5 requests     5 allowed     0 throttled     0 blocked
  scanner                  5 requests     0 allowed     0 throttled     5 blocked
  flood                   60 requests    60 allowed     0 throttled     0 blocked
  flood-write             20 requests    18 allowed     2 throttled     0 blocked
  ipv6-rotate            300 requests   200 allowed     2 throttled    98 blocked
  credential-stuffing     25 requests    10 allowed     2 throttled    13 blocked
```

```
$ siege-guard inspect
$ siege-guard explain < decision.json
```

Flags: `--limit`, `--window`, `--ipv6-prefix`, `--ipv4-prefix`, `--block-score`,
`--challenge-score`, `--strikes`, `--block-on-scan`, `--json`, `--quiet`.

Exit codes: `0` ok, `1` traffic was denied (a pass for `simulate`), `2` usage or IO error.

## Configuration

```js
const { createGuard } = require('siege-guard');

const guard = createGuard({
  windowMs: 60_000,
  limit: 1000,             // budget in cost units
  ipv6Prefix: 64,
  ipv4Prefix: 32,
  blockScore: 0.6,         // fingerprint score that hard-blocks
  challengeScore: 0.35,    // score that triggers the challenge hook
  strikesToBlock: 3,
  blockMs: 300_000,
  blockOnScan: false,      // off by default: entropy alone will not block
  behindProxy: false,      // true when a CDN fronts the origin
  challenge: (req) => 'prove you are a browser',
  costs: { apiWrite: 80 }, // override the price of one route class
});
```

`limit` is in **cost units**, not requests. Dividing by your average request cost gives a
requests-per-minute figure that reads naturally; that is a reporting convenience, not the
unit.

Long-running processes should call `guard.sweep()` periodically. Without it a busy server
accumulates one entry per client address forever, which is a memory leak shaped like a slow
DoS.

## API

```js
const {
  createGuard, SiegeGuard, SlidingWindow, identityOf, classify,
  PathEntropyTracker, CircuitBreaker, fingerprint,
  guardMiddleware, attach, renderDecision, renderReport,
  ALLOW, THROTTLE, CHALLENGE, BLOCK, DEFAULTS,
} = require('siege-guard');

guard.check(req);          // a decision record
guard.inspect(req);        // the same analysis, spending nothing
guard.reportOrigin(ok);    // tell the breaker how the origin answered
guard.forgive(address);    // clear every trace of one client
guard.report();            // counters, circuit state, hottest identities
guard.sweep();             // drop idle state
```

Every module is usable on its own. `SlidingWindow`, `CircuitBreaker` and `PathEntropyTracker`
have no dependency on HTTP and no dependency on each other.

## Tests

```
$ npm test
```

```
ℹ tests 144
ℹ pass 144
ℹ fail 0
```

```
$ npm run cross-check
$ npm run demo
```

## Deployment notes

Put the guard as the **first** thing in the chain, before session loading, before body
parsing and before any database work. A limiter that runs after authentication has already
paid for the request it is trying to prevent.

Behind a reverse proxy, the client address is `req.socket.remoteAddress` of the proxy. Pass
the real address through and read it from your own header, or every client will share one
budget. This package does not trust `X-Forwarded-For` for that reason — it is a
client-controlled header unless something in front of you strips and rewrites it.

## License

MIT