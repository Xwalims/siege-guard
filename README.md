# siege-guard

Adaptive **application-layer (L7) DoS defence** for Node HTTP servers. Sliding-window
cost-weighted rate limiting, IPv6-aware client identity, path-entropy scanner detection,
trusted-proxy address resolution, a shared budget for multi-instance deployments, and a
circuit breaker for a failing origin.

Zero dependencies. Node 20+.

**A block is never issued on evidence a client can forge.** Fingerprints and path entropy
produce challenges and surcharges; only an exhausted budget, an open circuit or a cost
ceiling can produce a 403. See "HTTP client fingerprinting" for why, and
[the five limits](#running-more-than-one-instance) this package has.

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

This keeps two adjacent buckets and interpolates between them.

**What that does and does not guarantee.** The attack above is closed: the test

```
sliding window cannot be burst-exploited at a minute boundary
```

fails against a fixed-window implementation and passes here.

It is still an *approximation*, not the exact set of the last 60 seconds. With two buckets,
the oldest one is charged linearly for its partial overlap, so a client whose requests
cluster at one end of the window is over-counted and one that clusters at the other end is
under-counted. The error is bounded and small, and it is the same trade-off Cloudflare and
Envoy make, because keeping every timestamp costs memory and CPU that the approximation
avoids. If you need the exact answer, this is not the right algorithm and you want a real
log of request times.

Clock going backwards is clamped to zero. An NTP step must never hand out free quota, and
the naive computation does exactly that: the older bucket gains weight instead of losing it.

**`Retry-After` is a promise the limiter keeps.** A client told to wait `retryAfterMs` is
admitted when it waits exactly that long — never refused again for obeying the header. The
delay is the *shortest* wait that works, so it neither stalls a client whose budget is already
free nor lies about when it returns. The cost curve is piecewise linear, so it takes at most
two phases: the older bucket decays for the rest of the current window, and the newer bucket
then decays over a full window after the roll-over. Both phases are pinned by tests that
re-ask the real accept path at the promised instant rather than restating the formula:

```
a honoured retry delay really does admit the client when it returns
```

Note that the answer is sometimes *more* than one window. A budget spent entirely at t=0 sits
in a bucket that does not start decaying until the window rolls over, so a cost-1 request
against a limit of 10 first fits at t=66 000, not t=60 000.

### 2. IPv6-aware identity — and its limits

This is the part naive limiters get wrong. Keying on the remote address is correct on IPv4
and useless on IPv6. A single allocation is typically a **/64 — 18 446 744 073 709 551 616
addresses**. An attacker rotates through them at will and every address gets a fresh budget,
so the limiter's memory grows without bound while the attack continues.

**What a /64 does not do.** It collapses one allocation into one budget, which stops
in-alloc address rotation — the cheap trick. It does not stop an attacker who rotates
*prefixes*, rents several VPS, or bounces through proxies: to those, each allocation is a
separate identity and each one gets a full budget, exactly as a distributed IPv4 attack gets
one budget per source address. A longer prefix (/56 or /48) makes that harder and starts
catching legitimate users of large ISPs in the same bucket.

Catching a genuinely distributed attacker needs something this package deliberately does not
have: a global reputation signal aggregated across identities. Feed the block and throttle
decisions into your SIEM, or run an ASN-level or account-level limit upstream of this. The
per-identity budget here is one layer, not the whole answer.

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

### 5. HTTP client fingerprinting — and why it never bans anyone

**Read this before trusting any of it.** Every signal below is forgeable in one line:

```python
requests.get(url, headers={
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.7',
  'Accept-Encoding': 'gzip, deflate, br',
  'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document',
})
```

That request scores **0.00** here, exactly like Chrome. An earlier version of this package
blocked on the fingerprint score alone, which meant those six headers earned a permanent
ban — a rule that punishes anyone who read the README and stops nothing.

So a fingerprint is no longer allowed to convict. `src/policy.js` enforces it: a `BLOCK`
requires a basis a client cannot manufacture, and `judge()` throws if a forgeable one ever
reaches `blockBases`. A high score now earns exactly two things:

- a **challenge**, if you wire one, and
- a **surcharge**: 1.5× or 2× the base price, so a suspicious client exhausts its window
  sooner and starts earning strikes.

Both are about making suspicion *cost something*, not about declaring guilt. When the budget
is finally exceeded, the block cites `budget-exceeded` — the one thing the client could not
fake.

The same applies to path entropy: an attacker who never repeats a path trivially keeps
novelty at 1.0, so `blockOnScan` is **off by default** and an entropy verdict earns a
challenge rather than a ban.

Legitimate API clients are the other half of the problem. A `curl` call, a server-to-server
integration, or a Go program sends a sparse header set and looks exactly like a scanner.
`challengeScore` is therefore a question, not an assertion: set it above 0.47 and you will
challenge ordinary integrations.

What this module actually reads, and what it cannot:

| Signal | Weight | Limit |
| --- | --- | --- |
| `noSecFetch` | 0.22 | trivially forged |
| `missingUserAgent` | 0.20 | trivially forged |
| `knownBotUserAgent` | 0.15 | one substring match away from a real browser |
| `alphabeticalHeaders` | 0.18 | order is attacker-chosen |
| `flatAcceptLanguage` | 0.05 | trivially forged |
| `missingAcceptEncoding` | 0.05 | trivially forged |
| `missingAccept` | 0.05 | trivially forged |
| `rawSocket` | 0.10 | trivially forged |

**Full JA3/JA4 needs the TLS ClientHello, which Node's `http` module does not expose** — by
the time a handler runs, the handshake is finished and its bytes are gone. Reading it needs a
TLS-terminating proxy, a native addon, or a TLS library that hands over the raw handshake.
That is a real capability difference, and it is the difference between "this script looks
automated" and "this is a known bot infrastructure".

Measured:

```
ordinary browser      0.00
python-requests       0.47
fully forged          0.00   <- identical to a browser
bare socket           0.77
```

Header order is read from `rawHeaders`, the real wire order. An earlier version filtered
through a list that was itself alphabetical and compared the filtered list against itself, so
every request matched and the signal was decorative.

Behind a CDN the browser-shaped signals describe the CDN. Pass `behindProxy: true` and they
are discounted.

## Running more than one instance

**The default budget is per-process.** Run four Node processes behind a load balancer and an
attacker who owns one IP gets four budgets. This is not a bug in the limiter; it is what
happens when state lives in a process.

The test asserts the failure rather than avoiding it, so the reason `src/store.js` exists
cannot be quietly forgotten:

```js
// four guards, no shared store: 80 requests served
// four guards, one shared store: 20 requests served, the same as one instance
```

Pass a store and the budget becomes global:

```js
const { createGuard, RedisStore, ResilientStore } = require('siege-guard');

const guard = createGuard({
  limit: 1000,
  store: new ResilientStore({
    primary: new RedisStore({ client: redisClient }),
  }),
});
```

Then use the async path, because a remote store is a network round trip:

```js
const decision = await guard.checkAsync(req);
```

`check()` throws if a store is configured, and `checkAsync()` throws if one is not. The two
cannot be mixed up silently, which is how a limiter ends up admitting everything while
looking configured.

**The arithmetic has to be atomic.** A read followed by a write leaves a gap, and four
processes in that gap each see room for one more request. `RedisStore` therefore ships a Lua
script that trims the window and tests the budget in one server-side operation. A pipeline of
`ZREMRANGEBYSCORE` → `ZCARD` → `ZADD` is not equivalent, and that mistake is common.

**The member encoding matters.** A stored entry is `cost|now|id`, cost first, because
both readers take a *leading* number: the Lua script with `string.match(m, '^([%d%.]+)')`
and `peek()` through `RedisStore.costOf`. An earlier encoding put the timestamp first and
the cost last, where the non-greedy match stopped at the wrong colon, `tonumber` returned
nil, and the script's `used` stayed 0 — a store that admits every request while looking
correct. `test/redis-store.test.js` runs the script's own extraction rule over members built
by the script's own writer instead of trusting a regex over the source.

A shared store also gives a place to put global state this package does not implement:
per-identity strikes and blocked-until timestamps are still per-process, so with N instances
a client needs N strikes before any one of them blocks it. Pass the same store for counters
you need global, or accept the weaker guarantee.

Redis is not bundled. Install it, point the client at it, and wire it up. **If Redis goes
down, the site must not.** `ResilientStore` falls back to local memory and marks the result
`backend: 'memory-fallback', degraded: true`, so a dashboard can show that the shared limit
stopped being shared — a materially weaker defence, reported honestly rather than hidden.

## Behind a reverse proxy

`req.socket.remoteAddress` is whoever opened the TCP connection, which behind a proxy is
always the proxy. Without help, every client behind it shares one budget and the limiter does
nothing at all.

Reading `X-Forwarded-For` is not the fix, because that header is client-controlled. Anyone
can send `X-Forwarded-For: 1.2.3.4` and every proxy in the path appends to it, producing
`1.2.3.4, <real client>`. Trust the leftmost entry and you have handed rate-limit identity to
whoever asked for it.

So the address is derived from the **trusted chain**, walked right to left:

```js
const guard = createGuard({
  trustedProxies: ['127.0.0.1', '10.0.0.0/8'],
});
```

1. Start from the socket, which cannot be forged.
2. Walk backwards while each hop is a configured proxy.
3. Stop at the first address that is not a proxy. That is the client, and it is the first
   value no proxy has vouched for.

The measured behaviour:

```
XFF: 5.6.7.8                                -> 5.6.7.8    the real client
XFF: 1.2.3.4, 5.6.7.8                        -> 5.6.7.8    forged 1.2.3.4 discarded
XFF: 1.2.3.4, 5.6.7.8, 9.10.11.12            -> 9.10.11.12  two forgeries discarded
socket 198.51.100.5 + XFF: 1.2.3.4           -> 198.51.100.5  untrusted socket wins
no trustedProxies configured + XFF: 1.2.3.4  -> the socket   headers ignored
200 hops, maxHops 16                         -> null          refused, not parsed
```

### The chain is validated first, not last

`X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP` and `Fly-Client-IP` carry a single
address rather than a chain. They are read only when there is **no** `X-Forwarded-For`
to validate. A client that sends both headers gets the chain's answer, because the chain
is the only form that can distinguish a forged entry from a real one.

That ordering is the whole point, and it was backwards:

```
socket 10.0.0.1 (a trusted proxy), appending proxy, real client 203.0.113.9

X-Forwarded-For: 6.6.6.6, 203.0.113.9   walk correctly resolves 203.0.113.9
X-Real-IP: 6.6.6.6                      consulted first, so 6.6.6.6 won
```

The resolver computed the right answer and then discarded it. Against a guard with
`limit: 10`, 200 requests each forging a different claimed address: **1 allowed, 99
throttled** with the chain alone, **200 allowed, 0 throttled** once a forged `X-Real-IP`
was added beside it. Rotation through unbounded identities defeats a per-identity budget
completely, so the forged value was being handed straight to `identityOf()`.

The limitation that remains, and is deliberate: when a client sends a single-address
header and **no** `X-Forwarded-For` at all, that header is trusted, because there is
nothing to validate it against. Set `trustedProxies` to the proxy ranges that actually
*overwrite* these headers, or configure the proxy to always send `X-Forwarded-For`.

An empty `trustedProxies` is the safe default: forwarding headers are ignored and every
client is the socket address. Loopback is trusted automatically, because a local proxy is the
ordinary case; set `trustLoopback: false` to require an explicit list.

Configure your proxy to overwrite rather than append, and keep this list tight. A CIDR in
`trustedProxies` means "anything in this range may speak for a client", so a broad range
hands that power to whoever can run a host in it.

IPv4 CIDRs are supported; IPv6 prefixes are refused rather than half-understood. A peer
address that is not a valid dotted quad is not trusted at all -- `Number('zzz')` is NaN and
every comparison against NaN is false, so accepting one would make a malformed address
match prefixes it should have failed.

### The mask arithmetic, which is easy to get subtly wrong

Computing the per-octet mask as `0xff << (8 - (bits - i * 8))` looks right and is not.
The shift goes **negative** as soon as an octet is entirely covered by the prefix, and
JavaScript does not raise on a negative shift -- it masks the count with `& 31`, so
`0xff << -7` becomes `0xff << 25`, which is zero. Octet 0 of a `/16` was therefore compared
against a mask of `0` and never checked at all:

```
trustedProxies: ['10.0.0.0/16']
  192.0.0.1     reported inside    (octet 0 unchecked)
  11.0.0.1      reported inside    (octet 0 unchecked)
  172.31.255.254 reported outside   (accidentally right, via octet 1)
```

The effect was not cosmetic. `isTrusted` decides whether a peer counts as a proxy, so
`10.0.0.0/16` believed the `X-Forwarded-For` of anyone whose second octet was zero -- a
256x wider trust set than configured, and the forged-header rule above quietly defeated for
every deployment that did not happen to use a `/8`. Only `/0`-`/8` were ever correct, which is
why the original tests, all of which used a `/8`, passed.

`test/proxy.test.js` now flips every bit of every octet at all 32 prefix lengths and checks
each against the prefix arithmetic, so no mask position can go unchecked again.

`decision.address` carries the resolver's verdict, including `untrustedPrefix`, so a
discarded forgery is visible in your logs rather than silent.

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

The order is deliberate: circuit, then an existing block, then the cost ceiling, then the
budget, then a challenge, then the scan verdict. Cheap and decisive checks come before
arithmetic, so an attack that trips the breaker never reaches the counting.

`check()` and `checkAsync()` apply that order identically, and are covered by a test that
walks both step lists so they cannot quietly drift apart. They diverge only in how the budget
is spent: an in-process `SlidingWindow` versus `await store.spend(...)`, which is why a guard
with a shared store refuses the synchronous call instead of pretending to serve it.

**Fingerprint is not in that list as a blocking condition.** It appears only after the budget
has been spent, where its influence is the surcharge and the optional challenge. Every 403
carries a `bases` array naming why, and `judge()` throws rather than let a forgeable basis
reach it:

```js
decision.bases;  // ['budget-exceeded']
```

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
  trustedProxies: ['127.0.0.1'],  // whose forwarding headers to believe
  store: null,             // a shared store; see "Running more than one instance"
  challenge: (req) => 'prove you are a browser',
  costs: { apiWrite: 80 }, // override the price of one route class
});
```

`limit` is in **cost units**, not requests. Dividing by your average request cost gives a
requests-per-minute figure that reads naturally; that is a reporting convenience, not the
unit.

Long-running processes should call `guard.sweep()` periodically. Without it a busy server
accumulates one entry per client address forever, which is a memory leak shaped like a slow
DoS. It returns what it dropped: `{ window, entropy, punished, store }`, the last being a
promise when a shared store is configured. An identity is forgotten five minutes after its
last request, so the counters agree with what the process is actually holding.

## API

```js
const {
  createGuard, SiegeGuard, SlidingWindow, identityOf, classify,
  PathEntropyTracker, CircuitBreaker, fingerprint,
  guardMiddleware, attach, renderDecision, renderReport,
  judge, mayBlock, BLOCK_BASES, CHALLENGE_BASES,
  createAddressResolver, InMemoryStore, RedisStore, ResilientStore,
  ALLOW, THROTTLE, CHALLENGE, BLOCK, DEFAULTS,
} = require('siege-guard');

guard.check(req);           // a decision record (single process)
await guard.checkAsync(req); // the same, against a shared store
guard.inspect(req);         // the same analysis, spending nothing
guard.reportOrigin(ok);     // tell the breaker how the origin answered
guard.forgive(address);     // clear every trace of one client
guard.report();             // counters, budgetScope, hottest identities
await guard.sweep();        // drop idle state, local and shared
```

Every module is usable on its own. `SlidingWindow`, `CircuitBreaker` and `PathEntropyTracker`
have no dependency on HTTP and no dependency on each other.

## Tests

```
$ npm test
```

```
ℹ tests 248
ℹ pass 248
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