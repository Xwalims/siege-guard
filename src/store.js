'use strict';

/**
 * Sharing one budget across processes and hosts.
 *
 * ## The problem
 *
 * `SiegeGuard` keeps its window in memory. Run four Node processes behind a load
 * balancer and the attacker who owns one IP gets **four** budgets: one per
 * process. Reproduced in test/distributed.test.js -- with a limit of 100 and a
 * request cost of 5, 400 requests spread over four instances are served 80
 * times, where a single-instance limiter serves 20.
 *
 * This is not a bug in the limiter, it is a property of keeping state in a
 * process. The fix is to move the counter somewhere all instances can see.
 *
 * ## The interface
 *
 * A store is anything with these four methods:
 *
 *   spend(key, cost, windowMs, limit, now) -> {allowed, used, retryAfterMs}
 *   peek(key, windowMs, now)               -> {used, limit}
 *   reset(key)                             -> boolean
 *   sweep(now, idleMs)                     -> number removed
 *
 * Everything in this file is built on that shape, and {@link InMemoryStore} is
 * the same semantics as before so it can be used as a test double and as the
 * single-process default.
 *
 * ## Getting the arithmetic right
 *
 * A distributed window has to answer one question atomically: "if this request
 * spends `cost`, does the total stay within `limit`?" Redis gets this with a
 * Lua script, because a read followed by a write leaves a gap between them and
 * four processes hitting that gap together all see room for one more.
 *
 * The Redis store below emits a Lua script rather than a MULTI/EXEC pipeline for
 * exactly that reason. It is returned as a string, not executed, so this package
 * stays dependency-free and the tests can assert the script's shape.
 *
 * ## What still needs infrastructure
 *
 * Redis itself is not bundled. Install it, point `REDIS_URL` at it, and pass
 * `{store: new RedisStore(url)}` to the guard. A Redis outage must not take the
 * site down, so {@link ResilientStore} falls back to local memory and reports
 * that it did.
 */

/** The shape every store implements. */
const STORE_METHODS = Object.freeze(['spend', 'peek', 'reset', 'sweep']);

/**
 * A store backed by a Map: identical semantics to the in-process limiter.
 *
 * Useful as the default, as a test double for the Redis path, and as the
 * fallback when a remote store is unreachable.
 */
class InMemoryStore {
  constructor() {
    this.windows = new Map();
  }

  /** @inheritdoc */
  spend(key, cost, windowMs, limit, now) {
    let entry = this.windows.get(key);
    if (!entry) {
      entry = [];
      this.windows.set(key, entry);
    }
    const cutoff = now - windowMs;
    while (entry.length > 0 && entry[0].at <= cutoff) entry.shift();

    const used = entry.reduce((sum, e) => sum + e.cost, 0);
    if (used + cost > limit) {
      // Time until the oldest entry falls out of the window, which is the
      // earliest moment the request could succeed.
      const retryAfterMs = entry.length > 0 ? Math.max(1, entry[0].at + windowMs - now) : 1;
      return { allowed: false, used, retryAfterMs, backend: 'memory' };
    }
    entry.push({ at: now, cost });
    return { allowed: true, used: used + cost, retryAfterMs: 0, backend: 'memory' };
  }

  /** @inheritdoc */
  peek(key, windowMs, now) {
    const entry = this.windows.get(key);
    if (!entry) return { used: 0, backend: 'memory' };
    const cutoff = now - windowMs;
    let used = 0;
    for (const e of entry) {
      if (e.at > cutoff) used += e.cost;
    }
    return { used, backend: 'memory' };
  }

  /** @inheritdoc */
  reset(key) {
    return this.windows.delete(key);
  }

  /** @inheritdoc */
  sweep(now, idleMs = 60_000) {
    let removed = 0;
    for (const [key, entry] of this.windows) {
      const newest = entry.length > 0 ? entry[entry.length - 1].at : 0;
      if (newest <= now - idleMs) {
        this.windows.delete(key);
        removed += 1;
      }
    }
    return removed;
  }
}

/**
 * A shared store over Redis.
 *
 * The atomic part is {@link RedisStore#SPEND_SCRIPT}: it trims the window and
 * checks the total in one server-side operation. A pipeline of `ZREMRANGEBYSCORE`
 * then `ZCARD` then `ZADD` is not equivalent -- three processes interleaving
 * between those three commands each see room for one more request.
 *
 * A sorted set per key holds one member per accepted request, scored by arrival
 * time. The window is trimmed by score, and the total is the sum of a `cost`
 * field carried in the member's metadata.
 *
 * ## The member encoding, which is easy to get subtly wrong
 *
 * A member is `<cost>|<now>|<random>`: the cost leads and is closed by a pipe,
 * because both readers match a leading number terminated by that delimiter --
 * Lua with `string.match(rows[i], '^([%d%.]+)|')` and {@link RedisStore#costOf}
 * with `/^([\d.]+)\|/`.
 *
 * An earlier encoding put the cost last (`<now>-<cost>-<random>:<cost>`), where
 * the non-greedy pattern stopped at the wrong colon and made `tonumber` return
 * nil, breaking the script's arithmetic outright. Merely moving the cost to the
 * front is not enough either: a bare leading-number match then reads a *legacy*
 * member's arrival timestamp as its cost, reporting 1.75e12 of spend and locking
 * the identity out for a full window. The pipe is what makes an unreadable
 * member read as zero. See test/redis-store.test.js, which runs a real round
 * trip -- the script's own writer against the script's own reader, both parsed
 * out of SPEND_SCRIPT rather than hand-copied.
 *
 * @param {object} options
 * @param {object} options.client a redis client exposing eval/evalSha/zremrangebyscore/zrange/zadd/del/keys
 * @param {string} [options.prefix='sgw'] key namespace
 * @param {number} [options.maxSamplesPerKey=1000] cap on members per key
 */
class RedisStore {
  constructor(options) {
    if (!options || !options.client) {
      throw new TypeError('RedisStore needs a client with an eval() method');
    }
    this.client = options.client;
    this.prefix = options.prefix || 'sgw';
    this.maxSamples = options.maxSamplesPerKey ?? 1000;
  }

  /** The namespaced key for an identity. */
  keyFor(key) {
    return `${this.prefix}:${key}`;
  }

  /**
   * Build a sorted-set member in the exact shape the Lua script writes.
   *
   * Cost first, then arrival time, then a uniquifier. Anything that reads a
   * stored member must go through here and through the extraction rule the
   * script uses, or it will read the wrong field.
   *
   * @param {number} cost
   * @param {number} now
   * @param {string} [unique]
   * @returns {string}
   */
  static member(cost, now, unique) {
    const tail = unique ?? Math.random().toString(36).slice(2, 10);
    return `${cost}|${now}|${tail}`;
  }

  /**
   * The leading-number-plus-pipe rule shared with the Lua script's
   * `string.match(m, '^([%d%.]+)|')`. Kept in one place so the two cannot drift
   * apart.
   *
   * The trailing pipe is load-bearing. A member from an older encoding led with
   * the arrival time, so matching a bare leading number reads 1.75e12 as a cost.
   * Requiring the delimiter means such a member reads as 0 -- fail open, and the
   * key ages out of the window normally -- rather than bricking an identity.
   *
   * @param {string} member
   * @returns {number} the cost, or 0 for a member this version cannot read
   */
  static costOf(member) {
    const m = /^([\d.]+)\|/.exec(member);
    return m ? Number(m[1]) : 0;
  }

  /**
   * Atomically trim the window, test the budget, and record the request.
   *
   * Returned as a string rather than executed, so this package needs no Redis
   * dependency and the tests can assert that the script really is atomic.
   */
  get SPEND_SCRIPT() {
    return `
-- KEYS[1] the window key
-- ARGV[1] windowMs  ARGV[2] limit  ARGV[3] cost  ARGV[4] now  ARGV[5] memberId
--                                     ARGV[6] maxSamples
--
-- A stored member is "<cost>|<now>|<memberId>". The cost leads *and* is
-- terminated by a pipe on purpose. Both readers match '^([%d%.]+)|': anchoring
-- only the start is not enough, because an older encoding led with the arrival
-- time, so a bare leading-number match reads 1.75e12 as a cost and locks the
-- identity out for a whole window. Requiring the pipe makes an unreadable
-- member read as no spend at all, which fails open instead of bricking a key.
local key      = KEYS[1]
local window   = tonumber(ARGV[1])
local limit    = tonumber(ARGV[2])
local cost     = tonumber(ARGV[3])
local now      = tonumber(ARGV[4])
local member   = ARGV[5]
local maxSamp  = tonumber(ARGV[6])

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)

local rows = redis.call('ZRANGE', key, 0, -1, 'WITHSCORES')
local used = 0
for i = 1, #rows, 2 do
  local c = string.match(rows[i], '^([%d%.]+)|')
  if c then used = used + tonumber(c) end
end

if used + cost > limit then
  local oldest = nil
  if #rows >= 2 then oldest = tonumber(rows[2]) end
  local retry = 1
  if oldest then retry = math.max(1, oldest + window - now) end
  return {0, tostring(used), tostring(retry)}
end

redis.call('ZADD', key, now, tostring(cost) .. '|' .. now .. '|' .. member)
redis.call('ZCARD', key)
local count = redis.call('ZCARD', key)
if count > maxSamp then
  redis.call('ZREMRANGEBYRANK', key, 0, count - maxSamp - 1)
end
return {1, tostring(used + cost), '0'}
`.trim();
  }

  /** @inheritdoc */
  async spend(key, cost, windowMs, limit, now) {
    // Only a uniquifier: the script prepends cost and now itself, so a memberId
    // carrying its own copy of either would put a third number in front of the
    // cost and the leading-number readers would total the wrong thing.
    const memberId = Math.random().toString(36).slice(2, 10);
    const raw = await this.client.eval(this.SPEND_SCRIPT, {
      keys: [this.keyFor(key)],
      arguments: [String(windowMs), String(limit), String(cost), String(now), memberId, String(this.maxSamples)],
    });
    const [allowed, used, retryAfterMs] = Array.from(raw);
    return {
      allowed: allowed === 1 || allowed === '1',
      used: Number(used),
      retryAfterMs: Number(retryAfterMs),
      backend: 'redis',
    };
  }

  /** @inheritdoc */
  async peek(key, windowMs, now) {
    const rows = await this.client.zrange(this.keyFor(key), 0, -1, 'WITHSCORES');
    let used = 0;
    const cutoff = now - windowMs;
    for (let i = 0; i < rows.length; i += 2) {
      const score = Number(rows[i + 1]);
      if (score <= cutoff) continue;
      used += RedisStore.costOf(rows[i]);
    }
    return { used, backend: 'redis' };
  }

  /** @inheritdoc */
  async reset(key) {
    const removed = await this.client.del(this.keyFor(key));
    return Number(removed) > 0;
  }

  /**
   * Remove keys untouched for longer than `idleMs`.
   *
   * SCAN, never KEYS: KEYS blocks the Redis event loop for the length of the
   * keyspace, and on a shared instance that is someone else's outage.
   *
   * @inheritdoc
   */
  async sweep(now, idleMs = 300_000) {
    let cursor = '0';
    let removed = 0;
    do {
      const [next, keys] = await this.client.scan(cursor, 'MATCH', `${this.prefix}:*`, 'COUNT', 200);
      cursor = next;
      for (const key of keys) {
        const rows = await this.client.zrange(key, 0, 0, 'WITHSCORES');
        if (rows.length >= 2 && Number(rows[1]) <= now - idleMs) {
          await this.client.del(key);
          removed += 1;
        }
      }
    } while (cursor !== '0');
    return removed;
  }
}

/**
 * A store that prefers a remote backend and falls back to local memory.
 *
 * A Redis outage must not become a site outage. On failure this records the
 * error, serves from memory, and says so in `backend: 'memory-fallback'`, so an
 * operator watching metrics can see that the shared limit is no longer shared --
 * which is a materially weaker defence, not a transparent no-op.
 *
 * @param {object} options
 * @param {object} options.primary the store to try first
 * @param {object} [options.fallback] defaults to a fresh InMemoryStore
 * @param {number} [options.retryAfterMs=5000] how long to stay local before retrying
 * @param {Function} [options.now]
 */
class ResilientStore {
  constructor(options) {
    if (!options || !options.primary) {
      throw new TypeError('ResilientStore needs a primary store');
    }
    this.primary = options.primary;
    this.fallback = options.fallback || new InMemoryStore();
    this.retryAfterMs = options.retryAfterMs ?? 5000;
    this.now = options.now || Date.now;
    this.degradedUntil = 0;
    this.lastError = null;
    this.failures = 0;
  }

  /** True while serving from local memory instead of the shared backend. */
  get degraded() {
    return this.now() < this.degradedUntil;
  }

  /**
   * Run against the primary, falling back on failure or while degraded.
   *
   * @param {string} method
   * @param {Array} args
   * @returns {Promise<object>}
   */
  async call(method, args) {
    if (this.degraded) {
      const result = await this.fallback[method](...args);
      return { ...result, backend: 'memory-fallback', degraded: true };
    }
    try {
      const result = await this.primary[method](...args);
      this.failures = 0;
      return result;
    } catch (error) {
      this.lastError = error;
      this.failures += 1;
      this.degradedUntil = this.now() + this.retryAfterMs;
      const result = await this.fallback[method](...args);
      return { ...result, backend: 'memory-fallback', degraded: true, error: error.message };
    }
  }

  spend(...args) {
    return this.call('spend', args);
  }

  peek(...args) {
    return this.call('peek', args);
  }

  reset(...args) {
    return this.call('reset', args);
  }

  sweep(...args) {
    return this.call('sweep', args);
  }
}

module.exports = Object.freeze({
  InMemoryStore,
  RedisStore,
  ResilientStore,
  STORE_METHODS,
});