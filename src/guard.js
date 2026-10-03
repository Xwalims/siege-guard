'use strict';

/**
 * The guard: the single place where a request becomes a decision.
 *
 * Every decision carries a structured reason. A DoS defence that cannot explain
 * why it denied something is a DoS defence that gets turned off during an
 * incident -- usually by someone who cannot work out whether it is broken or
 * working.
 *
 * ## Policy in one paragraph
 *
 * A BLOCK requires independent evidence: a budget that was actually exceeded, a
 * circuit that is open, a cost above the operator's ceiling. A fingerprint never
 * blocks on its own, because every fingerprint signal is forgeable and a
 * ban-happy limiter bans real API clients. Suspicion buys a challenge and a
 * higher price per request, which is enough: the budget still has to be spent,
 * and the request that spends it is the evidence.
 */

const { SlidingWindow } = require('./window.js');
const { identityOf } = require('./identity.js');
const { classify } = require('./cost.js');
const { PathEntropyTracker } = require('./entropy.js');
const { fingerprint } = require('./signals.js');
const { CircuitBreaker } = require('./circuit.js');
const { createAddressResolver } = require('./proxy.js');
const { judge, BLOCK_BASES } = require('./policy.js');
const { InMemoryStore } = require('./store.js');
const { renderDecision, renderReport } = require('./explain.js');

/** Outcomes, ordered by severity. */
const ALLOW = 'allow';
const THROTTLE = 'throttle';
const CHALLENGE = 'challenge';
const BLOCK = 'block';

/** Every default, in one frozen object. */
const DEFAULTS = Object.freeze({
  windowMs: 60_000,
  limit: 1000,
  ipv6Prefix: 64,
  ipv4Prefix: 32,
  /** A single request costing more than this is rejected outright. 0 disables. */
  maxCostPerRequest: 0,
  /** Fingerprint at or above this is no longer merely suspicious. Still not a ban. */
  blockScore: 0.6,
  /** Fingerprint at or above this earns a challenge when one is wired. */
  challengeScore: 0.35,
  /** Path-entropy verdict that leads to a block rather than a throttle. */
  blockOnScan: false,
  /** Times an identity may exceed its budget before it is blocked outright. */
  strikesToBlock: 3,
  /** How long a block lasts. */
  blockMs: 300_000,
  behindProxy: false,
  /**
   * Proxies whose forwarding headers may be believed. Empty means "believe the
   * socket only", which is the safe default: without this every client behind a
   * proxy shares one budget, because the socket address is always the proxy.
   */
  trustedProxies: [],
  challenge: null,
  enabled: true,
});

class SiegeGuard {
  /**
   * @param {object} [options] see {@link DEFAULTS}
   * @param {number|Function} [options.now] fixed clock, for tests and simulations
   * @param {object} [options.costs] cost table override
   * @param {object} [options.breaker] circuit breaker options
   * @param {object} [options.resolver] a pre-built address resolver
   * @param {object} [options.store] a shared budget store; see src/store.js.
   *   Without one the guard keeps its budget in process, which means N instances
   *   give an attacker N budgets. That is documented rather than hidden, and
   *   {@link SiegeGuard#report} says which mode it is in.
   */
  constructor(options = {}) {
    this.options = Object.freeze({ ...DEFAULTS, ...options });
    const clock =
      typeof options.now === 'function' ? options.now
      : typeof options.now === 'number' ? () => options.now
      : Date.now;
    this.now = clock;

    this.sharedStore = options.store || null;

    this.window = new SlidingWindow({
      windowMs: this.options.windowMs,
      limit: this.options.limit,
      now: clock,
    });
    this.entropy = new PathEntropyTracker(options.entropy || {});
    this.breaker = new CircuitBreaker({ ...(options.breaker || {}), now: clock });
    this.resolver =
      options.resolver ||
      createAddressResolver({
        trustedProxies: this.options.trustedProxies,
        trustLoopback: options.trustLoopback,
        maxHops: options.maxHops,
      });

    /** @type {Map<string, {strikes: number, blockedUntil: number}>} */
    this.punished = new Map();
    this.decisionCount = 0;
    this.allowedCount = 0;
    this.throttledCount = 0;
    this.challengedCount = 0;
    this.blockedCount = 0;
  }

  /**
   * Inspect a request without spending anything.
   *
   * @param {object} req
   * @returns {object}
   */
  inspect(req) {
    const address = this.resolveClientAddress(req);
    const identity = this.resolveIdentity(req, address);
    const cost = classify(req, {
      costs: this.options.costs,
      authenticated: Boolean(req.authenticated),
    });
    const entropy = this.entropy.score(identity.normalized);
    const print = fingerprint(req, { behindProxy: this.options.behindProxy });
    const circuit = this.breaker.allow(this.now());
    const state = this.punished.get(identity.normalized);

    return {
      identity,
      address,
      cost,
      entropy,
      fingerprint: print,
      circuit,
      strikes: state ? state.strikes : 0,
      blockedUntil: state ? state.blockedUntil : 0,
      budget: {
        used: this.window.used(identity.normalized, this.now()),
        limit: this.options.limit,
      },
    };
  }

  /**
   * Find the client address, honouring the trusted proxy list.
   *
   * @param {object} req
   * @returns {object} the resolver's verdict
   */
  resolveClientAddress(req) {
    try {
      return this.resolver.resolve(req);
    } catch {
      return {
        address: null,
        trusted: false,
        chain: [],
        source: 'error',
        untrustedPrefix: true,
      };
    }
  }

  /**
   * Work out who a request came from.
   *
   * A request with no usable address, or one carrying an address this package
   * cannot parse, must not crash the guard: a defence that throws on malformed
   * input is an outage waiting for a stranger to find. Such a request is given
   * its own single identity, so it still spends a budget and cannot flood by
   * being unparseable, but it cannot be attributed to anyone either.
   *
   * @param {object} req
   * @param {object} [resolved] the resolver's verdict, to avoid resolving twice
   * @returns {object} an identity record
   */
  resolveIdentity(req, resolved) {
    const address = resolved ? resolved.address : this.resolveClientAddress(req).address;
    const options = {
      ipv6Prefix: this.options.ipv6Prefix,
      ipv4Prefix: this.options.ipv4Prefix,
    };
    try {
      return identityOf(address, options);
    } catch {
      const label =
        address === undefined || address === null ? 'no-address' : String(address);
      return Object.freeze({
        raw: address === undefined || address === null ? '' : String(address),
        normalized: `unattributed:${label}`,
        family: 0,
        subnetSize: '1',
        prefix: 0,
        mapped: false,
        unattributed: true,
      });
    }
  }

  /**
   * Decide what to do with a request.
   *
   * @param {object} req
   * @param {object} [options]
   * @param {boolean} [options.record=true] observe the path for entropy
   * @returns {object} a decision record
   */
  check(req, options = {}) {
    if (this.sharedStore) {
      throw new Error(
        'this guard has a shared store, so the budget must be awaited: use checkAsync(), or drop {store} for single-process use'
      );
    }
    const now = this.now();
    this.decisionCount += 1;
    const details = this.inspect(req);
    const { identity } = details;
    const key = identity.normalized;

    // Observe the path BEFORE judging. The entropy verdict in `details` was taken
    // before this request was recorded, so judging on it would always be one
    // request behind: a scan would only be noticed after the request that
    // completed it had already been served.
    let entropyVerdict = details.entropy;
    if (options.record !== false) {
      entropyVerdict = this.entropy.observe(key, String(req.url || '/').split('?')[0]);
      details.entropy = entropyVerdict;
    }

    // 1. The origin is failing. Not client behaviour at all, so it outranks
    //    everything and needs no evidence beyond the breaker itself.
    if (!details.circuit.allow) {
      return this.decide(BLOCK, details, {
        reason: `origin circuit is ${details.circuit.state}: ${details.circuit.reason}`,
        status: 503,
        retryAfterMs: this.breaker.snapshot(now).cooldownRemainingMs,
        bases: [BLOCK_BASES.CIRCUIT],
      });
    }

    // 2. A previous excess already earned a block.
    if (details.blockedUntil > now) {
      return this.decide(BLOCK, details, {
        reason: `blocked for another ${Math.ceil((details.blockedUntil - now) / 1000)}s after ${details.strikes} strikes`,
        status: 403,
        retryAfterMs: details.blockedUntil - now,
        bases: [BLOCK_BASES.EXISTING],
      });
    }

    // 3. Judge the request. The verdict comes from src/policy.js, where a
    //    fingerprint is structurally incapable of producing a block.
    const verdict = judge({
      fingerprint: details.fingerprint,
      entropy: details.entropy,
      budget: details.budget,
      cost: details.cost.cost,
      strikes: details.strikes,
      options: this.options,
    });

    // 4. A cost above the operator's ceiling, refused before any budget work.
    if (
      this.options.maxCostPerRequest > 0 &&
      details.cost.cost > this.options.maxCostPerRequest
    ) {
      return this.decide(BLOCK, details, {
        reason: `request costs ${details.cost.cost}, above the per-request ceiling ${this.options.maxCostPerRequest}`,
        status: 403,
        bases: [BLOCK_BASES.CEILING],
      });
    }

    // 5. Spend the budget, priced by suspicion. The multiplier is not evidence
    //    and not a verdict: it only makes a suspicious client exhaust its window
    //    sooner, which is the honest way to make suspicion cost something.
    const priced = Math.max(1, Math.round(details.cost.cost * verdict.priceMultiplier));

    const budget = this.window.consume(key, priced, now);
    if (!budget.allowed) {
      const state = this.strikes(key, now);
      if (state.strikes >= this.options.strikesToBlock) {
        state.blockedUntil = now + this.options.blockMs;
        const surcharge =
          priced !== details.cost.cost ? ` (charged ${priced} for a suspicious client)` : '';
        return this.decide(BLOCK, details, {
          reason: `budget exceeded ${this.options.strikesToBlock} times: used ${Math.round(budget.used)} of ${this.options.limit} cost${surcharge}`,
          status: 403,
          retryAfterMs: this.options.blockMs,
          bases: [BLOCK_BASES.BUDGET],
          extra: { strikes: state.strikes, priced, multiplier: verdict.priceMultiplier },
        });
      }
      return this.decide(THROTTLE, details, {
        reason: `budget exhausted: ${Math.round(budget.used)} of ${this.options.limit} cost used, ${priced} requested`,
        status: 429,
        retryAfterMs: budget.retryAfterMs,
        after: { used: budget.used, limit: this.options.limit },
        bases: [BLOCK_BASES.BUDGET],
        extra: { strikes: state.strikes, priced, multiplier: verdict.priceMultiplier },
      });
    }

    // 6. The budget is fine. Now a challenge is possible, and only now: there
    //    is budget left, so the cost of asking for proof is affordable.
    if (verdict.verdict === 'challenge' && this.options.challenge) {
      this.challengedCount += 1;
      const why =
        details.fingerprint.score >= this.options.challengeScore
          ? `fingerprint ${details.fingerprint.score.toFixed(2)} >= ${this.options.challengeScore}`
          : details.entropy.reason;
      return this.decide(CHALLENGE, details, {
        reason: `${verdict.challengeBases.join(' + ')}: ${why}`,
        status: 403,
        after: { used: budget.used, limit: this.options.limit },
        bases: verdict.challengeBases,
        extra: { multiplier: verdict.priceMultiplier },
      });
    }

    // 7. An operator may still want a scan verdict to be fatal. Off by default,
    //    because path entropy is also forgeable by simply not repeating a path.
    if (this.options.blockOnScan && entropyVerdict.isScan) {
      return this.decide(BLOCK, details, {
        reason: entropyVerdict.reason,
        status: 403,
        bases: [BLOCK_BASES.SCAN],
        extra: { entropy: entropyVerdict },
      });
    }

    return this.decide(ALLOW, details, {
      reason: `within budget: ${Math.round(budget.used)} of ${this.options.limit} cost used`,
      status: 200,
      after: { used: budget.used, limit: this.options.limit },
      bases: [],
      extra: { multiplier: verdict.priceMultiplier },
    });
  }

  /**
   * Decide asynchronously, against a shared store.
   *
   * A remote store is inherently async, so the guard needs an async path that
   * does exactly what `check()` does. Keeping them separate is deliberate: the
   * synchronous path stays free of promise overhead for the single-process case,
   * and neither has to quietly call the other, because a synchronous method that
   * secretly returns a pending promise is how rate limiters end up admitting
   * everything.
   *
   * `check()` refuses to run against a shared store, and `checkAsync()` throws
   * without one, so the two cannot be mixed up silently.
   *
   * @param {object} req
   * @param {object} [options] see {@link SiegeGuard#check}
   * @returns {Promise<object>} a decision record
   */
  async checkAsync(req, options = {}) {
    if (!this.sharedStore) {
      throw new Error(
        'checkAsync needs a shared store: pass {store} to the guard, or use check() for a single process'
      );
    }
    const now = this.now();
    this.decisionCount += 1;
    const details = this.inspect(req);
    const { identity } = details;
    const key = identity.normalized;

    let entropyVerdict = details.entropy;
    if (options.record !== false) {
      entropyVerdict = this.entropy.observe(key, String(req.url || '/').split('?')[0]);
      details.entropy = entropyVerdict;
    }

    if (!details.circuit.allow) {
      return this.decide(BLOCK, details, {
        reason: `origin circuit is ${details.circuit.state}: ${details.circuit.reason}`,
        status: 503,
        retryAfterMs: this.breaker.snapshot(now).cooldownRemainingMs,
        bases: [BLOCK_BASES.CIRCUIT],
      });
    }

    if (details.blockedUntil > now) {
      return this.decide(BLOCK, details, {
        reason: `blocked for another ${Math.ceil((details.blockedUntil - now) / 1000)}s after ${details.strikes} strikes`,
        status: 403,
        retryAfterMs: details.blockedUntil - now,
        bases: [BLOCK_BASES.EXISTING],
      });
    }

    const verdict = judge({
      fingerprint: details.fingerprint,
      entropy: details.entropy,
      budget: details.budget,
      cost: details.cost.cost,
      strikes: details.strikes,
      options: this.options,
    });

    const priced = Math.max(1, Math.round(details.cost.cost * verdict.priceMultiplier));
    const budget = await this.sharedStore.spend(
      key,
      priced,
      this.options.windowMs,
      this.options.limit,
      now
    );

    if (!budget.allowed) {
      const state = this.strikes(key, now);
      if (state.strikes >= this.options.strikesToBlock) {
        state.blockedUntil = now + this.options.blockMs;
        return this.decide(BLOCK, details, {
          reason: `budget exceeded ${this.options.strikesToBlock} times on a shared store (${budget.backend})`,
          status: 403,
          retryAfterMs: this.options.blockMs,
          bases: [BLOCK_BASES.BUDGET],
          extra: { strikes: state.strikes, priced, backend: budget.backend, degraded: budget.degraded },
        });
      }
      return this.decide(THROTTLE, details, {
        reason: `budget exhausted on a shared store (${budget.backend}): ${Math.round(budget.used)} of ${this.options.limit} cost used`,
        status: 429,
        retryAfterMs: budget.retryAfterMs,
        after: { used: budget.used, limit: this.options.limit },
        bases: [BLOCK_BASES.BUDGET],
        extra: { strikes: state.strikes, priced, backend: budget.backend, degraded: budget.degraded },
      });
    }

    if (verdict.verdict === 'challenge' && this.options.challenge) {
      this.challengedCount += 1;
      return this.decide(CHALLENGE, details, {
        reason: `${verdict.challengeBases.join(' + ')}`,
        status: 403,
        after: { used: budget.used, limit: this.options.limit },
        bases: verdict.challengeBases,
        extra: { backend: budget.backend },
      });
    }

    if (this.options.blockOnScan && entropyVerdict.isScan) {
      return this.decide(BLOCK, details, {
        reason: entropyVerdict.reason,
        status: 403,
        bases: [BLOCK_BASES.SCAN],
        extra: { entropy: entropyVerdict },
      });
    }

    return this.decide(ALLOW, details, {
      reason: `within budget on a shared store (${budget.backend}): ${Math.round(budget.used)} of ${this.options.limit} cost used`,
      status: 200,
      after: { used: budget.used, limit: this.options.limit },
      bases: [],
      extra: { backend: budget.backend, degraded: budget.degraded },
    });
  }

  /**
   * Record an excess and return the punishment state.
   *
   * @param {string} key
   * @param {number} now
   * @returns {{strikes: number, blockedUntil: number}}
   */
  strikes(key, now) {
    let state = this.punished.get(key);
    if (!state) {
      state = { strikes: 0, blockedUntil: 0 };
      this.punished.set(key, state);
    }
    // A block that has expired starts the count again rather than resuming it.
    if (state.blockedUntil > 0 && state.blockedUntil <= now) {
      state.strikes = 0;
      state.blockedUntil = 0;
    }
    state.strikes += 1;
    return state;
  }

  /**
   * Assemble a decision record.
   *
   * The record always carries `bases`: the independent reasons the decision was
   * made. An operator reading a 403 can check that at least one of them is
   * something a client cannot forge by setting a header.
   *
   * @param {string} action
   * @param {object} details
   * @param {object} extra
   * @returns {object}
   */
  decide(action, details, extra) {
    if (action === ALLOW) this.allowedCount += 1;
    else if (action === THROTTLE) this.throttledCount += 1;
    else if (action === BLOCK) this.blockedCount += 1;

    return Object.freeze({
      action,
      status: extra.status,
      reason: extra.reason,
      retryAfterMs: extra.retryAfterMs || 0,
      identity: details.identity,
      cost: details.cost,
      // The budget AFTER this request, not the snapshot taken before it.
      // Reading details.budget here would contradict the reason string, which
      // already carries the post-request figure.
      budget: extra.after,
      entropy: details.entropy,
      fingerprint: details.fingerprint,
      circuit: details.circuit,
      bases: extra.bases || [],
      address: details.address,
      details: Object.freeze({ ...details, ...(extra.extra || {}) }),
      at: this.now(),
    });
  }

  /**
   * Report an origin outcome to the circuit breaker.
   *
   * @param {boolean} ok
   * @returns {string} the resulting state
   */
  reportOrigin(ok) {
    return ok ? this.breaker.onSuccess(this.now()) : this.breaker.onFailure(this.now());
  }

  /**
   * Clear every trace of an identity.
   *
   * @param {string} address
   * @returns {boolean}
   */
  forgive(address) {
    let key;
    try {
      key = identityOf(address, this.options).normalized;
    } catch {
      return false;
    }
    const a = this.window.reset(key);
    const b = this.entropy.reset(key);
    const c = this.punished.delete(key);
    return a || b || c;
  }

  /**
   * Drop idle state so a long-running process does not leak memory.
   *
   * With a shared store this is asynchronous, because cleaning a shared store
   * is a network round trip. `removed.store` is then a Promise; the rest of the
   * counters are local and are returned immediately. Callers that sweep on an
   * interval should await it:
   *
   *     const removed = await guard.sweep();
   *     metrics.gauge('siege_guard.keys_removed', removed.store);
   *
   * @returns {Promise<object>|object} see the note above
   */
  sweep() {
    const now = this.now();
    const removed = { window: this.window.sweep(now), entropy: 0, punished: 0, store: null };
    for (const [key, state] of this.punished) {
      if (state.blockedUntil !== 0 && state.blockedUntil <= now) {
        this.punished.delete(key);
        removed.punished += 1;
      }
    }
    if (this.sharedStore) {
      // Normalised to a Promise either way, so callers need one code path.
      removed.store = Promise.resolve(this.sharedStore.sweep(now));
    }
    return removed;
  }

  /**
   * Everything an operator needs to understand current state.
   *
   * @returns {object}
   */
  report() {
    const now = this.now();
    return Object.freeze({
      at: now,
      decisions: this.decisionCount,
      allowed: this.allowedCount,
      throttled: this.throttledCount,
      challenged: this.challengedCount,
      blocked: this.blockedCount,
      circuit: this.breaker.snapshot(now),
      window: this.window.snapshot(now),
      identities: this.punished.size,
      /**
       * Whether the budget is shared. "in-process" means every instance keeps
       * its own counter, so N instances give an attacker N budgets. Callers that
       * alert on this should refuse to pretend the limit is global until it is.
       */
      budgetScope: this.sharedStore ? 'shared' : 'in-process',
      instances: this.sharedStore ? null : 1,
      options: this.options,
    });
  }
}

module.exports = Object.freeze({
  SiegeGuard,
  createGuard: (options) => new SiegeGuard(options),
  ALLOW,
  THROTTLE,
  CHALLENGE,
  BLOCK,
  DEFAULTS,
  renderDecision,
  renderReport,
});