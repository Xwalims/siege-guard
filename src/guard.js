'use strict';

/**
 * The guard: the single place where a request becomes a decision.
 *
 * Every decision carries a structured reason. A DoS defence that cannot explain
 * why it denied something is a DoS defence that gets turned off during an
 * incident -- usually by someone who cannot work out whether it is broken or
 * working.
 */

const { SlidingWindow } = require('./window.js');
const { identityOf } = require('./identity.js');
const { classify } = require('./cost.js');
const { PathEntropyTracker } = require('./entropy.js');
const { fingerprint } = require('./signals.js');
const { CircuitBreaker } = require('./circuit.js');
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
  /** A client may never cost more than this fraction of the budget in one window. */
  /** A single request costing more than the whole budget is rejected outright. */
  maxCostPerRequest: 0,
  /** Bot-likelihood at or above this is refused without spending budget. */
  blockScore: 0.6,
  /** Bot-likelihood at or above this is challenged when a challenge is wired. */
  challengeScore: 0.35,
  /** Path-entropy verdict that leads to a block rather than a throttle. */
  blockOnScan: false,
  /** Times an identity may exceed its budget before it is blocked outright. */
  strikesToBlock: 3,
  /** How long a block lasts. */
  blockMs: 300_000,
  behindProxy: false,
  challenge: null,
  enabled: true,
});

class SiegeGuard {
  /**
   * @param {object} [options] see {@link DEFAULTS}
   * @param {number} [options.now] fixed clock, for tests and simulations
   * @param {object} [options.costs] cost table override
   * @param {object} [options.breaker] circuit breaker options
   */
  constructor(options = {}) {
    this.options = Object.freeze({ ...DEFAULTS, ...options });
    const clock =
      typeof options.now === 'function' ? options.now
      : typeof options.now === 'number' ? () => options.now
      : Date.now;
    this.now = clock;

    this.window = new SlidingWindow({
      windowMs: this.options.windowMs,
      limit: this.options.limit,
      now: clock,
    });
    this.entropy = new PathEntropyTracker(options.entropy || {});
    this.breaker = new CircuitBreaker({ ...(options.breaker || {}), now: clock });

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
   * @returns {{identity: object, cost: object, entropy: object, fingerprint: object,
   *            circuit: object, strikes: number, blockedUntil: number}}
   */
  inspect(req) {
    const identity = this.resolveIdentity(req);
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
   * Work out who a request came from.
   *
   * A request with no usable address, or one carrying an address this package
   * cannot parse, must not crash the guard: a defence that throws on malformed
   * input is an outage waiting for a stranger to find. Such a request is given
   * its own single identity, so it still spends a budget and cannot flood by
   * being unparseable, but it cannot be attributed to anyone either.
   *
   * @param {object} req
   * @returns {object} an identity record
   */
  resolveIdentity(req) {
    const address =
      (req.socket && req.socket.remoteAddress) ||
      (req.connection && req.connection.remoteAddress) ||
      req.remoteAddress ||
      req.ip;
    const options = {
      ipv6Prefix: this.options.ipv6Prefix,
      ipv4Prefix: this.options.ipv4Prefix,
    };
    try {
      return identityOf(address, options);
    } catch {
      return Object.freeze({
        raw: address === undefined || address === null ? '' : String(address),
        normalized: `unattributed:${address === undefined ? 'no-address' : String(address)}`,
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
   * The order is deliberate: circuit first, then an existing block, then
   * fingerprinting, then the budget, then the scan verdict. Cheap and decisive
   * checks come before expensive ones, so an attack that trips the breaker never
   * reaches the arithmetic.
   *
   * @param {object} req
   * @param {object} [options]
   * @param {boolean} [options.record=true] observe the path for entropy
   * @returns {{action: string, reason: string, status: number, identity: object,
   *            cost: object, signals: string[], retryAfterMs: number,
   *            details: object}}
   */
  check(req, options = {}) {
    const now = this.now();
    this.decisionCount += 1;
    const details = this.inspect(req);
    const { identity } = details;
    const key = identity.normalized;

    // 1. The origin is failing; do not add load.
    if (!details.circuit.allow) {
      return this.decide(BLOCK, details, {
        reason: `origin circuit is ${details.circuit.state}: ${details.circuit.reason}`,
        status: 503,
        retryAfterMs: this.breaker.snapshot(now).cooldownRemainingMs,
      });
    }

    // 2. A previous excess already earned a block.
    if (details.blockedUntil > now) {
      return this.decide(BLOCK, details, {
        reason: `blocked for another ${Math.ceil((details.blockedUntil - now) / 1000)}s after ${details.strikes} strikes`,
        status: 403,
        retryAfterMs: details.blockedUntil - now,
      });
    }

    // 3. Clear enough to be a scanner; refuse without spending budget.
    if (details.fingerprint.score >= this.options.blockScore) {
      return this.decide(BLOCK, details, {
        reason: `client fingerprint ${details.fingerprint.score.toFixed(2)} >= ${this.options.blockScore}: ${details.fingerprint.reason}`,
        status: 403,
      });
    }

    // 4. Suspicious but not certain: make it prove itself, if a way exists.
    if (
      this.options.challenge &&
      details.fingerprint.score >= this.options.challengeScore
    ) {
      this.challengedCount += 1;
      return this.decide(CHALLENGE, details, {
        reason: `challenge: fingerprint ${details.fingerprint.score.toFixed(2)} >= ${this.options.challengeScore}`,
        status: 403,
      });
    }

    // 5. Spend the budget.
    const maxCost =
      this.options.maxCostPerRequest > 0 ? this.options.maxCostPerRequest : Infinity;
    if (details.cost.cost > maxCost) {
      return this.decide(BLOCK, details, {
        reason: `request costs ${details.cost.cost}, above the per-request ceiling ${maxCost}`,
        status: 403,
      });
    }

    const budget = this.window.consume(key, details.cost.cost, now);
    if (!budget.allowed) {
      const state = this.strikes(key, now);
      const overLimit = state.strikes >= this.options.strikesToBlock;
      if (overLimit) {
        state.blockedUntil = now + this.options.blockMs;
        return this.decide(BLOCK, details, {
          reason: `budget exceeded ${this.options.strikesToBlock} times: used ${Math.round(budget.used)} of ${this.options.limit} cost`,
          status: 403,
          retryAfterMs: this.options.blockMs,
          extra: { strikes: state.strikes },
        });
      }
      return this.decide(THROTTLE, details, {
        reason: `budget exhausted: ${Math.round(budget.used)} of ${this.options.limit} cost used, ${details.cost.cost} requested`,
        status: 429,
        retryAfterMs: budget.retryAfterMs,
        after: { used: budget.used, limit: this.options.limit },
        extra: { strikes: state.strikes },
      });
    }

    // 6. Budget is fine: only now does the scan verdict matter, and it can only
    // downgrade an allowance to a block when the operator asked for that.
    if (options.record !== false) {
      const verdict = this.entropy.observe(key, String(req.url || '/').split('?')[0]);
      if (this.options.blockOnScan && verdict.isScan) {
        return this.decide(BLOCK, details, {
          reason: verdict.reason,
          status: 403,
          extra: { entropy: verdict },
        });
      }
    }

    return this.decide(ALLOW, details, {
      reason: `within budget: ${Math.round(budget.used)} of ${this.options.limit} cost used`,
      status: 200,
      after: { used: budget.used, limit: this.options.limit },
      extra: { retryAfterMs: 0 },
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
   * @param {string} action
   * @param {object} details
   * @param {object} extra
   * @returns {object}
   */
  decide(action, details, extra) {
    if (action === ALLOW) this.allowedCount += 1;
    else if (action === THROTTLE) this.throttledCount += 1;
    else if (action === BLOCK) this.blockedCount += 1;

    if (extra.status === 200 || extra.status === 429) {
      // The budget AFTER this request, not the snapshot taken before it.
      // Reading details.budget here would contradict the reason string, which
      // already carries the post-request figure.
      const after = extra.after;
      if (after) {
        return Object.freeze({
          action,
          status: extra.status,
          reason: extra.reason,
          retryAfterMs: extra.retryAfterMs || 0,
          identity: details.identity,
          cost: details.cost,
          budget: after,
          entropy: details.entropy,
          fingerprint: details.fingerprint,
          circuit: details.circuit,
          signals: extra.extra ? Object.keys(extra.extra) : [],
          details: Object.freeze({ ...details, ...(extra.extra || {}) }),
          at: this.now(),
        });
      }
    }
    return Object.freeze({
      action,
      status: extra.status,
      reason: extra.reason,
      retryAfterMs: extra.retryAfterMs || 0,
      identity: details.identity,
      cost: details.cost,
      entropy: details.entropy,
      fingerprint: details.fingerprint,
      circuit: details.circuit,
      signals: extra.extra ? Object.keys(extra.extra) : [],
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
   * @returns {{window: number, entropy: number, punished: number}}
   */
  sweep() {
    const now = this.now();
    const removed = { window: this.window.sweep(now), entropy: 0, punished: 0 };
    for (const [key, state] of this.punished) {
      if (state.blockedUntil !== 0 && state.blockedUntil <= now) {
        this.punished.delete(key);
        removed.punished += 1;
      }
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