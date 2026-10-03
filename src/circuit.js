'use strict';

/**
 * Circuit breaker, so a failing origin is not hammered by retrying traffic.
 *
 * Without one, an origin that starts returning 500s attracts more traffic, not
 * less: every client retries, health checks pile on, and the retries consume
 * the capacity needed to recover. The breaker stops sending requests to a known
 * -bad origin and lets it breathe.
 *
 * States:
 *
 *   closed      normal operation; failures are counted
 *   open        the origin is failing; requests are refused without being sent
 *   half-open   after the cooldown, a limited number of probes are allowed
 *               through; one success closes the breaker, one failure re-opens it
 *
 * The half-open probe count matters. Letting unlimited traffic through while
 * probing means the moment the origin recovers it is immediately flooded, which
 * is the failure this is meant to prevent.
 */

/** Consecutive successful probes needed to close from half-open. */
const SUCCESSES_TO_CLOSE = 2;
/** Probe requests allowed while half-open. */
const HALF_OPEN_PROBES = 3;

/**
 * @param {object} [options]
 * @param {number} [options.failureRatio=0.5] fraction of failures that trips it
 * @param {number} [options.minSamples=20] samples before the ratio is trusted
 * @param {number} [options.windowMs=10000] sliding window of outcomes
 * @param {number} [options.cooldownMs=5000] how long open lasts
 */
class CircuitBreaker {
  constructor(options = {}) {
    this.failureRatio = options.failureRatio ?? 0.5;
    this.minSamples = options.minSamples ?? 20;
    this.windowMs = options.windowMs ?? 10_000;
    this.cooldownMs = options.cooldownMs ?? 5_000;
    this.now = options.now ?? Date.now;

    /** @type {'closed'|'open'|'half-open'} */
    this.state = 'closed';
    /** @type {Array<{at: number, ok: boolean}>} */
    this.outcomes = [];
    this.openedAt = 0;
    this.successesInHalfOpen = 0;
    this.probesInHalfOpen = 0;
  }

  /**
   * May a request be sent to the origin right now?
   *
   * @param {number} [now=this.now()]
   * @returns {{allow: boolean, state: string, reason: string}}
   */
  allow(now = this.now()) {
    if (this.state === 'closed') {
      return { allow: true, state: 'closed', reason: 'circuit closed' };
    }

    if (this.state === 'open') {
      if (now - this.openedAt < this.cooldownMs) {
        return {
          allow: false,
          state: 'open',
          reason: `circuit open, ${this.cooldownMs - (now - this.openedAt)}ms of cooldown left`,
        };
      }
      this.transitionTo('half-open');
    }

    if (this.probesInHalfOpen >= HALF_OPEN_PROBES) {
      return {
        allow: false,
        state: 'half-open',
        reason: 'probe budget spent, waiting for an outcome',
      };
    }
    this.probesInHalfOpen += 1;
    return { allow: true, state: 'half-open', reason: 'probe request' };
  }

  /**
   * Record a successful origin response.
   *
   * @param {number} [now=this.now()]
   * @returns {string} the resulting state
   */
  onSuccess(now = this.now()) {
    this.record(now, true);
    if (this.state === 'half-open') {
      this.successesInHalfOpen += 1;
      if (this.successesInHalfOpen >= SUCCESSES_TO_CLOSE) this.transitionTo('closed');
    }
    return this.state;
  }

  /**
   * Record a failed origin response.
   *
   * @param {number} [now=this.now()]
   * @returns {string} the resulting state
   */
  onFailure(now = this.now()) {
    this.record(now, false);
    if (this.state === 'half-open') {
      this.transitionTo('open', now);
    } else if (this.state === 'closed') {
      const stats = this.stats(now);
      if (stats.samples >= this.minSamples && stats.ratio >= this.failureRatio) {
        this.transitionTo('open', now);
      }
    }
    return this.state;
  }

  /**
   * Append an outcome and expire anything outside the window.
   *
   * @param {number} now
   * @param {boolean} ok
   */
  record(now, ok) {
    this.outcomes.push({ at: now, ok });
    const cutoff = now - this.windowMs;
    while (this.outcomes.length > 0 && this.outcomes[0].at < cutoff) {
      this.outcomes.shift();
    }
  }

  /**
   * Failure ratio over the current window.
   *
   * @param {number} [now=this.now()]
   * @returns {{samples: number, failures: number, ratio: number}}
   */
  stats(now = this.now()) {
    const cutoff = now - this.windowMs;
    let failures = 0;
    let samples = 0;
    for (const o of this.outcomes) {
      if (o.at >= cutoff) {
        samples += 1;
        if (!o.ok) failures += 1;
      }
    }
    return { samples, failures, ratio: samples > 0 ? failures / samples : 0 };
  }

  /**
   * Move to a new state, resetting the counters that state owns.
   *
   * @param {'closed'|'open'|'half-open'} next
   * @param {number} [now=this.now()]
   */
  transitionTo(next, now = this.now()) {
    this.state = next;
    if (next === 'open') {
      this.openedAt = now;
      this.successesInHalfOpen = 0;
      this.probesInHalfOpen = 0;
    } else if (next === 'half-open') {
      this.successesInHalfOpen = 0;
      this.probesInHalfOpen = 0;
    } else {
      this.outcomes = [];
      this.successesInHalfOpen = 0;
      this.probesInHalfOpen = 0;
      this.openedAt = 0;
    }
  }

  /**
   * Force the breaker closed, for an operator override.
   *
   * @param {number} [now=this.now()]
   */
  reset(now = this.now()) {
    this.transitionTo('closed', now);
  }

  /**
   * @param {number} [now=this.now()]
   * @returns {object}
   */
  snapshot(now = this.now()) {
    return {
      state: this.state,
      ...this.stats(now),
      cooldownRemainingMs:
        this.state === 'open' ? Math.max(0, this.cooldownMs - (now - this.openedAt)) : 0,
      probesInHalfOpen: this.probesInHalfOpen,
      successesInHalfOpen: this.successesInHalfOpen,
    };
  }
}

module.exports = Object.freeze({
  CircuitBreaker,
  SUCCESSES_TO_CLOSE,
  HALF_OPEN_PROBES,
});