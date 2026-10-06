'use strict';

/**
 * Cost-weighted sliding window budget.
 *
 * ## Why sliding and not fixed
 *
 * The textbook limiter is a fixed window: "at most N requests per 60 seconds".
 * It is trivially defeated at the boundary. With N = 300 per minute, a client
 * sends 300 requests in the last second of minute 1 and 300 in the first second
 * of minute 2, and has made 600 requests in about two seconds while never
 * violating the rule as written. Two adjacent windows each held exactly the
 * limit.
 *
 * The fix is to stop counting in whole windows. Keep two adjacent buckets and
 * interpolate: the portion of the older bucket that still falls inside the
 * window is counted fractionally, and the newer bucket is counted in full.
 * The count then moves continuously instead of jumping, so a boundary burst
 * lands on a non-zero fraction of the previous bucket and cannot exceed the
 * limit.
 *
 * ## Costs, not counts
 *
 * Requests are not equal. A static asset costs a little CPU; an authenticated
 * database write costs a lot. Counting both as 1 lets an attacker drain the
 * server with cheap requests while the limiter believes it admitted a trickle.
 * The budget here is in COST units, and each route class contributes its own
 * cost, so the account is spent in proportion to the work actually requested.
 *
 * ## Clock going backwards
 *
 * NTP steps and manual clock changes happen. If elapsed time went negative, the
 * intuitive computation hands out free quota: the older bucket gains weight
 * instead of losing it, and a client that keeps requesting through a backwards
 * step receives an unbounded burst. Negative elapsed time is therefore clamped
 * to zero, which is strictly the safer direction.
 */

const DEFAULT_WINDOW_MS = 60_000;
const DEFAULT_LIMIT = 1000;
/** Guard against a huge cost argument emptying the budget of every client. */
const MAX_COST = 1e9;

/**
 * One time bucket of accumulated cost.
 */
class Bucket {
  /**
   * @param {number} index
   * @param {number} cost
   */
  constructor(index, cost) {
    this.index = index;
    this.cost = cost;
  }
}

/**
 * A sliding-window cost budget for many keys at once.
 */
class SlidingWindow {
  /**
   * @param {object} [options]
   * @param {number} [options.windowMs=60000] width of the window
   * @param {number} [options.limit=1000] budget in cost units per window
   */
  constructor(options = {}) {
    const windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;
    const limit = options.limit ?? DEFAULT_LIMIT;
    if (!Number.isFinite(windowMs) || windowMs <= 0) {
      throw new RangeError(`windowMs must be a positive number, got ${windowMs}`);
    }
    if (!Number.isFinite(limit) || limit <= 0) {
      throw new RangeError(`limit must be a positive number, got ${limit}`);
    }
    this.windowMs = windowMs;
    this.limit = limit;
    /** @type {Map<string, {older: Bucket|null, newer: Bucket|null}>} */
    this.keys = new Map();
    this.now = options.now ?? Date.now;
  }

  /**
   * Current cost in the window for a key.
   *
   * @param {string} key
   * @param {number} [now=this.now()]
   * @returns {number}
   */
  used(key, now = this.now()) {
    const state = this.keys.get(key);
    if (!state) return 0;
    return this.weighted(state, now).cost;
  }

  /**
   * Interpolate the two buckets into a single cost.
   *
   * The buckets returned alongside the cost are the ones the cost was computed
   * from, already pruned of anything that has slid out of the window. Callers
   * that reason about the individual buckets (consume()'s retry calculation)
   * must use these rather than reading state.older/state.newer directly, or
   * they reason about buckets that this method has just discarded.
   *
   * @param {{older: Bucket|null, newer: Bucket|null}} state
   * @param {number} now
   * @returns {{cost: number, olderWeight: number, older: Bucket|null,
   *            newer: Bucket|null}}
   */
  weighted(state, now) {
    const index = Math.floor(now / this.windowMs);
    let older = state.older;
    let newer = state.newer;

    // Drop buckets that have slid entirely out of the window.
    if (older && older.index < index - 1) older = null;
    if (newer && newer.index < index) {
      older = newer;
      newer = null;
    }
    if (!older || older.index !== index - 1) older = null;
    if (!newer || newer.index !== index) newer = null;

    const elapsed = now - index * this.windowMs;
    // Negative elapsed time can only come from a clock step. Clamp to zero so
    // the older bucket loses weight instead of gaining it.
    const fraction = elapsed < 0 ? 0 : Math.min(1, elapsed / this.windowMs);

    const cost =
      (older ? older.cost * (1 - fraction) : 0) + (newer ? newer.cost : 0);
    return { cost, olderWeight: 1 - fraction, older, newer };
  }

  /**
   * Try to spend cost from a key's budget.
   *
   * A request is either fully admitted or fully rejected. Partial admission
   * would mean serving a truncated response, which is worse than a 429.
   *
   * @param {string} key rate-limit identity
   * @param {number} cost units to spend
   * @param {number} [now=this.now()]
   * @returns {{allowed: boolean, used: number, remaining: number,
   *            retryAfterMs: number, reason: string}}
   */
  consume(key, cost = 1, now = this.now()) {
    const spend = Number.isFinite(cost) && cost > 0 ? Math.min(cost, MAX_COST) : 1;
    const index = Math.floor(now / this.windowMs);

    let state = this.keys.get(key);
    if (!state) {
      state = { older: null, newer: new Bucket(index, 0) };
      this.keys.set(key, state);
    }

    const { cost: current, olderWeight, older, newer } = this.weighted(state, now);
    const projected = current + spend;

    if (projected > this.limit) {
      // How long until this request fits? The cost curve is piecewise linear in
      // time, so the answer is found in at most two phases.
      //
      // cost(t) = older.cost * (1 - (t - index*W)/W) + newer.cost
      //   for the rest of this window: the older bucket keeps decaying while the
      //   newer one is charged in full.
      // cost(t) = newer.cost * (1 - (t - (index+1)*W)/W)
      //   once the window rolls over: the newer bucket becomes the older one and
      //   decays over a FULL window, not the remainder of the current one.
      // cost(t) = 0 afterwards.
      //
      // The buckets used are the ones `current` was computed from, not the raw
      // fields on `state`: weighted() discards buckets that have slid out of
      // the window without touching state, so reading state here would reason
      // about cost this request is not being charged for.
      const newerCost = newer ? newer.cost : 0;
      const olderCost = older ? older.cost : 0;
      const startOfNextWindow = (index + 1) * this.windowMs;
      let waitMs;

      if (olderCost > 0 && this.limit - newerCost - spend >= 0) {
        // Phase 1: enough of the older bucket falls out before the roll-over
        // that the request already fits.
        const maxWeight = (this.limit - newerCost - spend) / olderCost;
        waitMs = Math.ceil(this.windowMs * (olderWeight - maxWeight));
      } else if (newerCost > 0 && spend <= this.limit) {
        // Phase 2: the newer bucket has to decay on its own, which takes up to
        // a whole window past the roll-over.
        const weightNeeded = Math.max(0, 1 - (this.limit - spend) / newerCost);
        waitMs = Math.ceil(startOfNextWindow - now + weightNeeded * this.windowMs);
      } else {
        // The request on its own costs more than the whole budget, so no amount
        // of waiting makes room for it. Report when the window rolls over,
        // which is the soonest the state could possibly change.
        waitMs = Math.ceil(startOfNextWindow - now);
      }
      return {
        allowed: false,
        used: current,
        remaining: Math.max(0, this.limit - current),
        retryAfterMs: Math.max(1, waitMs),
        reason: 'budget-exhausted',
      };
    }

    // Accepted: write the cost into the current bucket.
    if (!state.newer || state.newer.index !== index) {
      state.older = state.newer && state.newer.index === index - 1 ? state.newer : null;
      state.newer = new Bucket(index, 0);
    }
    state.newer.cost += spend;

    return {
      allowed: true,
      used: current + spend,
      remaining: Math.max(0, this.limit - (current + spend)),
      retryAfterMs: 0,
      reason: 'within-budget',
    };
  }

  /**
   * Forget a key entirely. Use on sign-out or on a confirmed ban.
   *
   * @param {string} key
   * @returns {boolean} true when a key was actually removed
   */
  reset(key) {
    return this.keys.delete(key);
  }

  /**
   * Drop keys whose window is entirely empty of activity.
   *
   * Without this a long-running server accumulates one entry per client
   * address forever, which is a memory leak that looks like a slow DoS.
   *
   * @param {number} [now=this.now()]
   * @param {number} [idleWindows=2] keep a key this many windows after its
   *   last activity
   * @returns {number} keys removed
   */
  sweep(now = this.now(), idleWindows = 2) {
    const index = Math.floor(now / this.windowMs);
    const cutoff = index - idleWindows;
    let removed = 0;
    for (const [key, state] of this.keys) {
      const newest = state.newer ? state.newer.index : state.older ? state.older.index : -1;
      if (newest < cutoff) {
        this.keys.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  /**
   * Snapshot of current state, for `explain` and for diagnostics.
   *
   * @param {number} [now=this.now()]
   * @returns {{keys: number, windowMs: number, limit: number, entries: object[]}}
   */
  snapshot(now = this.now()) {
    const entries = [];
    for (const [key, state] of this.keys) {
      const { cost, olderWeight } = this.weighted(state, now);
      entries.push({
        key,
        used: cost,
        remaining: Math.max(0, this.limit - cost),
        ratio: this.limit > 0 ? cost / this.limit : 0,
        olderWeight,
      });
    }
    entries.sort((a, b) => b.used - a.used);
    return {
      keys: this.keys.size,
      windowMs: this.windowMs,
      limit: this.limit,
      entries,
    };
  }
}

module.exports = Object.freeze({
  SlidingWindow,
  Bucket,
  DEFAULT_WINDOW_MS,
  DEFAULT_LIMIT,
  MAX_COST,
});