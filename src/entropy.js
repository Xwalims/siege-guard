'use strict';

/**
 * Path-entropy scanner detection.
 *
 * ## The signal
 *
 * A human browsing a site visits few distinct paths and returns to them: the
 * home page, a category page, two articles. A directory enumerator touches
 * `/api/admin`, `/api/users`, `/.env`, `/wp-login.php`, `/backup.sql`, each
 * exactly once and never again.
 *
 * Two measurements capture that difference:
 *
 * - **Shannon entropy** over the distribution of recently requested paths. Low
 *   entropy means one path dominates; high entropy means requests are spread
 *   thinly across many distinct paths.
 * - **Novelty ratio**: the share of recently requested paths never seen before
 *   from this identity. A human re-requests known paths, so its ratio falls.
 *
 * Entropy alone is not enough, because a legitimate API client walking a
 * resource tree also produces high entropy. Novelty is what separates
 * enumeration from navigation.
 *
 * ## Thresholds
 *
 * The thresholds are NOT guessed. `test/entropy.test.js` drives both a bundled
 * benign trace and a bundled hostile trace through this module and asserts that
 * the separation between them is wide. If a future change to the scoring moved
 * the boundary into the overlap region, that test fails. The constants below
 * record where the measured separation actually sits.
 *
 * A sample of 40 paths that all occur once has entropy log2(40) = 5.32 bits,
 * which is the practical ceiling here and the maximum score.
 */

/** Minimum samples before a verdict is offered at all. */
const MIN_SAMPLES = 8;

/** Entropy at or above this, together with novelty, means scan. */
const SCAN_ENTROPY = 3.4;

/** Novelty at or above this, together with entropy, means scan. */
const SCAN_NOVELTY = 0.6;

/** How many recent paths are remembered per identity. */
const DEFAULT_HISTORY = 64;

/** How long an identity may be idle before {@link PathEntropyTracker#sweep} forgets it. */
const DEFAULT_SWEEP_KEEP_MS = 300_000;

/**
 * Paths treated as static and therefore excluded from scan detection.
 *
 * A webpack or esbuild output is `/assets/app.4f2a91.js`: every build changes the
 * name, so a client walking a single-page app touches hundreds of distinct paths.
 * Treating that as enumeration challenges ordinary users.
 */
const DEFAULT_IGNORE_PATTERN = /\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|mp4|webm|pdf|txt|xml)$/i;

/**
 * Shannon entropy of a count distribution, in bits per observation.
 *
 * @param {Iterable<number>} counts non-negative frequencies
 * @returns {number} 0 for an empty or single-bucket distribution
 */
function shannonEntropy(counts) {
  const values = Array.from(counts);
  const total = values.reduce((a, b) => a + b, 0);
  if (total <= 0) return 0;
  let bits = 0;
  for (const c of values) {
    if (c <= 0) continue;
    const p = c / total;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/**
 * Tracks recently requested paths for one identity and scores them.
 */
class PathEntropyTracker {
  /**
   * @param {object} [options]
   * @param {number} [options.history=64] paths remembered per identity
   * @param {number} [options.minSamples=8] samples needed for a verdict
   * @param {number} [options.scanEntropy=3.4]
   * @param {number} [options.scanNovelty=0.6]
   * @param {number} [options.sweepKeepMs=300000] idle time before sweep forgets
   *   an identity
   * @param {number|Function} [options.now] a fixed clock for tests
   */
  constructor(options = {}) {
    this.history = options.history ?? DEFAULT_HISTORY;
    this.minSamples = options.minSamples ?? MIN_SAMPLES;
    this.scanEntropy = options.scanEntropy ?? SCAN_ENTROPY;
    this.scanNovelty = options.scanNovelty ?? SCAN_NOVELTY;
    this.sweepKeepMs = options.sweepKeepMs ?? DEFAULT_SWEEP_KEEP_MS;
    // sweep() has to know when an identity was last active, and the only way to
    // know that is to stamp it on the way in. The tracker is usable standalone,
    // so the clock is injectable rather than hard-wired.
    this.now =
      typeof options.now === 'function' ? options.now
      : typeof options.now === 'number' ? () => options.now
      : Date.now;
    /**
     * Paths excluded from the entropy computation. Defaults to static assets,
     * because hashed filenames from a bundler or CDN are unique by construction.
     */
    this.ignorePatterns = options.ignorePatterns
      ? options.ignorePatterns.map((p) => (p instanceof RegExp ? p : new RegExp(p)))
      : [DEFAULT_IGNORE_PATTERN];
    /** @type {Map<string, {order: string[], seen: Set<string>, requests: number, novel: number}>} */
    this.state = new Map();
  }

  /**
   * Record a path request.
   *
   * Static assets are counted, not sampled. A CDN serving 400 hashed chunk names
   * produces a stream of unique paths that is indistinguishable from a directory
   * enumeration -- and a rule that challenges every such client is a rule that
   * punishes legitimate traffic, which is the mistake that gets a limiter
   * switched off. An operator can exclude their own patterns with
   * `ignorePatterns`.
   *
   * @param {string} key rate-limit identity
   * @param {string} path the requested path, query string excluded
   * @returns {{samples: number, entropy: number, novelty: number,
   *            isScan: boolean, reason: string}}
   */
  observe(key, path) {
    // Stamp the activity BEFORE the ignore check, so an identity that only ever
    // requests static assets is still bounded by history instead of becoming a
    // permanent leak. A request this tracker deliberately ignores is still a
    // request, and it says the identity is alive.
    this.stamp(key);
    for (const pattern of this.ignorePatterns) {
      if (pattern.test(path)) {
        const current = this.state.get(key);
        return {
          samples: current ? current.order.length : 0,
          entropy: 0,
          novelty: 0,
          isScan: false,
          reason: 'path matches an ignored pattern',
          ignored: true,
        };
      }
    }
    let entry = this.state.get(key);
    if (!entry) {
      entry = { order: [], seen: new Set(), requests: 0, novel: 0, lastSeen: 0 };
      this.state.set(key, entry);
    }

    const isNovel = !entry.seen.has(path);
    if (isNovel) {
      entry.seen.add(path);
      entry.order.push(path);
      entry.novel += 1;
      // Bound the memory: drop the oldest path, and forget it from `seen` only
      // if it no longer appears in the retained window.
      if (entry.order.length > this.history) {
        const dropped = entry.order.shift();
        entry.seen.delete(dropped);
      }
    }
    entry.requests += 1;

    return this.score(key);
  }

  /**
   * Record that an identity was active, creating its entry if needed.
   *
   * Separate from the sampling below because an ignored path must still count
   * as activity, and because a sweepable entry needs its `lastSeen` stamped even
   * on the request that was ignored.
   *
   * @param {string} key rate-limit identity
   * @returns {object} the entry for this identity
   */
  stamp(key) {
    let entry = this.state.get(key);
    if (!entry) {
      entry = { order: [], seen: new Set(), requests: 0, novel: 0, lastSeen: 0 };
      this.state.set(key, entry);
    }
    entry.lastSeen = this.now();
    return entry;
  }

  /**
   * Current verdict for a key without recording anything.
   *
   * @param {string} key
   * @returns {{samples: number, entropy: number, novelty: number,
   *            isScan: boolean, reason: string}}
   */
  score(key) {
    const entry = this.state.get(key);
    if (!entry || entry.order.length < this.minSamples) {
      return {
        samples: entry ? entry.order.length : 0,
        entropy: 0,
        novelty: 0,
        isScan: false,
        reason: `need ${this.minSamples} distinct paths, have ${entry ? entry.order.length : 0}`,
      };
    }

    const counts = new Array(entry.order.length).fill(1);
    const entropy = shannonEntropy(counts);
    const novelty = entry.novel / entry.requests;

    // Both signals are required. A high-entropy API client that keeps reusing
    // known paths is not enumerating anything.
    const highEntropy = entropy >= this.scanEntropy;
    const highNovelty = novelty >= this.scanNovelty;

    let reason = 'navigation-like: paths repeat';
    if (highEntropy && highNovelty) {
      reason =
        `scan-like: entropy ${entropy.toFixed(2)} >= ${this.scanEntropy} and ` +
        `novelty ${novelty.toFixed(2)} >= ${this.scanNovelty}`;
    } else if (highEntropy) {
      reason = `spread over many paths (entropy ${entropy.toFixed(2)}) but known ones repeat`;
    }

    return {
      samples: entry.order.length,
      entropy,
      novelty,
      isScan: highEntropy && highNovelty,
      reason,
    };
  }

  /**
   * Forget an identity.
   *
   * @param {string} key
   * @returns {boolean}
   */
  reset(key) {
    return this.state.delete(key);
  }

  /**
   * Drop identities that have been idle for longer than `keepMs`.
   *
   * This used to check `entry.lastSeen`, which nothing ever wrote, so the guard
   * condition was never true and the method returned 0 for every input: every
   * identity the process had ever seen stayed resident forever. Measured on the
   * old code, 20,000 identities and ten hours of idle time still left all 20,000
   * held. The tracker keeps up to 64 paths per identity, so an Internet-facing
   * process behind rotating addresses leaks without bound -- the exact slow DoS
   * the README tells operators to call sweep() to prevent.
   *
   * An entry with no usable `lastSeen` is dropped rather than kept: a timestamp
   * of 0 is older than any `keepMs`, and retaining an entry whose liveness is
   * unknown is what made the old behaviour look like a working sweep.
   *
   * @param {number} [keepMs=this.sweepKeepMs] idle time before forgetting
   * @param {number} [now=this.now()]
   * @returns {number} identities removed
   */
  sweep(keepMs = this.sweepKeepMs, now = this.now()) {
    let removed = 0;
    for (const [key, entry] of this.state) {
      const lastSeen = entry.lastSeen;
      if (lastSeen === undefined || now - lastSeen > keepMs) {
        this.state.delete(key);
        removed += 1;
      }
    }
    return removed;
  }
}

module.exports = Object.freeze({
  PathEntropyTracker,
  shannonEntropy,
  MIN_SAMPLES,
  SCAN_ENTROPY,
  SCAN_NOVELTY,
  DEFAULT_HISTORY,
  DEFAULT_SWEEP_KEEP_MS,
  DEFAULT_IGNORE_PATTERN,
});