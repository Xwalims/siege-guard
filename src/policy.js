'use strict';

/**
 * Combining signals so that no single forgeable one can convict.
 *
 * ## The problem this file exists to fix
 *
 * The first version of this package blocked a request outright when the HTTP
 * fingerprint score crossed a threshold. Every one of those signals is
 * forgeable: `python-requests` sets `User-Agent`, `Accept`, `Accept-Encoding`
 * and `Accept-Language` in one line, and adding `Sec-Fetch-Mode: navigate`
 * makes it indistinguishable from Chrome at the HTTP layer. So the rule was
 * "ban anyone who can make themselves look like a bot in under ten lines of
 * code", which is both trivially defeated and, worse, ban-happy against real
 * API clients that happen to send a sparse header set.
 *
 * ## What changed
 *
 * A fingerprint alone can no longer produce a BLOCK. It can produce:
 *
 * - a CHALLENGE, which is cheap and reversible, or
 * - a discount, so the client spends its budget faster, or
 * - a TALLY, which raises the price of the next violation.
 *
 * A BLOCK requires an *independent* signal: budget exhaustion, a circuit that is
 * open, or an operator's explicit allowlist of known bots. That is the difference
 * between "this looks automated" and "this is demonstrably over budget".
 *
 * The two are kept deliberately separate. Fingerprint describes the request's
 * shape; the budget describes what it consumed. Only the second is evidence.
 *
 * ## Weighting, honestly
 *
 * The score is not a probability. It is a sortable index of "how many
 * unforgeable-ish tells fired", used only to order requests and to decide whether
 * a challenge is worth it. Treating 0.77 as "77% probability of being a bot"
 * would be a lie, and a very expensive one: it would justify bans that the
 * following request contradicts.
 */

/** Reasons a decision can be a block. Only these justify a 403. */
const BLOCK_BASES = Object.freeze({
  CIRCUIT: 'circuit-open',
  BUDGET: 'budget-exceeded',
  CEILING: 'cost-ceiling',
  SCAN: 'scan-verdict',
  BLOCKLIST: 'operator-blocklist',
  EXISTING: 'previous-block',
});

/** Reasons a decision can be a challenge. Reversible, so forgeable signals fit. */
const CHALLENGE_BASES = Object.freeze({
  FINGERPRINT: 'fingerprint',
  NOVELTY: 'high-novelty',
});

/**
 * How much extra budget cost a fingerprint charges, as a multiplier.
 *
 * A suspicious client pays more, which means it exhausts its window sooner and
 * starts earning strikes on a path that leads to a legitimate BLOCK. The
 * evidence is still the budget; the fingerprint only accelerated the arrival.
 */
const DEFAULT_PRICE_MULTIPLIER = Object.freeze({
  /** Below challengeScore: no extra charge. */
  none: 1,
  /** At or above challengeScore: spend 1.5x. */
  suspicious: 1.5,
  /** At or above blockScore: spend 2x. Still not a ban on its own. */
  verySuspicious: 2,
});

/**
 * Judge one request from its fingerprint and, separately, from what it consumed.
 *
 * @param {object} input
 * @param {object} input.fingerprint result of signals.fingerprint()
 * @param {object} input.entropy result of the path entropy tracker
 * @param {object} input.budget {used, limit} after the request
 * @param {number} input.cost what the request was priced at
 * @param {number} input.strikes strikes the identity already holds
 * @param {object} [input.options] the guard options
 * @returns {{
 *   verdict: string, blockBases: string[], challengeBases: string[],
 *   priceMultiplier: number, reason: string, evidence: string
 * }}
 */
function judge(input) {
  const options = input.options || {};
  const score = (input.fingerprint && input.fingerprint.score) || 0;
  const challengeScore = options.challengeScore ?? 0.35;
  const blockScore = options.blockScore ?? 0.6;

  const challengeBases = [];
  const blockBases = [];

  // --- Reversible consequences. A forgeable signal may drive these. ---
  if (score >= challengeScore) challengeBases.push(CHALLENGE_BASES.FINGERPRINT);
  if (input.entropy && input.entropy.isScan) challengeBases.push(CHALLENGE_BASES.NOVELTY);

  let priceMultiplier = DEFAULT_PRICE_MULTIPLIER.none;
  if (score >= blockScore) priceMultiplier = DEFAULT_PRICE_MULTIPLIER.verySuspicious;
  else if (score >= challengeScore) priceMultiplier = DEFAULT_PRICE_MULTIPLIER.suspicious;

  // --- Irreversible consequences. These need evidence a forger cannot mint. ---
  const budget = input.budget || { used: 0, limit: 0 };
  const limit = budget.limit || options.limit || 0;
  const strikesToBlock = options.strikesToBlock ?? 3;

  if (limit > 0 && budget.used >= limit) blockBases.push(BLOCK_BASES.BUDGET);
  if (options.maxCostPerRequest > 0 && input.cost > options.maxCostPerRequest) {
    blockBases.push(BLOCK_BASES.CEILING);
  }
  if (input.strikes >= strikesToBlock) blockBases.push(BLOCK_BASES.BUDGET);
  if (options.blockOnScan && input.entropy && input.entropy.isScan) {
    blockBases.push(BLOCK_BASES.SCAN);
  }

  // The invariant, enforced rather than asserted in a comment. A block may only
  // ever rest on a basis a client cannot manufacture by setting a header, or by
  // simply never repeating a path. Throwing here means a future edit that adds a
  // forgeable basis fails loudly in development instead of quietly banning honest
  // clients in production.
  const forbidden = blockBases.filter((b) => NON_CONVICTING.has(b));
  if (forbidden.length > 0) {
    throw new Error(
      `refusing to block on evidence a client can forge: ${forbidden.join(', ')}`
    );
  }

  const evidence =
    blockBases.length > 0
      ? `${blockBases.join(' + ')}: spent ${Math.round(budget.used)} of ${limit} cost`
      : `no independent evidence of abuse (fingerprint ${score.toFixed(2)} alone is not evidence)`;

  return {
    verdict: blockBases.length > 0 ? 'block' : challengeBases.length > 0 ? 'challenge' : 'allow',
    blockBases,
    challengeBases,
    priceMultiplier,
    reason: evidence,
    evidence,
  };
}

/**
 * Whether a decision may be a hard block.
 *
 * Every basis a client can manufacture for free -- by setting a header, or by
 * simply never repeating a path -- is forbidden here. Note `every`, not `some`:
 * one real basis must not excuse a forged one riding along with it.
 *
 * The forbidden set is derived from CHALLENGE_BASES rather than typed out, so
 * adding a new challenge basis cannot silently become a ban.
 *
 * @param {string[]} blockBases
 * @returns {boolean}
 */
const NON_CONVICTING = new Set([
  CHALLENGE_BASES.FINGERPRINT,
  CHALLENGE_BASES.NOVELTY,
]);

function mayBlock(blockBases) {
  if (!Array.isArray(blockBases) || blockBases.length === 0) return false;
  return blockBases.every((b) => !NON_CONVICTING.has(b));
}

module.exports = Object.freeze({
  judge,
  mayBlock,
  BLOCK_BASES,
  CHALLENGE_BASES,
  DEFAULT_PRICE_MULTIPLIER,
});