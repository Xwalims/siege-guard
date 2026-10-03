'use strict';

/**
 * Explaining decisions.
 *
 * Two functions: one renders a single decision, one renders the whole state.
 * Both exist for the same reason -- a denial nobody can interpret becomes an
 * outage nobody is willing to keep.
 */

/**
 * Render one decision as plain text.
 *
 * @param {object} decision as returned by SiegeGuard#check
 * @returns {string}
 */
function renderDecision(decision) {
  if (!decision || !decision.action) {
    return 'not a decision record';
  }
  const lines = [];
  const d = decision;
  // Every field is optional. This function renders records that arrived over a
  // pipe from another process, and a diagnostic tool that crashes on a partial
  // record is worse than useless exactly when it is needed.
  const identity = d.identity || {};
  const who = identity.normalized || identity.raw || 'unknown';
  lines.push(`${String(d.action).toUpperCase()}  ${who}${d.status ? `  (${d.status})` : ''}`);
  lines.push(`  why      ${d.reason === undefined ? 'no reason recorded' : d.reason}`);
  if (Array.isArray(d.bases) && d.bases.length > 0) {
    lines.push(`  basis    ${d.bases.join(' + ')}`);
  }

  const used = d.budget || (d.details && d.details.budget);
  if (used) {
    lines.push(
      `  budget   ${Math.round(used.used)} of ${used.limit} cost used` +
        `  ${used.limit > 0 ? `(${Math.round((used.used / used.limit) * 100)}%)` : ''}`
    );
  }
  if (d.cost && typeof d.cost.cost === 'number') {
    lines.push(`  request  ${d.cost.cost} cost  (${d.cost.class || 'unknown'}: ${d.cost.reason || ''})`);
  }
  if (d.fingerprint && typeof d.fingerprint.score === 'number') {
    lines.push(
      `  client   score ${d.fingerprint.score.toFixed(2)}  ${d.fingerprint.reason || ''}`
    );
  }
  if (d.entropy && typeof d.entropy.samples === 'number') {
    const e = d.entropy;
    if (e.samples > 0 && typeof e.entropy === 'number') {
      lines.push(
        `  paths    entropy ${e.entropy.toFixed(2)}, novelty ${e.novelty.toFixed(2)}, ${e.samples} distinct`
      );
    }
  }
  if (d.identity && typeof d.identity.prefix === 'number') {
    lines.push(
      `  identity ${d.identity.family === 6 ? 'IPv6' : 'IPv4'} /${d.identity.prefix}` +
        `  covers ${d.identity.subnetSize || '?'} address(es)` +
        `${d.identity.mapped ? '  (IPv4-mapped, unwrapped)' : ''}`
    );
  }
  if (typeof d.retryAfterMs === 'number' && d.retryAfterMs > 0) {
    lines.push(`  retry    after ${Math.ceil(d.retryAfterMs / 1000)}s`);
  }
  if (d.circuit && d.circuit.state && d.circuit.state !== 'closed') {
    lines.push(`  circuit  ${d.circuit.state}: ${d.circuit.reason}`);
  }
  return lines.join('\n');
}

/**
 * Render the whole guard state as plain text.
 *
 * @param {object} report as returned by SiegeGuard#report
 * @returns {string}
 */
function renderReport(report) {
  const lines = [];
  lines.push('siege-guard state');
  lines.push('==================');
  const total = report.decisions || 0;
  const pct = (n) => (total > 0 ? `${Math.round((n / total) * 100)}%` : 'n/a');
  lines.push(`decisions   ${total}`);
  lines.push(`  allowed   ${report.allowed}  (${pct(report.allowed)})`);
  lines.push(`  throttled ${report.throttled}  (${pct(report.throttled)})`);
  lines.push(`  challenged${String(report.challenged).padStart(2)}  (${pct(report.challenged)})`);
  lines.push(`  blocked   ${report.blocked}  (${pct(report.blocked)})`);
  lines.push('');
  lines.push(
    `circuit     ${report.circuit.state}` +
      `  failures ${report.circuit.failures}/${report.circuit.samples}` +
      `  ratio ${report.circuit.ratio.toFixed(2)}`
  );
  lines.push(
    `budget      limit ${report.window.limit} cost per ${report.window.windowMs}ms,` +
      ` ${report.window.keys} identit(y|ies) tracked`
  );
  const hot = report.window.entries.slice(0, 5);
  if (hot.length) {
    lines.push('');
    lines.push('hottest identities:');
    for (const e of hot) {
      lines.push(
        `  ${e.key.padEnd(24)} ${Math.round(e.used)}/${report.window.limit} cost` +
          `  ${Math.round(e.ratio * 100)}%`
      );
    }
  }
  return lines.join('\n');
}

module.exports = Object.freeze({ renderDecision, renderReport });