'use strict';

/**
 * Route cost classification.
 *
 * A rate limit that counts requests treats a cached stylesheet and a database
 * write as equal. They are not: one is a disk read the kernel may serve from
 * cache, the other is a transaction. Under attack the cheap path wins by
 * default, so a limiter counting requests in units of one lets a flood of
 * static requests through while the server burns its budget doing almost
 * nothing -- and a flood of writes through while it burns everything.
 *
 * So requests are priced, and the budget is spent in cost units.
 *
 * The defaults below are starting points, not truth. They are deliberately
 * round numbers so a deployment can multiply or divide them as one knob.
 */

/** Static asset served from disk or cache. */
const STATIC = 1;
/** Unauthenticated GET on a public endpoint. */
const API_READ = 5;
/** Authenticated GET, cheap database read. */
const API_READ_AUTHED = 15;
/** Write: POST, PUT, PATCH, DELETE. */
const API_WRITE = 50;
/** Login, password reset, token exchange: always expensive and always attacked. */
const AUTH = 100;

/**
 * Default cost per route class.
 */
const COSTS = Object.freeze({
  static: STATIC,
  apiRead: API_READ,
  apiReadAuthed: API_READ_AUTHED,
  apiWrite: API_WRITE,
  auth: AUTH,
});

/** Cost applied when nothing else matches, and to unknown route shapes. */
const DEFAULT_COST = API_READ;

/**
 * Classify a request and price it.
 *
 * Order matters: `/api/auth/login` is an auth route, not a write, even though
 * it is a POST. Checking the write rule first would price a credential-stuffing
 * flood at 50 instead of 100, understating it by half.
 *
 * @param {object} req a Node IncomingMessage, or anything with method/url/headers
 * @param {object} [options]
 * @param {Record<string, number>} [options.costs] override the cost table
 * @param {RegExp} [options.staticPattern] what counts as a static asset
 * @param {RegExp} [options.authPattern] what counts as an auth endpoint
 * @param {RegExp} [options.apiPattern] what counts as an API path
 * @param {boolean} [options.authenticated=false] is this request authenticated
 * @param {Array<{prefix: string, cost: number}>} [options.rules] explicit routes
 * @returns {{cost: number, class: string, reason: string}}
 */
function classify(req, options = {}) {
  const costs = { ...COSTS, ...(options.costs || {}) };
  const method = String(req.method || 'GET').toUpperCase();
  const url = String(req.url || '/');
  const path = url.split('?')[0];

  const staticPattern =
    options.staticPattern ||
    /\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|txt|xml|pdf|mp4|webp)$/i;
  const authPattern =
    options.authPattern || /\/(?:auth|login|logout|signin|signup|password|reset|token|session)/i;
  const apiPattern = options.apiPattern || /^\/api\//;

  // 1. Explicit rules win over every heuristic.
  for (const rule of options.rules || []) {
    if (path === rule.prefix || path.startsWith(rule.prefix)) {
      return {
        cost: rule.cost,
        class: 'rule',
        reason: `explicit rule for ${rule.prefix}`,
      };
    }
  }

  // 2. Auth endpoints before writes: a POST to /auth/login is AUTH, not a write.
  if (authPattern.test(path)) {
    return {
      cost: costs.auth,
      class: 'auth',
      reason: 'authentication endpoint: always expensive and always attacked',
    };
  }

  // 3. Static assets are the cheapest thing that can happen.
  if (staticPattern.test(path)) {
    return {
      cost: costs.static,
      class: 'static',
      reason: 'static asset',
    };
  }

  // 4. Anything that changes state.
  if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
    return {
      cost: costs.apiWrite,
      class: 'apiWrite',
      reason: `${method} changes state`,
    };
  }

  // 5. Reads: authenticated reads cost more than public ones.
  if (apiPattern.test(path) || path.startsWith('/v')) {
    const authenticated = Boolean(options.authenticated);
    return authenticated
      ? { cost: costs.apiReadAuthed, class: 'apiReadAuthed', reason: 'authenticated API read' }
      : { cost: costs.apiRead, class: 'apiRead', reason: 'public API read' };
  }

  return { cost: DEFAULT_COST, class: 'default', reason: 'unclassified path' };
}

/**
 * Cost of a whole trace, useful for explaining why a client was cut off.
 *
 * @param {Array<{method: string, url: string}>} requests
 * @param {object} [options] see {@link classify}
 * @returns {{total: number, byClass: Record<string, number>}}
 */
function costOfTrace(requests, options = {}) {
  const byClass = {};
  let total = 0;
  for (const req of requests) {
    const { cost, class: cls } = classify(req, options);
    total += cost;
    byClass[cls] = (byClass[cls] || 0) + cost;
  }
  return { total, byClass };
}

module.exports = Object.freeze({
  classify,
  costOfTrace,
  COSTS,
  STATIC,
  API_READ,
  API_READ_AUTHED,
  API_WRITE,
  AUTH,
  DEFAULT_COST,
});