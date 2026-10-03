'use strict';

/**
 * HTTP integration.
 *
 * Two shapes, because Node has no standard middleware chain and projects keep
 * reinventing one:
 *
 * - {@link guardMiddleware} is an ordinary `(req, res, next)` function, so it
 *   drops into anything that has a `next`, including Express.
 * - {@link attach} wraps a plain `http.createServer` handler, which is the case
 *   with no framework at all.
 *
 * Neither one throws. A defence that can crash the process it protects is not a
 * defence, so every error path ends in a decision and every decision ends in a
 * response.
 */

const { SiegeGuard, ALLOW } = require('./guard.js');
const { renderDecision } = require('./explain.js');

/**
 * Write a denial and stop.
 *
 * @param {object} res
 * @param {object} decision
 * @param {object} options
 */
function deny(res, decision, options = {}) {
  const headers = { 'content-type': 'text/plain; charset=utf-8' };
  if (decision.retryAfterMs > 0) {
    headers['retry-after'] = String(Math.max(1, Math.ceil(decision.retryAfterMs / 1000)));
  }
  headers['x-siege-guard'] = decision.action;

  const body = options.explain
    ? `${renderDecision(decision)}\n`
    : `${decision.reason}\n`;

  res.writeHead(decision.status, headers);
  res.end(body);
}

/**
 * Build a `(req, res, next)` middleware.
 *
 * @param {object} [options] passed to {@link SiegeGuard}, plus:
 * @param {SiegeGuard} [options.guard] use an existing guard
 * @param {boolean} [options.explain=false] put the full reasoning in the body
 * @param {boolean} [options.pass=true] call `next()` on allow
 * @returns {((req: object, res: object, next: Function) => void) & {guard: SiegeGuard}}
 */
function guardMiddleware(options = {}) {
  const guard = options.guard || new SiegeGuard(options);
  const explain = Boolean(options.explain);

  function middleware(req, res, next) {
    let decision;
    try {
      decision = guard.check(req);
    } catch (error) {
      // Never let the guard take the server down. Fail open, because a bug in
      // the limiter is not a reason to drop every legitimate request. Handing
      // the request back to the origin keeps the site up; the next deploy is
      // where this gets fixed.
      if (typeof next === 'function') return next();
      res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('guard error\n');
      return undefined;
    }

    res.setHeader?.('x-siege-guard-action', decision.action);

    if (decision.action === ALLOW) {
      req.siegeGuard = decision;
      if (typeof next === 'function') return next();
      return undefined;
    }
    return deny(res, decision, { explain });
  }

  middleware.guard = guard;
  return middleware;
}

/**
 * Wrap a plain Node request handler.
 *
 * @param {(req: object, res: object) => void} handler
 * @param {object} [options] passed to {@link guardMiddleware}
 * @returns {(req: object, res: object) => void}
 */
function attach(handler, options = {}) {
  const middleware = guardMiddleware(options);
  return function guarded(req, res) {
    middleware(req, res, () => {
      req.siegeGuard = req.siegeGuard || null;
      handler(req, res);
    });
  };
}

module.exports = Object.freeze({ guardMiddleware, attach, deny });