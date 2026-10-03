'use strict';

const { SlidingWindow } = require('./window.js');
const { identityOf, sameIdentity } = require('./identity.js');
const { classify } = require('./cost.js');
const { PathEntropyTracker, shannonEntropy } = require('./entropy.js');
const { fingerprint, browserRequest, scannerRequest } = require('./signals.js');
const { CircuitBreaker } = require('./circuit.js');
const { SiegeGuard, ALLOW, THROTTLE, CHALLENGE, BLOCK, DEFAULTS } = require('./guard.js');
const { renderDecision, renderReport } = require('./explain.js');
const { attach, guardMiddleware } = require('./middleware.js');

module.exports = Object.freeze({
  SlidingWindow,
  identityOf,
  sameIdentity,
  classify,
  PathEntropyTracker,
  shannonEntropy,
  fingerprint,
  browserRequest,
  scannerRequest,
  CircuitBreaker,
  SiegeGuard,
  createGuard: (options) => new SiegeGuard(options),
  guardMiddleware,
  attach,
  renderDecision,
  renderReport,
  ALLOW,
  THROTTLE,
  CHALLENGE,
  BLOCK,
  DEFAULTS,
});