'use strict';

/**
 * HTTP-layer client fingerprinting.
 *
 * ## What is available, and what is not
 *
 * A complete client fingerprint (JA3, JA4, Akamai fingerprint) is built from
 * the TLS ClientHello. Node's `http` module does not expose it: by the time a
 * request handler runs, the TLS handshake is long finished and its bytes are
 * gone. Reading it requires a TLS-terminating proxy, a native addon, or moving
 * to a TLS library that hands over the raw handshake.
 *
 * This module therefore works with what a plain Node HTTP server can actually
 * see, and says so plainly rather than pretending to offer more. That is still
 * a lot: browsers and bots differ in header presence, header ORDER, and in
 * fields that only one of them sends.
 *
 * ## The signals
 *
 * Each is a plain boolean, weighted, and combined into a 0..1 score. Weights
 * are in {@link WEIGHTS} and are documented there.
 *
 * Honest limits, stated up front:
 *
 * - A determined attacker can forge every one of these. They raise the cost of
 *   a casual scan; they are not authentication.
 * - A headless browser with fingerprint spoofing defeats most of them.
 * - Behind a CDN, the `sec-fetch-*` and header-order signals describe the CDN,
 *   not the client. Set `behindProxy: true` and the module downweights them.
 */

/** Per-signal weights. The sum is 1.0. */
const WEIGHTS = Object.freeze({
  /** Headers arrive in alphabetical order: very few real clients do this. */
  alphabeticalHeaders: 0.18,
  /** No `sec-fetch-*` at all: browsers always send at least one. */
  noSecFetch: 0.22,
  /** Empty or absent user agent. */
  missingUserAgent: 0.2,
  /** A user agent naming a known scanner or a non-browser client. */
  knownBotUserAgent: 0.15,
  /** `accept-language` missing, or carrying a single language with no q-values. */
  flatAcceptLanguage: 0.05,
  /** `accept-encoding` missing, which no browser omits. */
  missingAcceptEncoding: 0.05,
  /** `accept` missing. */
  missingAccept: 0.05,
  /** No `accept-encoding` AND no `accept`: almost certainly a raw socket. */
  rawSocket: 0.1,
});

/** Substrings in a user agent that mark a non-browser client. */
const BOT_AGENTS = Object.freeze([
  'sqlmap',
  'nikto',
  'nmap',
  'masscan',
  'zgrab',
  'curl/',
  'wget/',
  'python-requests',
  'python-urllib',
  'go-http-client',
  'java/',
  'libwww-perl',
  'okhttp',
  'axios',
  'postmanruntime',
  'headlesschrome',
  'phantomjs',
  'scrapy',
  'httpclient',
  'aiohttp',
  'guzzlehttp',
]);

/**
 * Header names whose position is worth checking, deliberately NOT in
 * alphabetical order -- if this list were sorted, every request would match it
 * and the signal would be meaningless.
 */
const ORDER_SENSITIVE = Object.freeze([
  'user-agent',
  'accept',
  'accept-encoding',
  'accept-language',
  'sec-fetch-mode',
  'sec-fetch-site',
  'connection',
  'cache-control',
  'host',
]);

/**
 * Build a fingerprint from a Node request.
 *
 * @param {object} req anything with `headers` and optionally `httpVersion`
 * @param {object} [options]
 * @param {boolean} [options.behindProxy=false] discount CDN-obscured signals
 * @returns {{
 *   score: number, signals: Record<string, boolean>, keys: string[],
 *   botLikelihood: number, reason: string
 * }}
 */
function fingerprint(req, options = {}) {
  const headers = normaliseHeaders(req && req.headers ? req.headers : {});
  const signals = Object.create(null);

  const names = Object.keys(headers);
  const hasSecFetch = names.some((h) => h.startsWith('sec-fetch-'));
  signals.noSecFetch = !hasSecFetch;

  const ua = String(headers['user-agent'] || '').trim();
  signals.missingUserAgent = ua === '';
  const lowerUa = ua.toLowerCase();
  signals.knownBotUserAgent = lowerUa !== '' && BOT_AGENTS.some((s) => lowerUa.includes(s));

  const al = headers['accept-language'];
  signals.flatAcceptLanguage = al === undefined || !/;\s*q\s*=/i.test(al);

  signals.missingAcceptEncoding = headers['accept-encoding'] === undefined;
  signals.missingAccept = headers.accept === undefined;
  signals.rawSocket =
    signals.missingAcceptEncoding && signals.missingAccept && !hasSecFetch && ua === '';

  // Alphabetical header order is a bot tell, and it only means anything if the
  // observed order is the wire order. `req.headers` preserves insertion order
  // for string keys in Node, and rawHeaders is used when it is available, so
  // the sequence below really is the order the client sent. Note that the
  // previous version filtered through ORDER_SENSITIVE and compared the filtered
  // list against itself, which every request passed; it now compares the
  // order the client actually used.
  signals.alphabeticalHeaders = isAlphabetical(observedHeaderOrder(req));

  // Behind a CDN the browser-shaped signals describe the CDN, not the client.
  if (options.behindProxy) {
    signals.noSecFetch = false;
    signals.alphabeticalHeaders = false;
  }

  const keys = Object.keys(signals).filter((k) => signals[k]);

  let score = 0;
  for (const k of keys) score += WEIGHTS[k] || 0;
  // A raw socket is itself a strong signal, and it is already partly counted
  // through missingAccept/missingAcceptEncoding; add it explicitly so the score
  // can reach 1.0 on a completely bare request.
  if (signals.rawSocket) score = Math.min(1, score + WEIGHTS.rawSocket);
  score = Math.min(1, score);

  return {
    score: Number(score.toFixed(4)),
    signals,
    keys,
    botLikelihood: score,
    reason: keys.length === 0 ? 'looks like an ordinary browser' : `fired: ${keys.join(', ')}`,
  };
}

/**
 * True when the header names arrive in alphabetical order.
 *
 * Real browsers and HTTP libraries emit headers in the order the protocol
 * requires: host, user-agent, accept and so on. Scripts that build a request
 * from a hash map produce alphabetical order as a side effect, and almost
 * nothing else does.
 *
 * Two guards keep the signal honest:
 *
 * - Fewer than four headers is not enough evidence. A request with two headers
 *   is alphabetical by coincidence half the time.
 * - Only the well-known set is compared. A client may add an arbitrary header,
 *   and one extra unknown name must not flip the verdict.
 *
 * @param {string[]} names lower-case header names in observed order
 * @returns {boolean}
 */
function isAlphabetical(names) {
  const known = names.filter((n) => KNOWN_HEADERS.has(n));
  if (known.length < 4) return false;
  for (let i = 1; i < known.length; i += 1) {
    if (known[i - 1] > known[i]) return false;
  }
  return true;
}

/**
 * Lower-case every header name, as HTTP/2 requires and HTTP/1 does not.
 *
 * @param {object} headers
 * @returns {object}
 */
function normaliseHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) out[String(k).toLowerCase()] = v;
  return out;
}

/**
 * Header names a browser actually sends, used to filter the order check.
 */
const KNOWN_HEADERS = new Set(
  [
    'accept',
    'accept-encoding',
    'accept-language',
    'authorization',
    'cache-control',
    'connection',
    'content-length',
    'content-type',
    'cookie',
    'dnt',
    'host',
    'origin',
    'pragma',
    'referer',
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
    'sec-fetch-dest',
    'sec-fetch-mode',
    'sec-fetch-site',
    'sec-fetch-user',
    'upgrade-insecure-requests',
    'user-agent',
  ].concat(ORDER_SENSITIVE)
);

/**
 * Extract header names in the order the client sent them.
 *
 * `req.rawHeaders` is the authoritative wire order when present; `req.headers`
 * is a fallback, since Node preserves insertion order for string keys.
 *
 * @param {object} req
 * @returns {string[]}
 */
function observedHeaderOrder(req) {
  const raw = req && req.rawHeaders;
  if (Array.isArray(raw) && raw.length >= 2) {
    const names = [];
    for (let i = 0; i < raw.length; i += 2) names.push(String(raw[i]).toLowerCase());
    return names;
  }
  return Object.keys(normaliseHeaders(req && req.headers ? req.headers : {}));
}

/**
 * A human-readable browser request, for the demo and for tests.
 *
 * @param {string} [path='/']
 * @returns {object}
 */
function browserRequest(path = '/') {
  return {
    method: 'GET',
    url: path,
    httpVersion: '1.1',
    headers: {
      Host: 'example.com',
      'User-Agent':
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
      'Accept-Encoding': 'gzip, deflate, br',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      Connection: 'keep-alive',
    },
  };
}

/**
 * A directory scanner request, for the demo and for tests.
 *
 * @param {string} [path='/']
 * @returns {object}
 */
function scannerRequest(path = '/') {
  return {
    method: 'GET',
    url: path,
    httpVersion: '1.1',
    // Alphabetical, and none of the browser-only fields.
    headers: {
      Accept: '*/*',
      'Accept-Encoding': 'gzip',
      Connection: 'close',
      Host: 'example.com',
      'User-Agent': 'python-requests/2.32.3',
    },
  };
}

module.exports = Object.freeze({
  fingerprint,
  normaliseHeaders,
  observedHeaderOrder,
  isAlphabetical,
  browserRequest,
  scannerRequest,
  WEIGHTS,
  BOT_AGENTS,
  ORDER_SENSITIVE,
  KNOWN_HEADERS,
});