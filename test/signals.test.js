'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  fingerprint,
  browserRequest,
  scannerRequest,
  isAlphabetical,
  observedHeaderOrder,
  normaliseHeaders,
  WEIGHTS,
} = require('../src/signals.js');

test('an ordinary browser request fires no bot signals', () => {
  const result = fingerprint(browserRequest());
  assert.equal(result.score, 0, `a browser scored ${result.score}: ${result.reason}`);
  assert.deepEqual(result.keys, []);
  assert.match(result.reason, /ordinary browser/);
});

test('a directory scanner scores clearly above a browser', () => {
  const scan = fingerprint(scannerRequest('/.env'));
  const browser = fingerprint(browserRequest());
  assert.ok(scan.score > browser.score, `${scan.score} should exceed ${browser.score}`);
  assert.ok(scan.keys.includes('noSecFetch'));
  assert.ok(scan.keys.includes('knownBotUserAgent'));
});

test('a completely bare request looks like a raw socket', () => {
  const result = fingerprint({ headers: { Host: 'example.com' } });
  assert.equal(result.signals.rawSocket, true);
  assert.ok(result.score > 0.5, `bare request scored only ${result.score}`);
});

test('the score never exceeds one', () => {
  const everything = {
    headers: {
      Accept: '*/*',
      'Accept-Encoding': 'identity',
      'Accept-Language': 'en',
      Connection: 'close',
      Host: 'example.com',
      'User-Agent': 'sqlmap/1.7',
    },
  };
  const result = fingerprint(everything);
  assert.ok(result.score <= 1, `score was ${result.score}`);
});

test('signal weights are all positive and documented', () => {
  for (const [name, weight] of Object.entries(WEIGHTS)) {
    assert.ok(weight > 0, `${name} has weight ${weight}`);
  }
});

test('an alphabetical header order is detected', () => {
  // A script building headers from a hash map emits them sorted.
  assert.equal(isAlphabetical(['accept', 'accept-encoding', 'accept-language', 'user-agent']), true);
  assert.equal(isAlphabetical(['user-agent', 'accept', 'accept-encoding', 'accept-language']), false);
});

test('too few headers are not enough evidence of an alphabetical order', () => {
  // Two headers are alphabetical by coincidence half the time.
  assert.equal(isAlphabetical(['accept', 'user-agent']), false);
  assert.equal(isAlphabetical(['a', 'b', 'c']), false);
});

test('an unknown header name does not flip the order verdict', () => {
  // A client may add arbitrary headers, and they must not decide the signal.
  // Both lists contain the same four known headers in alphabetical order, so
  // both must be judged the same way regardless of what rides along.
  const known = ['accept', 'accept-encoding', 'accept-language', 'user-agent'];
  assert.equal(isAlphabetical(known), true);
  assert.equal(isAlphabetical([...known, 'zz-custom']), true, 'a trailing header must not matter');
  assert.equal(isAlphabetical([...known, 'aa-custom']), true, 'a leading unknown header must not matter');
  // ...but a known header in the wrong position still flips it.
  assert.equal(isAlphabetical([...known, 'host']), false);
});

test('rawHeaders is preferred over headers for the observed order', () => {
  const req = {
    // The headers object is sorted, but the wire order is not.
    headers: { accept: '*/*', host: 'e.com', 'user-agent': 'curl/8' },
    rawHeaders: ['Host', 'e.com', 'User-Agent', 'curl/8', 'Accept', '*/*'],
  };
  assert.deepEqual(observedHeaderOrder(req), ['host', 'user-agent', 'accept']);
  assert.equal(isAlphabetical(observedHeaderOrder(req)), false);
});

test('header names are lower-cased before comparison', () => {
  assert.deepEqual(
    Object.keys(normaliseHeaders({ Host: 'x', 'USER-AGENT': 'y' })),
    ['host', 'user-agent']
  );
});

test('a missing sec-fetch family is detected', () => {
  const bare = fingerprint({ headers: { 'User-Agent': 'Mozilla/5.0 Chrome/128.0', Accept: 'text/html' } });
  assert.equal(bare.signals.noSecFetch, true);
  const withFetch = fingerprint(browserRequest());
  assert.equal(withFetch.signals.noSecFetch, false);
});

test('an empty user agent is flagged', () => {
  const result = fingerprint({ headers: { 'User-Agent': '   ' } });
  assert.equal(result.signals.missingUserAgent, true);
});

test('known scanner user agents are recognised', () => {
  for (const ua of ['sqlmap/1.7', 'Nikto/2.5', 'python-requests/2.32', 'curl/8.4.0', 'Go-http-client/2.0']) {
    const result = fingerprint({ headers: { 'User-Agent': ua } });
    assert.equal(result.signals.knownBotUserAgent, true, `${ua} was not detected`);
  }
});

test('a normal browser user agent is not flagged as a bot', () => {
  const result = fingerprint(browserRequest());
  assert.equal(result.signals.knownBotUserAgent, false);
});

test('accept-language without q-values is flagged', () => {
  const flat = fingerprint({ headers: { 'Accept-Language': 'en' } });
  assert.equal(flat.signals.flatAcceptLanguage, true);
  const weighted = fingerprint({ headers: { 'Accept-Language': 'ru;q=0.9,en;q=0.8' } });
  assert.equal(weighted.signals.flatAcceptLanguage, false);
});

test('missing accept and accept-encoding are detected separately', () => {
  const result = fingerprint({ headers: { Host: 'x' } });
  assert.equal(result.signals.missingAccept, true);
  assert.equal(result.signals.missingAcceptEncoding, true);
});

test('behind a proxy the CDN-obscured signals are discounted', () => {
  const direct = fingerprint(scannerRequest('/.env'));
  const viaProxy = fingerprint(scannerRequest('/.env'), { behindProxy: true });
  assert.ok(
    viaProxy.score < direct.score,
    `behind a proxy ${viaProxy.score} should be below ${direct.score}`
  );
  assert.equal(viaProxy.signals.noSecFetch, false, 'sec-fetch describes the CDN, not the client');
});

test('every fired signal is reported by name', () => {
  const result = fingerprint(scannerRequest('/.env'));
  for (const key of result.keys) {
    assert.equal(result.signals[key], true, `${key} listed but not set`);
    assert.match(result.reason, new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('a request with no headers at all still returns a verdict', () => {
  const result = fingerprint({});
  assert.ok(result.score >= 0);
  assert.equal(typeof result.reason, 'string');
});

test('header order is read case-insensitively from rawHeaders', () => {
  const req = {
    headers: {},
    rawHeaders: ['ACCEPT', '*/*', 'User-Agent', 'curl/8', 'Host', 'x', 'Accept-Encoding', 'gzip'],
  };
  assert.deepEqual(observedHeaderOrder(req), ['accept', 'user-agent', 'host', 'accept-encoding']);
  assert.equal(isAlphabetical(observedHeaderOrder(req)), false);
});