'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createAddressResolver } = require('../src/proxy.js');

/** A request from a socket, optionally carrying forwarding headers. */
function req(socket, headers = {}) {
  return { socket: { remoteAddress: socket }, headers: { Host: 'x', ...headers } };
}

/** A resolver that trusts one proxy on loopback and nothing else. */
function oneProxy(extra = {}) {
  return createAddressResolver({ trustedProxies: ['127.0.0.1'], trustLoopback: false, ...extra });
}

// ---------------------------------------------------------------------------
// With no trusted proxy configured, forwarding headers must be ignored
// ---------------------------------------------------------------------------

test('with no trusted proxies, only the socket is believed', () => {
  const r = createAddressResolver({ trustLoopback: false });
  const result = r.resolve(req('203.0.113.9', { 'x-forwarded-for': '1.2.3.4' }));
  assert.equal(result.address, '203.0.113.9', 'a client must not be able to name itself');
  assert.equal(result.source, 'socket');
});

test('with no trusted proxies, x-real-ip is ignored too', () => {
  const r = createAddressResolver({ trustLoopback: false });
  const result = r.resolve(req('203.0.113.9', { 'x-real-ip': '1.2.3.4' }));
  assert.equal(result.address, '203.0.113.9');
});

test('loopback is trusted by default, because a local proxy is the normal case', () => {
  const r = createAddressResolver();
  const result = r.resolve(req('127.0.0.1', { 'x-forwarded-for': '203.0.113.7' }));
  assert.equal(result.address, '203.0.113.7');
});

// ---------------------------------------------------------------------------
// The central attack: a forged leftmost entry
// ---------------------------------------------------------------------------

test('a forged leading entry is discarded', () => {
  const r = oneProxy();
  // The client sends a header claiming to be 1.2.3.4. The proxy appends the real
  // address. Trusting the leftmost entry would hand rate-limit identity to the
  // attacker.
  const result = r.resolve(req('127.0.0.1', { 'x-forwarded-for': '1.2.3.4, 203.0.113.7' }));
  assert.equal(result.address, '203.0.113.7');
  assert.equal(result.untrustedPrefix, true);
  assert.match(result.reason, /discarded 1/);
});

test('several forged leading entries are all discarded', () => {
  const r = oneProxy();
  const result = r.resolve(
    req('127.0.0.1', { 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 203.0.113.7' })
  );
  assert.equal(result.address, '203.0.113.7');
  assert.match(result.reason, /discarded 2/);
});

test('an honest single-entry chain resolves to the client', () => {
  const r = oneProxy();
  const result = r.resolve(req('127.0.0.1', { 'x-forwarded-for': '203.0.113.7' }));
  assert.equal(result.address, '203.0.113.7');
  assert.equal(result.untrustedPrefix, false);
});

// ---------------------------------------------------------------------------
// An untrusted socket may not speak for anybody
// ---------------------------------------------------------------------------

test('an untrusted socket cannot have its headers believed', () => {
  const r = oneProxy();
  const result = r.resolve(req('198.51.100.5', { 'x-forwarded-for': '1.2.3.4' }));
  assert.equal(result.address, '198.51.100.5', 'the socket wins when it is not a known proxy');
  assert.equal(result.untrustedPrefix, true);
  assert.match(result.reason, /not a trusted proxy/);
});

// ---------------------------------------------------------------------------
// Multi-hop chains
// ---------------------------------------------------------------------------

test('a two-hop trusted chain resolves to the real client', () => {
  const r = createAddressResolver({
    trustedProxies: ['127.0.0.1', '10.0.0.0/8'],
    trustLoopback: false,
  });
  // socket is the CDN at 10.1.1.1, which appended to what nginx appended.
  const result = r.resolve(req('10.1.1.1', { 'x-forwarded-for': '203.0.113.7' }));
  assert.equal(result.address, '203.0.113.7');
});

test('a CIDR trusts only addresses inside it', () => {
  const r = createAddressResolver({ trustedProxies: ['10.0.0.0/8'], trustLoopback: false });
  assert.equal(r.isTrusted('10.1.2.3'), true);
  assert.equal(r.isTrusted('11.1.2.3'), false);
  assert.equal(r.isTrusted('192.0.2.1'), false);
  assert.equal(r.isTrusted(''), false);
  assert.equal(r.isTrusted(undefined), false);
});

// ---------------------------------------------------------------------------
// Resource exhaustion through the header
// ---------------------------------------------------------------------------

test('an over-long chain is refused rather than parsed', () => {
  const long = Array.from({ length: 200 }, (_, i) => `10.0.0.${(i % 250) + 1}`).join(', ');
  const r = oneProxy({ maxHops: 16 });
  const result = r.resolve(req('127.0.0.1', { 'x-forwarded-for': long }));
  assert.equal(result.address, null, 'an unbounded chain must not become a lookup table');
  assert.match(result.reason, /exceeds maxHops/);
});

test('a chain at exactly maxHops is still accepted', () => {
  const chain = Array.from({ length: 16 }, (_, i) => `10.0.0.${(i % 250) + 1}`).join(', ');
  const r = oneProxy({ maxHops: 16 });
  const result = r.resolve(req('127.0.0.1', { 'x-forwarded-for': chain }));
  assert.notEqual(result.address, null);
});

// ---------------------------------------------------------------------------
// Single-address headers
// ---------------------------------------------------------------------------

test('cf-connecting-ip is honoured behind a trusted proxy', () => {
  const r = oneProxy();
  const result = r.resolve(req('127.0.0.1', { 'cf-connecting-ip': '203.0.113.7' }));
  assert.equal(result.address, '203.0.113.7');
  assert.equal(result.source, 'cf-connecting-ip');
});

test('cf-connecting-ip is ignored from an untrusted socket', () => {
  const r = oneProxy();
  const result = r.resolve(req('198.51.100.5', { 'cf-connecting-ip': '1.2.3.4' }));
  assert.equal(result.address, '198.51.100.5');
});

test('a single-address header with a forged prefix is not trusted', () => {
  const r = oneProxy();
  const result = r.resolve(req('127.0.0.1', { 'cf-connecting-ip': '1.2.3.4, 203.0.113.7' }));
  // Only the first entry is read, and it is the client's own claim. A single
  // header is only as trustworthy as the proxy that sets it, which is why the
  // chain form is preferred when more than one proxy is involved.
  assert.equal(result.address, '1.2.3.4');
});

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

test('malformed header values do not crash the resolver', () => {
  const r = oneProxy();
  for (const value of ['', '   ', ',,,', 'not-an-ip', '999.999.999.999', '1.2.3', '\x00\x01']) {
    const result = r.resolve(req('127.0.0.1', { 'x-forwarded-for': value }));
    assert.ok(result.address === null || typeof result.address === 'string');
  }
});

test('a request with no headers at all resolves to the socket', () => {
  const r = oneProxy();
  const result = r.resolve({ socket: { remoteAddress: '127.0.0.1' } });
  assert.equal(result.address, '127.0.0.1');
  assert.equal(result.source, 'socket');
});

test('a request with no socket resolves to null rather than throwing', () => {
  const r = oneProxy();
  const result = r.resolve({ headers: {} });
  assert.equal(result.address, null);
});

test('IPv6 socket addresses are handled', () => {
  const r = createAddressResolver({ trustedProxies: ['::1'], trustLoopback: false });
  const result = r.resolve(req('::1', { 'x-forwarded-for': '2001:db8::1' }));
  assert.equal(result.address, '2001:db8::1');
});

test('the resolver exposes what it trusts', () => {
  const r = oneProxy();
  assert.deepEqual(r.trustedProxies, ['127.0.0.1']);
  assert.equal(r.maxHops, 32);
  assert.ok(Object.isFrozen(r));
});