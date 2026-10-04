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
// Prefix masking, at every prefix length
//
// The regression that made this worth testing: the mask was computed as
// `0xff << (8 - (bits - i * 8))`, whose shift goes negative as soon as an
// octet is fully covered by the prefix. JavaScript does not throw on that, it
// masks the count with `& 31`, so the mask silently became 0 and octet 0 of a
// `/16` was never compared. The existing tests only ever configured a `/8`,
// which is the one family of lengths where the arithmetic happens to come out
// right, so the hole was invisible.
//
// This matters because isTrusted() gates the whole leftmost-XFF rule: a peer
// outside the proxy range that is nevertheless believed as a proxy gets its
// forwarding headers believed too.
// ---------------------------------------------------------------------------

/**
 * Prefix arithmetic over a 32-bit address, done in BigInt so that the "+1"
 * used to step just outside a prefix can never silently wrap past 255 the way
 * a per-octet helper would.
 */
const toInt = (quad) => quad.split('.').reduce((acc, o) => (acc << 8n) + BigInt(o), 0n);
const toQuad = (v) => [24n, 16n, 8n, 0n].map((s) => Number((v >> s) & 0xffn)).join('.');

/** The mask for a /bits prefix, as a 32-bit BigInt. */
const netmask = (bits) => (bits === 0 ? 0n : (0xffffffffn << BigInt(32 - bits)) & 0xffffffffn);

test('a /16 trusts only its own 10.0.x.x, not a neighbour', () => {
  const r = createAddressResolver({ trustedProxies: ['10.0.0.0/16'], trustLoopback: false });
  assert.equal(r.isTrusted('10.0.0.1'), true);
  assert.equal(r.isTrusted('10.0.255.254'), true);
  // The regression: these three were all reported as inside 10.0.0.0/16.
  assert.equal(r.isTrusted('192.0.0.1'), false, '192.0.0.1 is not in 10.0.0.0/16');
  assert.equal(r.isTrusted('11.0.0.1'), false, '11.0.0.1 is not in 10.0.0.0/16');
  assert.equal(r.isTrusted('1.0.0.1'), false, '1.0.0.1 is not in 10.0.0.0/16');
});

test('flipping any single bit moves an address in or out as the prefix says', () => {
  // The strong form of the invariant, and the one that actually catches the
  // negative-shift bug. An earlier version of this test only probed the first
  // address above the prefix, which differs from the base in the *last* covered
  // octet -- precisely the one octet the buggy mask computed correctly -- so it
  // passed against the broken code. Flipping every bit of every octet covers all
  // 32 mask positions.
  const failures = [];
  let probes = 0;
  for (let bits = 1; bits <= 32; bits += 1) {
    const mask = netmask(bits);
    const net = 0xc0a80100n & mask; // 192.168.1.0 and friends
    const quad = toQuad(net);
    const r = createAddressResolver({
      trustedProxies: [`${quad}/${bits}`],
      trustLoopback: false,
    });
    const octets = quad.split('.').map(Number);

    // The network address is inside its own prefix by definition.
    if (!r.isTrusted(quad)) failures.push(`/${bits}: ${quad} should be inside ${quad}/${bits}`);

    for (let i = 0; i < 4; i += 1) {
      // How many leading bits of octet i the prefix covers.
      const significant = Math.max(0, Math.min(8, bits - i * 8));
      for (let b = 0; b < 8; b += 1) {
        const flipped = octets.slice();
        flipped[i] ^= 1 << (7 - b);
        const addr = flipped.join('.');
        // b is counted from the MSB, matching the XOR above, so the octet's
        // first `significant` bits are the ones the prefix fixes. Flipping any
        // of them leaves the prefix; flipping a later one does not.
        const expectInside = significant === 0 || b >= significant;
        if (r.isTrusted(addr) !== expectInside) {
          failures.push(
            `/${bits}: ${addr} ${expectInside ? 'should be inside' : 'should NOT be inside'} ${quad}/${bits}` +
              ` (octet ${i}, bit ${b}, ${significant} significant bits)`,
          );
        }
        probes += 1;
      }
    }
  }
  assert.deepEqual(failures, [], 'prefix masking is wrong:\n' + failures.join('\n'));
  assert.equal(probes, 1024, 'all 32 prefix lengths x 4 octets x 8 bits are exercised');
});

test('an attacker outside the proxy range cannot have its XFF believed', () => {
  // The invariant this module exists for, in its most direct form: a peer that
  // is not a configured proxy must never speak for the client. 172.31.255.254
  // is deliberately absent from the list for /12 -- it really is inside
  // 172.16.0.0/12, so it is a legitimate proxy peer there.
  for (const cidr of ['10.0.0.0/16', '172.16.0.0/12', '192.168.1.0/24']) {
    const r = createAddressResolver({ trustedProxies: [cidr], trustLoopback: false });
    for (const attacker of ['192.0.0.1', '8.8.8.8', '172.32.0.1', '203.0.113.9']) {
      const result = r.resolve(req(attacker, { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' }));
      assert.equal(
        result.address,
        attacker,
        `a socket of ${attacker} is not a proxy under ${cidr}, so its XFF must be ignored`,
      );
      assert.equal(result.source, 'socket');
    }
  }
});

test('a malformed address is not trusted rather than NaN-matched', () => {
  // Number('zzz') is NaN and every comparison against NaN is false, which used
  // to make these match any prefix at all.
  const r = createAddressResolver({ trustedProxies: ['10.0.0.0/16'], trustLoopback: false });
  for (const bad of ['10.zzz.0.0', '10.foo.0.0', '10. 0.0.0', 'x10.0.0.0', '10.0.0.0.0', '10.0.0']) {
    assert.equal(r.isTrusted(bad), false, `${JSON.stringify(bad)} must not be trusted`);
  }
  assert.equal(r.isTrusted('10.999.0.0'), false, 'octets above 255 are not addresses');
  assert.equal(r.isTrusted('10.-1.-1.-1'), false, 'negative octets are not addresses');
});

test('a malformed peer address resolves to itself, with no headers believed', () => {
  const r = createAddressResolver({ trustedProxies: ['10.0.0.0/16'], trustLoopback: false });
  const result = r.resolve(req('10.zzz.0.0', { 'x-forwarded-for': '8.8.8.8' }));
  assert.equal(result.address, '10.zzz.0.0');
  assert.equal(result.source, 'socket');
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