'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const identity = require('../src/identity.js');

// Every masking expectation here is cross-checked against Python's ipaddress
// module by scripts/cross-check.py, so "2001:db8:0:1:: is not in 2001:db8::/64"
// is a verified fact rather than a belief.

test('every address in one IPv6 /64 shares a single identity', () => {
  const addresses = ['2001:db8::1', '2001:db8::2', '2001:db8::ffff', '2001:db8::abcd:1234'];
  const normalised = new Set(addresses.map((a) => identity.identityOf(a).normalized));
  assert.equal(normalised.size, 1, `expected one identity, got ${[...normalised]}`);
  assert.equal(identity.identityOf('2001:db8::1').normalized, '2001:db8::');
});

test('the neighbouring IPv6 /64 is a genuinely different identity', () => {
  // 2001:db8:0:1::abcd has third group 0:1, not 0:0, so it is the next /64.
  // If this merged with 2001:db8:: the module would collapse whole blocks.
  assert.notEqual(
    identity.identityOf('2001:db8:0:1::abcd').normalized,
    identity.identityOf('2001:db8::1').normalized
  );
  assert.equal(identity.identityOf('2001:db8:0:1::abcd').normalized, '2001:db8:0:1::');
  assert.equal(identity.identityOf('2001:db8:ffff:ffff::1').normalized, '2001:db8:ffff:ffff::');
});

test('two different IPv6 /64s get separate identities', () => {
  assert.notEqual(
    identity.identityOf('2001:db8::1').normalized,
    identity.identityOf('2001:db9::1').normalized
  );
  assert.equal(identity.identityOf('2001:db8::').normalized, '2001:db8::');
  assert.equal(identity.identityOf('2001:db9::').normalized, '2001:db9::');
});

test('a /64 covers exactly 2^64 addresses, reported without precision loss', () => {
  const id = identity.identityOf('2001:db8::1');
  assert.equal(id.subnetSize, '18446744073709551616');
  // A double cannot hold this; going through Number would corrupt it.
  assert.equal(Number(id.subnetSize).toString(), '18446744073709552000');
});

test('a shorter IPv6 prefix merges allocations that are close together', () => {
  // The /56 boundary sits 8 bits into the FOURTH group, so a /56 merge needs
  // two addresses that differ only in the low 8 bits of group 3. 2001:db8::1
  // and 2001:db8:ff::1 differ in the THIRD group, which is above the /56
  // boundary, so they are in different /56s. scripts/cross-check.py confirms
  // every one of these expectations against Python.
  const a = identity.identityOf('2001:db8:0:ff00::1', { ipv6Prefix: 56 }).normalized;
  const b = identity.identityOf('2001:db8:0:ffff::1', { ipv6Prefix: 56 }).normalized;
  assert.equal(a, b, `/56 must merge both, got ${a} and ${b}`);
  assert.equal(a, '2001:db8:0:ff00::');
  // One bit of group 3 apart: different /56.
  assert.notEqual(
    identity.identityOf('2001:db8:0:ff00::1', { ipv6Prefix: 56 }).normalized,
    identity.identityOf('2001:db8:0:0f00::1', { ipv6Prefix: 56 }).normalized
  );
});

test('an IPv6 /48 merges many /56s and a /49 splits them', () => {
  const a = identity.identityOf('2001:db8:0:1::1', { ipv6Prefix: 48 }).normalized;
  const b = identity.identityOf('2001:db8:0:ffff::1', { ipv6Prefix: 48 }).normalized;
  assert.equal(a, b, `/48 must merge both, got ${a} and ${b}`);
  assert.equal(a, '2001:db8::');
  // A /49 sits between the two, one bit into group 3.
  assert.equal(identity.identityOf('2001:db8:0:0::1', { ipv6Prefix: 49 }).normalized, '2001:db8::');
  assert.equal(
    identity.identityOf('2001:db8:0:8000::1', { ipv6Prefix: 49 }).normalized,
    '2001:db8:0:8000::'
  );
});

test('IPv4 defaults to one host per identity', () => {
  assert.equal(identity.identityOf('192.0.2.10').normalized, '192.0.2.10');
  assert.notEqual(
    identity.identityOf('192.0.2.10').normalized,
    identity.identityOf('192.0.2.11').normalized
  );
  assert.equal(identity.identityOf('192.0.2.10').subnetSize, '1');
});

test('an IPv4 /24 prefix merges a subnet', () => {
  assert.equal(identity.identityOf('192.0.2.10', { ipv4Prefix: 24 }).normalized, '192.0.2.0');
  assert.equal(identity.identityOf('192.0.2.200', { ipv4Prefix: 24 }).normalized, '192.0.2.0');
  assert.equal(identity.identityOf('192.0.3.1', { ipv4Prefix: 24 }).normalized, '192.0.3.0');
});

test('IPv4-mapped IPv6 is unwrapped so dual-stack clients are not collapsed', () => {
  const mapped = identity.identityOf('::ffff:127.0.0.1');
  assert.equal(mapped.family, 4);
  assert.equal(mapped.mapped, true);
  assert.equal(mapped.normalized, '127.0.0.1');
  // Without unwrapping, all IPv4 traffic would land in one /64 bucket.
  assert.equal(identity.sameIdentity('::ffff:127.0.0.1', '127.0.0.1'), true);
  assert.equal(identity.sameIdentity('::ffff:8.8.8.8', '127.0.0.1'), false);
});

test('bracketed IPv6 is accepted', () => {
  assert.equal(identity.identityOf('[::1]').normalized, '::');
});

test('IPv6 zone identifiers are stripped', () => {
  assert.equal(identity.identityOf('fe80::1%eth0').normalized, 'fe80::');
});

test('canonical IPv6 formatting compresses the longest zero run', () => {
  assert.equal(identity.formatIPv6([0, 0, 0, 0, 0, 0, 0, 0]), '::');
  assert.equal(identity.formatIPv6(identity.parseIPv6('2001:db8::1')), '2001:db8::1');
  assert.equal(
    identity.formatIPv6(identity.parseIPv6('2001:0db8:0000:0000:0000:0000:0000:0001')),
    '2001:db8::1'
  );
  // RFC 5952: only runs of two or more are compressed.
  assert.equal(identity.formatIPv6([0, 1, 0, 0, 0, 0, 0, 0]), '0:1::');
});

test('embedded IPv4 tails parse into the right groups', () => {
  const groups = identity.parseIPv6('::ffff:192.0.2.1');
  assert.equal(groups.length, 8);
  assert.equal(groups[6], 0xc000);
  assert.equal(groups[7], 0x0201);
});

test('a full 128-bit value round-trips through BigInt exactly', () => {
  const groups = [0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
  const { hi, lo } = identity.ipv6ToBigInt(groups);
  assert.equal(hi.toString(), '18446744073709551615');
  assert.equal(lo.toString(), '18446744073709551615');
});

test('malformed addresses are rejected', () => {
  const cases = [
    '',
    '010.0.0.1',
    '1.2.3',
    '1.2.3.4.5',
    '256.1.1.1',
    '2001:::1',
    '1:2:3:4:5:6:7',
    '1:2:3:4:5:6:7:8:9',
    '::1::2',
    '2001:db8::gggg',
    '1.2.3.4:5:6:7',
    '%eth0',
  ];
  for (const input of cases) {
    assert.throws(() => identity.identityOf(input), /./, `${JSON.stringify(input)} must throw`);
  }
});

test('a leading-zero IPv4 octet explains why it was refused', () => {
  assert.throws(() => identity.identityOf('010.0.0.1'), /leading zero/);
});

test('prefix lengths outside the legal range are rejected', () => {
  assert.throws(() => identity.identityOf('2001:db8::1', { ipv6Prefix: 129 }), /0\.\.128/);
  assert.throws(() => identity.identityOf('1.2.3.4', { ipv4Prefix: 33 }), /0\.\.32/);
  assert.throws(() => identity.identityOf('2001:db8::1', { ipv6Prefix: 1.5 }), /integer/);
});

test('sameIdentity returns false for unparseable input instead of throwing', () => {
  assert.equal(identity.sameIdentity('2001:db8::1', 'nonsense'), false);
  assert.equal(identity.sameIdentity('nonsense', 'nonsense'), false);
});

test('the identity record is frozen and complete', () => {
  const id = identity.identityOf('2001:db8::1');
  assert.ok(Object.isFrozen(id));
  for (const key of ['raw', 'normalized', 'family', 'subnetSize', 'prefix', 'mapped']) {
    assert.ok(key in id, `missing ${key}`);
  }
});

test('subnet sizes are reported exactly for both families', () => {
  assert.equal(identity.subnetSize(0, 6), '340282366920938463463374607431768211456');
  assert.equal(identity.subnetSize(128, 6), '1');
  assert.equal(identity.subnetSize(0, 4), '4294967296');
  assert.equal(identity.subnetSize(32, 4), '1');
});

test('masking an IPv6 address keeps only the prefix bits', () => {
  assert.equal(identity.maskIPv6('2001:db8:1:2:3:4:5:6', 64), '2001:db8:1:2::');
  assert.equal(identity.maskIPv6('2001:db8:1:2:3:4:5:6', 32), '2001:db8::');
  // Off-by-a-nibble boundaries: these caught the test above asserting /32's
  // answer for /64. Cross-checked against python3 -m ipaddress.
  assert.equal(identity.maskIPv6('2001:db8:1:2:3:4:5:6', 48), '2001:db8:1::');
  assert.equal(identity.maskIPv6('2001:db8:1:2:3:4:5:6', 16), '2001::');
  assert.equal(identity.maskIPv6('2001:db8:1:2:3:4:5:6', 128), '2001:db8:1:2:3:4:5:6');
  assert.equal(identity.maskIPv6('2001:db8:1:2:3:4:5:6', 0), '::');
});

test('masking an IPv4 address keeps only the prefix bits', () => {
  assert.equal(identity.maskIPv4('192.0.2.10', 24), '192.0.2.0');
  assert.equal(identity.maskIPv4('192.0.2.10', 32), '192.0.2.10');
  assert.equal(identity.maskIPv4('192.0.2.10', 0), '0.0.0.0');
  assert.equal(identity.maskIPv4('192.0.2.10', 16), '192.0.0.0');
});