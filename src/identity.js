'use strict';

/**
 * IPv6-aware client identity.
 *
 * ## Why this module exists
 *
 * The obvious implementation of a per-client rate limit is "key by remote
 * address". That is correct on IPv4 and useless on IPv6.
 *
 * A single residential or cloud IPv6 allocation is typically a /64. That is
 * 2^64 addresses. An attacker rotates through them at will and every one of
 * them gets a fresh budget. A limit keyed on the full address stops nothing;
 * it just makes the limiter's memory grow without bound while the attack
 * continues.
 *
 * So identity is computed on a PREFIX, not on an address. Everything in a /64
 * shares one budget by default, which means the attacker has to obtain a
 * genuinely different allocation to get more quota.
 *
 * ## Choosing the prefix length
 *
 * | Prefix | Addresses | Good for |
 * | --- | --- | --- |
 * | /64 | 2^64 | Residential ISP, mobile, cloud VMs. The correct default: one allocation, one customer. |
 * | /56 | 2^56 | An ISP handing out /56 to a large site. One address legitimately serves many users. |
 * | /48 | 2^48 | A datacentre or an organisation with many /56s under one RIR block. |
 * | /32 | 2^32 | Not a routing boundary in IPv6; never use this to rate limit. |
 *
 * The default is /64 because that is the fixed customer boundary the RIRs
 * adopted, so it rarely splits one legitimate party and rarely merges two
 * attackers who do not already share a subnet.
 */

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Parse a dotted-quad address into a 32-bit unsigned integer.
 *
 * Leading zeros are rejected deliberately. Some resolvers and libraries accept
 * `010.0.0.1`, and two parsers disagreeing about whether that is octal or
 * decimal is a classic way to slip past an allowlist, so this package treats it
 * as malformed instead of guessing.
 *
 * @param {string} text
 * @returns {number} unsigned 32-bit value
 */
function parseIPv4(text) {
  const m = IPV4_RE.exec(text);
  if (!m) throw new RangeError(`not a dotted-quad IPv4 address: ${JSON.stringify(text)}`);
  let value = 0;
  for (let i = 1; i <= 4; i += 1) {
    const part = m[i];
    // A leading zero means either octal or a typo; either way it is ambiguous.
    if (part.length > 1 && part[0] === '0') {
      throw new RangeError(
        `IPv4 octet ${JSON.stringify(part)} has a leading zero, which is ambiguous ` +
          '(octal in some parsers, decimal in others); write it without padding'
      );
    }
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      throw new RangeError(`IPv4 octet out of range in ${JSON.stringify(text)}`);
    }
    value = value * 256 + n;
  }
  return value >>> 0;
}

/**
 * Format a 32-bit unsigned integer as a dotted quad.
 *
 * @param {number} value
 * @returns {string}
 */
function formatIPv4(value) {
  const v = value >>> 0;
  return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff].join('.');
}

/**
 * Mask an IPv4 address down to a prefix.
 *
 * @param {string} text
 * @param {number} prefix 0..32
 * @returns {string}
 */
function maskIPv4(text, prefix) {
  assertPrefix(prefix, 32, 'IPv4');
  const value = parseIPv4(text);
  const keep = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return formatIPv4((value & keep) >>> 0);
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

/**
 * Expand an IPv6 address into its eight 16-bit groups, expanding `::` and any
 * embedded IPv4 tail.
 *
 * @param {string} text
 * @returns {number[]} exactly 8 groups
 */
function parseIPv6(text) {
  if (typeof text !== 'string' || text.length === 0) {
    throw new RangeError('empty IPv6 address');
  }
  // Strip a zone id; it identifies an interface, not a network, and it must
  // never influence the rate-limit key beyond being part of the raw value.
  const zone = text.indexOf('%');
  let body = zone === -1 ? text : text.slice(0, zone);
  if (body.length === 0) throw new RangeError('IPv6 address is only a zone id');

  // Embedded IPv4 tail, e.g. ::ffff:1.2.3.4. The two 16-bit groups are put
  // back into the address rather than replaced by zeros: masking at /128 has to
  // return the address that came in, and an earlier version computed the two
  // groups, threw them away and substituted 0:0, which quietly turned
  // ::ffff:192.0.2.1 into ::ffff:0:0.
  const lastColon = body.lastIndexOf(':');
  const tail4 = body.slice(lastColon + 1);
  if (tail4.includes('.')) {
    const v4 = parseIPv4(tail4);
    body = `${body.slice(0, lastColon + 1)}${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }

  const doubleColon = body.indexOf('::');
  let groups;
  if (doubleColon === -1) {
    const parts = body.split(':');
    if (parts.length !== 8) {
      throw new RangeError(
        `IPv6 address ${JSON.stringify(text)} has ${parts.length} groups, expected 8 without '::'`
      );
    }
    groups = parts;
  } else {
    if (body.indexOf('::', doubleColon + 1) !== -1) {
      throw new RangeError(`IPv6 address ${JSON.stringify(text)} contains more than one '::'`);
    }
    const head = body.slice(0, doubleColon) === '' ? [] : body.slice(0, doubleColon).split(':');
    const rest = body.slice(doubleColon + 2) === '' ? [] : body.slice(doubleColon + 2).split(':');
    const missing = 8 - head.length - rest.length;
    if (missing < 1) {
      throw new RangeError(
        `IPv6 address ${JSON.stringify(text)} has '::' but does not compress anything`
      );
    }
    groups = [...head, ...new Array(missing).fill('0'), ...rest];
  }

  if (groups.length !== 8) {
    throw new RangeError(`IPv6 address ${JSON.stringify(text)} did not resolve to 8 groups`);
  }
  return groups.map((g) => {
    if (g.length === 0 || g.length > 4 || !/^[0-9a-fA-F]+$/.test(g)) {
      throw new RangeError(`invalid IPv6 group ${JSON.stringify(g)} in ${JSON.stringify(text)}`);
    }
    return parseInt(g, 16);
  });
}

/**
 * Render eight 16-bit groups as an IPv6 address, compressing the longest run of
 * zeroes per RFC 5952 (leftmost run, at least two groups).
 *
 * @param {number[]} groups
 * @returns {string}
 */
function formatIPv6(groups) {
  const hex = groups.map((g) => g.toString(16));
  let bestStart = -1;
  let bestLen = 0;
  let i = 0;
  while (i < 8) {
    if (hex[i] !== '0') {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && hex[j] === '0') j += 1;
    if (j - i > bestLen && j - i >= 2) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (bestLen === 0) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLen).join(':');
  if (head === '' && tail === '') return '::';
  if (head === '') return `::${tail}`;
  if (tail === '') return `${head}::`;
  return `${head}::${tail}`;
}

/**
 * Convert eight groups to a 128-bit value as two 64-bit BigInt halves.
 *
 * BigInt is required: the address does not fit a double, and silent precision
 * loss above 2^53 is exactly the bug this package must not have.
 *
 * @param {number[]} groups
 * @returns {{hi: bigint, lo: bigint}}
 */
function ipv6ToBigInt(groups) {
  let hi = 0n;
  let lo = 0n;
  for (let i = 0; i < 4; i += 1) hi = (hi << 16n) | BigInt(groups[i]);
  for (let i = 4; i < 8; i += 1) lo = (lo << 16n) | BigInt(groups[i]);
  return { hi, lo };
}

/**
 * Mask an IPv6 address down to a prefix.
 *
 * @param {string} text
 * @param {number} prefix 0..128
 * @returns {string} the masked address in canonical form
 */
function maskIPv6(text, prefix) {
  assertPrefix(prefix, 128, 'IPv6');
  const groups = parseIPv6(text);
  const out = [];
  for (let i = 0; i < 8; i += 1) {
    const bitsInGroup = Math.max(0, Math.min(16, prefix - i * 16));
    out.push(bitsInGroup === 0 ? 0 : groups[i] & (0xffff << (16 - bitsInGroup)) & 0xffff);
  }
  return formatIPv6(out);
}

/**
 * How many addresses a prefix covers, as a decimal string.
 *
 * Returned as a string because 2^64 does not fit a double: printing
 * 1.8446744073709552e+19 would be a bug in the diagnostic that is supposed to
 * explain the diagnostic.
 *
 * @param {number} prefix
 * @param {4|6} family
 * @returns {string}
 */
function subnetSize(prefix, family) {
  const bits = family === 4 ? 32 : 128;
  assertPrefix(prefix, bits, family === 4 ? 'IPv4' : 'IPv6');
  return (2n ** BigInt(bits - prefix)).toString();
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/** IPv4 prefix used when none is configured: one host, one address. */
const DEFAULT_IPV4_PREFIX = 32;
/** IPv6 prefix used when none is configured: the standard customer boundary. */
const DEFAULT_IPV6_PREFIX = 64;

/**
 * Decide the family of an address, tolerating the forms Node hands over.
 *
 * `req.socket.remoteAddress` is already a bare address, but a reverse proxy in
 * front may hand over a bracketed form or an `::ffff:` mapped address.
 *
 * @param {string} address
 * @returns {4|6}
 */
function familyOf(address) {
  const text = stripBrackets(String(address).trim());
  return text.includes(':') ? 6 : 4;
}

/**
 * Remove surrounding brackets from `[::1]`.
 *
 * @param {string} text
 * @returns {string}
 */
function stripBrackets(text) {
  if (text.startsWith('[') && text.endsWith(']')) return text.slice(1, -1);
  return text;
}

/**
 * Unwrap an IPv4-mapped IPv6 address (`::ffff:127.0.0.1`).
 *
 * A dual-stack server sees every IPv4 client as `::ffff:a.b.c.d`. Leaving that
 * intact would put four million distinct IPv4 clients into one /64 bucket, so
 * the mapping is removed and the address treated as IPv4.
 *
 * @param {string} text
 * @returns {string|null} the IPv4 form, or null when it is not mapped
 */
function unwrapMappedIPv4(text) {
  const m = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(text);
  return m ? m[1] : null;
}

/**
 * Validate a prefix length for a family.
 *
 * @param {number} prefix
 * @param {number} bits
 * @param {string} label
 */
function assertPrefix(prefix, bits, label) {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) {
    throw new RangeError(`${label} prefix must be an integer 0..${bits}, got ${prefix}`);
  }
}

/**
 * Compute the rate-limit identity of a client.
 *
 * @param {string} address remote address, in any of the forms Node produces
 * @param {object} [options]
 * @param {number} [options.ipv6Prefix=64] prefix used for IPv6 identities
 * @param {number} [options.ipv4Prefix=32] prefix used for IPv4 identities
 * @returns {{
 *   raw: string, normalized: string, family: 4|6, subnetSize: string,
 *   prefix: number, mapped: boolean
 * }}
 */
function identityOf(address, options = {}) {
  if (address === undefined || address === null || address === '') {
    throw new RangeError('client address is required');
  }
  const ipv6Prefix = options.ipv6Prefix ?? DEFAULT_IPV6_PREFIX;
  const ipv4Prefix = options.ipv4Prefix ?? DEFAULT_IPV4_PREFIX;

  let text = stripBrackets(String(address).trim());
  let mapped = false;

  // Unwrap ::ffff:a.b.c.d so IPv4 clients are not collapsed into one /64.
  const v4 = unwrapMappedIPv4(text);
  if (v4 !== null) {
    text = v4;
    mapped = true;
  }

  const family = familyOf(text);
  const normalized =
    family === 6 ? maskIPv6(text, ipv6Prefix) : maskIPv4(text, ipv4Prefix);
  const prefix = family === 6 ? ipv6Prefix : ipv4Prefix;

  return Object.freeze({
    raw: String(address),
    normalized,
    family,
    subnetSize: subnetSize(prefix, family),
    prefix,
    mapped,
  });
}

/**
 * True when two addresses share a rate-limit identity.
 *
 * @param {string} a
 * @param {string} b
 * @param {object} [options] see {@link identityOf}
 * @returns {boolean}
 */
function sameIdentity(a, b, options = {}) {
  try {
    return identityOf(a, options).normalized === identityOf(b, options).normalized;
  } catch {
    return false;
  }
}

module.exports = Object.freeze({
  DEFAULT_IPV4_PREFIX,
  DEFAULT_IPV6_PREFIX,
  parseIPv4,
  formatIPv4,
  maskIPv4,
  parseIPv6,
  formatIPv6,
  maskIPv6,
  ipv6ToBigInt,
  subnetSize,
  identityOf,
  sameIdentity,
  familyOf,
  stripBrackets,
  unwrapMappedIPv4,
});