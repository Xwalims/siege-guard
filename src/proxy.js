'use strict';

/**
 * Client address extraction behind reverse proxies.
 *
 * ## Why this is not a one-liner
 *
 * `req.socket.remoteAddress` is the address of whoever opened the TCP
 * connection. Behind a reverse proxy that is always the proxy, so every client
 * shares one budget and the limiter does nothing at all.
 *
 * The obvious fix is to read `X-Forwarded-For`. That header is **client
 * controlled**: a stranger can send `X-Forwarded-For: 1.2.3.4` and every proxy
 * in the path appends to it, producing `1.2.3.4, <real client>`. If the
 * application trusts the leftmost entry it has been handing rate-limit
 * identity to whoever asked for it.
 *
 * So the address is derived from the **trusted chain**, built right to left:
 *
 *   1. Start from the socket, which cannot be forged.
 *   2. Walk the configured proxy addresses right to left. Each hop that matches
 *      a trusted proxy is a hop that may have appended a claim.
 *   3. Stop at the first address that is not a trusted proxy. That is the
 *      client, and it is the first value no proxy can have vouched for.
 *
 * `X-Forwarded-For: 1.2.3.4, 5.6.7.8` behind exactly one trusted proxy yields
 * `5.6.7.8`, not `1.2.3.4`. The forged leftmost entry is discarded because the
 * walk never reaches it.
 */

/** Headers that carry a proxy chain, in the order they are consulted. */
const CHAIN_HEADERS = Object.freeze(['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip']);

/**
 * The mask for octet `i` of a `bits`-wide IPv4 prefix.
 *
 * The shift has to be clamped to 0..8. Written as
 * `0xff << (8 - (bits - i * 8))` the shift goes *negative* for every octet that
 * is entirely inside the prefix once `bits - i * 8` exceeds 8 -- that is, for
 * every octet except the last partially-covered one. JavaScript does not throw
 * on a negative shift, it masks the count with `& 31`, so `0xff << -7` is
 * `0xff << 25`, i.e. 0. The result was that octet 0 of a `/16` compared against
 * a mask of 0: `10.0.0.0/16` reported `192.0.0.1` and `11.0.0.1` as inside it,
 * trusting 256x more addresses than configured, and believing the X-Forwarded-For
 * of an attacker outside the proxy range.
 *
 * @param {number} i 0..3
 * @param {number} bits 0..32
 * @returns {number} 0..255
 */
function octetMask(i, bits) {
  const significant = Math.max(0, Math.min(8, bits - i * 8));
  if (significant === 0) return 0;
  return (0xff << (8 - significant)) & 0xff;
}

/**
 * Parse a dotted-quad into four integers, or return null.
 *
 * `Number('zzz')` is NaN, and every comparison against NaN is false, so a
 * malformed octet used to make an address silently match any prefix it should
 * have failed: `10.zzz.0.0` was "inside" `10.0.0.0/16`. Rejecting the whole
 * address is the only safe answer, since a caller that cannot parse the peer
 * has no business trusting it.
 *
 * Leading zeros are rejected as well, and that one costs a page of history.
 * `Number('010')` is 10 in decimal but 8 in octal to a reader expecting octal,
 * so `010.000.000.001`, `001.1.1.1` and `192.168.001.1` each name a
 * *different* address depending on who parses them. `node:net`'s `isIPv4`
 * rejects all of them, as does python's `ipaddress`; both were checked.
 *
 * That matters here because the chain walk feeds attacker-written header text
 * straight back into this function: `current = candidate` on the way back
 * through the X-Forwarded-For loop. With `trustedProxies: ['10.0.0.0/8']` and a
 * real proxy on `10.0.0.1`, the header `"6.6.6.6, 010.000.000.001"` was read as
 * a two-hop chain whose middle hop was `10.0.0.1`, so the walk believed the
 * attacker's leftmost `6.6.6.6` AND reported the whole chain as trusted. A
 * malformed octet must not be a way to spell a trusted address.
 *
 * @param {string} text
 * @returns {number[]|null} four octets, or null
 */
function parseIPv4(text) {
  const parts = String(text).split('.');
  if (parts.length !== 4) return null;
  const out = new Array(4);
  for (let i = 0; i < 4; i += 1) {
    if (!/^\d{1,3}$/.test(parts[i])) return null;
    // `010` is not a decimal 10 -- it is ambiguous, so it is not an address.
    if (parts[i].length > 1 && parts[i][0] === '0') return null;
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out[i] = n;
  }
  return out;
}

/** Headers that carry exactly one address, not a chain. */
const SINGLE_HEADERS = Object.freeze([
  'cf-connecting-ip',
  'true-client-ip',
  'fly-client-ip',
  'x-real-ip',
]);

/**
 * A trusted proxy list that knows the loopback addresses by default.
 *
 * @param {object} [options]
 * @param {string[]} [options.trustedProxies] CIDRs or bare addresses
 * @param {boolean} [options.trustLoopback=true]
 * @param {number} [options.maxHops] hard cap on chain length
 * @returns {object} a resolver with a `.resolve(req)` method
 */
function createAddressResolver(options = {}) {
  const maxHops = options.maxHops ?? 32;
  const trusted = (options.trustedProxies || []).map(String);
  if (options.trustLoopback !== false) {
    trusted.push('127.0.0.1', '::1', '::ffff:127.0.0.1');
  }

  /**
   * Is this address inside one of the trusted ranges?
   *
   * Supports bare addresses and IPv4 CIDR. IPv6 CIDR is intentionally not
   * supported here: getting it wrong would mean trusting a proxy that should not
   * be trusted, which is the exact failure this module exists to prevent.
   *
   * @param {string} address
   * @returns {boolean}
   */
  function isTrusted(address) {
    if (!address) return false;
    if (trusted.includes(address)) return true;
    const octets = parseIPv4(address);
    if (!octets) return false;
    for (const entry of trusted) {
      const slash = entry.indexOf('/');
      if (slash === -1) continue;
      const base = entry.slice(0, slash);
      const bits = Number(entry.slice(slash + 1));
      if (!Number.isInteger(bits) || bits < 0 || bits > 32) continue;
      const baseOctets = parseIPv4(base);
      if (!baseOctets) continue;
      let ok = true;
      for (let i = 0; i < 4; i += 1) {
        const mask = octetMask(i, bits);
        if ((octets[i] & mask) !== (baseOctets[i] & mask)) ok = false;
      }
      if (ok) return true;
    }
    return false;
  }

  /**
   * Extract the client address, trusting only the configured proxies.
   *
   * @param {object} req a Node IncomingMessage, or anything with headers/socket
   * @returns {{address: string|null, trusted: boolean, chain: string[], source: string,
   *            untrustedPrefix: boolean}}
   */
  function resolve(req) {
    const socketAddress =
      (req.socket && req.socket.remoteAddress) ||
      (req.connection && req.connection.remoteAddress) ||
      null;

    const headers = {};
    for (const [key, value] of Object.entries((req && req.headers) || {})) {
      headers[String(key).toLowerCase()] = value;
    }

    // No proxy in front, or no list: the socket is the only honest answer.
    if (trusted.length === 0 || !socketAddress) {
      return {
        address: socketAddress,
        trusted: true,
        chain: [],
        source: 'socket',
        untrustedPrefix: false,
      };
    }

    // A single-address header is only honoured when the socket itself is a
    // trusted proxy, otherwise it is just a stranger asserting who they are.
    for (const header of SINGLE_HEADERS) {
      const value = headers[header];
      if (!value || !isTrusted(socketAddress)) continue;
      const candidate = String(value).split(',')[0].trim();
      if (candidate) {
        return {
          address: candidate,
          trusted: true,
          chain: [socketAddress],
          source: header,
          untrustedPrefix: false,
        };
      }
    }

    // The chain, right to left.
    const raw = headers['x-forwarded-for'];
    const claims = raw ? String(raw).split(',').map((s) => s.trim()).filter(Boolean) : [];

    if (claims.length === 0) {
      return {
        address: socketAddress,
        trusted: true,
        chain: [],
        source: 'socket',
        untrustedPrefix: false,
      };
    }

    if (claims.length > maxHops) {
      return {
        address: null,
        trusted: false,
        chain: claims,
        source: 'x-forwarded-for',
        untrustedPrefix: true,
        reason: `chain of ${claims.length} exceeds maxHops ${maxHops}`,
      };
    }

    // Walk backwards. The first address that is NOT a trusted proxy is the
    // client: everything to its left was appended by something that does not
    // get to speak for the client.
    let current = socketAddress;
    let resolved = null;
    let index = claims.length - 1;
    const walked = [];
    while (index >= 0) {
      const candidate = claims[index];
      if (!isTrusted(current)) break;
      walked.push(current);
      resolved = candidate;
      current = candidate;
      index -= 1;
    }

    if (resolved === null) {
      // The socket is not a trusted proxy, so no claim may be believed.
      return {
        address: socketAddress,
        trusted: true,
        chain: claims,
        source: 'socket',
        untrustedPrefix: true,
        reason: 'socket is not a trusted proxy, so forwarding headers were ignored',
      };
    }

    // Whatever remains to the left of the client was never vouched for.
    const untrustedPrefix = index >= 0;

    return {
      address: resolved,
      trusted: !untrustedPrefix,
      chain: walked,
      source: 'x-forwarded-for',
      untrustedPrefix,
      reason: untrustedPrefix
        ? `discarded ${index + 1} untrusted leading entr(y/ies) from the forwarding chain`
        : undefined,
    };
  }

  return Object.freeze({
    resolve,
    isTrusted,
    trustedProxies: Object.freeze([...trusted]),
    maxHops,
  });
}

module.exports = Object.freeze({
  createAddressResolver,
  CHAIN_HEADERS,
  SINGLE_HEADERS,
});