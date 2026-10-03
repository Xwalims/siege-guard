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
    for (const entry of trusted) {
      const slash = entry.indexOf('/');
      if (slash === -1) continue;
      const base = entry.slice(0, slash);
      const bits = Number(entry.slice(slash + 1));
      if (!Number.isInteger(bits) || bits < 0 || bits > 32) continue;
      const octets = address.split('.');
      const baseOctets = base.split('.');
      if (octets.length !== 4 || baseOctets.length !== 4) continue;
      let ok = true;
      for (let i = 0; i < 4; i += 1) {
        const mask = i * 8 >= bits ? 0 : 0xff << (8 - Math.max(0, bits - i * 8)) & 0xff;
        if ((Number(octets[i]) & mask) !== (Number(baseOctets[i]) & mask)) ok = false;
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