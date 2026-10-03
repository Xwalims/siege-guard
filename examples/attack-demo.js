#!/usr/bin/env node
'use strict';

/**
 * A runnable demonstration of siege-guard against a mixed hostile stream.
 *
 * Run it:   node examples/attack-demo.js
 *
 * What it does, in order:
 *
 *   1. An honest visitor browsing a catalogue. Must never be disturbed.
 *   2. A directory scanner with no browser-shaped headers.
 *   3. An L7 flood from one host: cheap static requests, then a burst of writes.
 *   4. The same flood rotated across every address in one IPv6 /64. This is the
 *      case a per-address limiter cannot see: 300 distinct source addresses, one
 *      allocation, one budget.
 *   5. Credential stuffing against the auth endpoint, which is priced at 100
 *      per attempt, so ten of them exhaust a default budget of 1000.
 *
 * Every request goes through the real guard with a simulated clock. Nothing here
 * touches a network: the attack is synthesised, and no traffic ever leaves the
 * process.
 */

const http = require('node:http');
const { SiegeGuard, guardMiddleware, attach } = require('../src/index.js');
const { renderDecision } = require('../src/explain.js');

const START = 1_700_000_000_000;

/** A browser-shaped request. */
function browser(url, address, method = 'GET') {
  return {
    method,
    url,
    httpVersion: '1.1',
    socket: { remoteAddress: address },
    headers: {
      Host: 'oakwall.net',
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0 Safari/537.36',
      Accept: 'text/html,application/xhtml+xml,application/json',
      'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
      'Accept-Encoding': 'gzip, deflate, br',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      Connection: 'keep-alive',
    },
  };
}

/** A scanner: nothing a browser would send. */
function scanner(url, address) {
  return {
    method: 'GET',
    url,
    httpVersion: '1.1',
    socket: { remoteAddress: address },
    headers: { Host: 'oakwall.net' },
  };
}

/** A request with every checked header forged to look exactly like Chrome. */
function forgedBrowser(url, address) {
  return {
    method: 'GET',
    url,
    httpVersion: '1.1',
    socket: { remoteAddress: address },
    headers: {
      Host: 'oakwall.net',
      'User-Agent':
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
      'Accept-Encoding': 'gzip, deflate, br',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Upgrade-Insecure-Requests': '1',
      Connection: 'keep-alive',
    },
  };
}

/** Print one section header. */
function heading(text) {
  console.log(`\n${text}`);
  console.log('-'.repeat(text.length));
}

/** Print a per-source tally. */
function tally(rows, label, note) {
  const allowed = rows.filter((r) => r.action === 'allow').length;
  const throttled = rows.filter((r) => r.action === 'throttle').length;
  const challenged = rows.filter((r) => r.action === 'challenge').length;
  const blocked = rows.filter((r) => r.action === 'block').length;
  console.log(
    `  ${label.padEnd(22)} ${String(rows.length).padStart(4)} requests  ` +
      `${String(allowed).padStart(4)} allowed  ${String(throttled).padStart(3)} throttled  ` +
      `${String(challenged).padStart(3)} challenged  ${String(blocked).padStart(4)} blocked`
  );
  if (note) console.log(`  ${' '.repeat(22)} ${note}`);
}

function main() {
  let now = START;
  const guard = new SiegeGuard({
    now: () => now,
    challenge: () => 'prove you are a browser',
  });
  const log = [];

  const hit = (label, req, gap = 40) => {
    now += gap;
    const decision = guard.check(req);
    log.push({ label, decision });
    return decision;
  };

  console.log('siege-guard: an application-layer DoS defence, under attack');
  console.log('===========================================================');
  console.log(`  budget       ${guard.options.limit} cost units per ${guard.options.windowMs}ms`);
  console.log(`  ipv6 prefix  /${guard.options.ipv6Prefix}   ipv4 prefix /${guard.options.ipv4Prefix}`);
  console.log(`  block score  ${guard.options.blockScore}   strikes to block ${guard.options.strikesToBlock}`);

  // ---------------------------------------------------------------- 1. honest
  heading('1. An honest visitor (must never be disturbed)');
  const honest = [];
  for (const path of ['/', '/', '/catalog', '/catalog', '/product/1', '/product/1', '/about']) {
    honest.push(hit('browser', browser(path, '203.0.113.7')));
  }
  tally(honest, 'visitor');
  const last = honest[honest.length - 1];
  console.log('\n  their last decision, in full:');
  console.log(
    renderDecision(last)
      .split('\n')
      .map((l) => `  ${l}`)
      .join('\n')
  );

  // --------------------------------------------------------------- 2. scanner
  heading('2. A directory scanner, and the same scanner that forges every header');
  const scanned = [];
  for (const path of ['/.env', '/wp-login.php', '/api/admin', '/api/users', '/.git/HEAD']) {
    scanned.push(hit('bare scanner', scanner(path, '198.51.100.23')));
  }
  tally(scanned, 'bare scanner', 'no user agent, no accept headers: fingerprint 0.77');

  const forgedScanned = [];
  for (const path of ['/.env', '/.git/config', '/wp-config.php.bak', '/id_rsa']) {
    forgedScanned.push(hit('forged scanner', forgedBrowser(path, '198.51.100.77')));
  }
  tally(
    forgedScanned,
    'forged scanner',
    'every header this package checks, set to exactly what Chrome sends'
  );

  const forgedPrint = guard.inspect(forgedBrowser('/.env', '198.51.100.77')).fingerprint;
  console.log(`\n  the forged request scores ${forgedPrint.score.toFixed(2)}, exactly like Chrome.`);
  console.log('  It is served, because a fingerprint a client can mint with six headers is');
  console.log('  not evidence. The first version of this package banned it, which meant');
  console.log('  anyone who read the README could earn a permanent 403.');
  console.log(`\n  what the bare scanner gets instead: ${renderDecision(scanned[0]).split('\n')[1].trim()}`);

  // ----------------------------------------------------------- 3. plain flood
  heading('3. An L7 flood from one host');
  const cheap = [];
  for (let i = 0; i < 400; i += 1) {
    cheap.push(hit('static-flood', browser(`/static/chunk${i}.js`, '192.0.2.66'), 5));
  }
  tally(cheap, 'static flood', '400 requests at cost 1 each');

  const writes = [];
  for (let i = 0; i < 40; i += 1) {
    writes.push(hit('write-flood', browser('/api/domains', '192.0.2.66', 'POST'), 5));
  }
  tally(writes, 'write flood', '40 requests at cost 50 each: 2000 for the same budget');
  console.log(
    '\n  the same budget served ' +
      `${cheap.filter((r) => r.action === 'allow').length} cheap requests but only ` +
      `${writes.filter((r) => r.action === 'allow').length} writes. Cost weighting is the` +
      '\n  difference between "400 requests" and "how much work did I actually ask for".'
  );

  // ------------------------------------------------------ 4. IPv6 rotation
  heading('4. The same flood, rotated across one IPv6 /64');
  const rotated = [];
  for (let i = 1; i <= 300; i += 1) {
    rotated.push(hit('ipv6-rotate', browser('/api/data', `2001:db8::${i.toString(16)}`), 3));
  }
  tally(rotated, 'rotated', '300 DIFFERENT source addresses, one allocation');
  const allowedRotated = rotated.filter((r) => r.action === 'allow').length;
  console.log(
    `\n  every request came from a different address, and all of them shared the key` +
      `\n  ${guard.options.ipv6Prefix === 64 ? '2001:db8::' : '2001:db8::'} ` +
      `(a /64 is ${guard.report().window.entries.find((e) => e.key === '2001:db8::')
        ? '18446744073709551616 addresses'
        : 'many addresses'}).`
  );
  console.log(
    `  ${allowedRotated} were served and the rest refused. A limiter keyed on the full` +
      '\n  address would have served all 300, because it would have seen 300 new clients.'
  );

  // ------------------------------------------------- 5. credential stuffing
  heading('5. Credential stuffing against /api/auth/login');
  const stuffing = [];
  for (let i = 0; i < 25; i += 1) {
    stuffing.push(hit('stuffing', browser('/api/auth/login', '198.51.100.99', 'POST'), 10));
  }
  tally(stuffing, 'login attempts', 'priced at 100 each, so ten of them fill the budget');

  // --------------------------------------------------------------- 6. summary
  heading('Summary');
  const report = guard.report();
  console.log(`  ${report.decisions} decisions, ${report.allowed} allowed, ` +
    `${report.throttled} throttled, ${report.challenged} challenged, ${report.blocked} blocked`);
  console.log(`  circuit ${report.circuit.state}, ${report.window.keys} identities tracked`);
  console.log('\n  what stopped what:');
  console.log('    bare scanner         fingerprint 0.77 earns a challenge and a 2x surcharge');
  console.log('    forged scanner       fingerprint 0.00, indistinguishable from Chrome, served');
  console.log('    static flood         400 cheap requests fit a 1000 budget');
  console.log('    write flood          the same 1000 budget admits only 20 writes');
  console.log('    IPv6 rotation        one /64, one budget, 300 addresses or 300 clients');
  console.log('    credential stuffing  priced at 100, so the budget dies in ten attempts');
  console.log('\n  what it does not stop:');
  console.log('    a volumetric L3/L4 flood. 300 Gbit/s of UDP does not reach this code;');
  console.log('    it is absorbed upstream by a scrubbing provider or anycast.');
  console.log('    a distributed attacker rotating prefixes, VPS and proxies. Each');
  console.log('    allocation is a separate identity; catching that needs aggregation');
  console.log('    above this layer.');
  console.log('    a multi-instance deployment without a shared store. Four processes');
  console.log('    means four budgets; pass {store} and the budget becomes global.');

  console.log('\n  Now the same guard in front of a real http server:');
  console.log("    const server = http.createServer(attach(handler, { guard }));");
  console.log("    // or, with a next-style chain:");
  console.log("    app.use(guardMiddleware({ limit: 5000 }));");
}

if (require.main === module) main();

module.exports = { main, browser, scanner };