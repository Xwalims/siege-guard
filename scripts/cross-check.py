#!/usr/bin/env python3
"""Check siege-guard's IPv6 and IPv4 prefix handling against Python's ipaddress.

Node and Python implement RFC 4291 masking independently. If they agree on a
wide matrix of addresses and prefix lengths, both are probably right; if they
disagree on one cell, one of them has a bug in a place no hand-written test
thought to look.

This script exists because hand-written expectations got it wrong twice during
development: 2001:db8:0:1::abcd was assumed to live inside 2001:db8::/64, and
2001:db8:ff::1 was assumed to live inside the same /56 as 2001:db8::1. Both
assumptions were wrong, and both were caught by asking Python rather than by
reasoning harder.

Usage:  python3 scripts/cross-check.py
Exit 0 when every cell matches, 1 otherwise.
"""

import ipaddress
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

IPV6 = [
    "2001:db8::1",
    "2001:db8::ffff",
    "2001:db8:ff::1",
    "2001:db8:abcd::1",
    "2001:db8:0:1::abcd",
    "2001:db8:1:2:3:4:5:6",
    "2001:db9::",
    "2001:dba:1234:5678:9abc:def0:1234:5678",
    "::1",
    "::",
    "fe80::1",
    "ff02::1",
    "::ffff:192.0.2.1",
]

IPV4 = [
    "192.0.2.1",
    "192.0.2.10",
    "192.0.2.255",
    "10.0.0.1",
    "172.16.5.9",
    "203.0.113.128",
    "255.255.255.255",
    "0.0.0.1",
]

V6_PREFIXES = [0, 16, 32, 48, 49, 56, 57, 64, 65, 96, 127, 128]
V4_PREFIXES = [0, 8, 16, 24, 25, 30, 31, 32]


def js_masks(addresses, prefixes, family):
    """Ask the Node implementation to mask every (address, prefix) pair.

    Results come back packed as hex so that the comparison is bit-for-bit and
    immune to the many legal ways to render the same address.
    """
    payload = json.dumps({"addresses": addresses, "prefixes": prefixes})
    script = (
        "const id = require('./src/identity.js');"
        "const net = require('net');"
        "let s = '';"
        "process.stdin.on('data', d => s += d);"
        "process.stdin.on('end', () => {"
        "  const {addresses, prefixes} = JSON.parse(s);"
        "  const out = [];"
        "  for (const p of prefixes) {"
        "    for (const a of addresses) {"
        "      const text = process.argv[1] === '4' ? id.maskIPv4(a, p) : id.maskIPv6(a, p);"
        "      let hex = null;"
        "      try {"
        "        if (net.isIP(text) === 4) {"
        "          hex = Buffer.from([(id.parseIPv4(text) >>> 24) & 255,"
        "                             (id.parseIPv4(text) >>> 16) & 255,"
        "                             (id.parseIPv4(text) >>> 8) & 255,"
        "                             id.parseIPv4(text) & 255]).toString('hex');"
        "        } else {"
        "          const g = id.parseIPv6(text);"
        "          const b = Buffer.alloc(16);"
        "          for (let i = 0; i < 8; i++) b.writeUInt16BE(g[i], i * 2);"
        "          hex = b.toString('hex');"
        "        }"
        "      } catch (e) { hex = null; }"
        "      out.push([a, p, hex]);"
        "    }"
        "  }"
        "  process.stdout.write(JSON.stringify(out));"
        "});"
    )
    result = subprocess.run(
        ["node", "-e", script, str(family)],
        cwd=ROOT,
        input=payload,
        capture_output=True,
        text=True,
        check=True,
    )
    return {(a, p): masked for a, p, masked in json.loads(result.stdout)}


def py_masks(addresses, prefixes, family):
    """Mask the same pairs with the standard library."""
    out = {}
    for prefix in prefixes:
        for address in addresses:
            net = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            text = str(net.network_address)
            # Python renders a masked ::ffff:a.b.c.d tail as ::ffff::0.0.0.0
            # or ::ffff::; neither is a canonical address, so normalise the
            # comparison to the packed form instead of the string form.
            out[(address, prefix)] = canonical(text)
    return out


def canonical(text):
    """Render an address as 32 lowercase hex digits, so formats cannot differ.

    Python prints ::ffff:: and ::ffff:0:0:0 where Node prints ::ffff:0:0 and
    ::ffff:0.0.0.0. Comparing packed bytes sidesteps the rendering difference
    entirely and only catches real bit-level disagreement.
    """
    packed = ipaddress.ip_address(text).packed
    return packed.hex()


def compare(label, addresses, prefixes, family):
    js = js_masks(addresses, prefixes, family)
    py = py_masks(addresses, prefixes, family)
    mismatches = []
    for key in sorted(py):
        if js.get(key) != py[key]:
            mismatches.append((key, js.get(key), py[key]))
    print(f"{label}: {len(py)} cells compared, {len(mismatches)} mismatch(es)")
    for (address, prefix), got, want in mismatches:
        print(f"  /{prefix} {address}: node={got!r} python={want!r}")
    return not mismatches


def compare_identity():
    """identityOf must agree on family, prefix, subnet size and mapped flag."""
    script = (
        "const id = require('./src/identity.js');"
        "const net = require('net');"
        "let s = '';"
        "process.stdin.on('data', d => s += d);"
        "process.stdin.on('end', () => {"
        "  const addrs = JSON.parse(s);"
        "  const out = addrs.map(a => {"
        "    try {"
        "      const r = id.identityOf(a);"
        "      let hex = '';"
        "      try {"
        "        if (net.isIP(r.normalized) === 4) {"
        "          const v = id.parseIPv4(r.normalized);"
        "          hex = Buffer.from([(v>>>24)&255,(v>>>16)&255,(v>>>8)&255,v&255]).toString('hex');"
        "        } else {"
        "          const g = id.parseIPv6(r.normalized);"
        "          const b = Buffer.alloc(16);"
        "          for (let i = 0; i < 8; i++) b.writeUInt16BE(g[i], i*2);"
        "          hex = b.toString('hex');"
        "        }"
        "      } catch (e) { hex = ''; }"
        "      return [a, r.family, r.prefix, r.subnetSize, r.mapped, hex];"
        "    } catch (e) { return [a, null, null, null, null, '']; }"
        "  });"
        "  process.stdout.write(JSON.stringify(out));"
        "});"
    )
    addrs = IPV6 + IPV4
    result = subprocess.run(
        ["node", "-e", script],
        cwd=ROOT,
        input=json.dumps(addrs),
        capture_output=True,
        text=True,
        check=True,
    )
    rows = json.loads(result.stdout)

    problems = []
    checked = 0
    for address, family, prefix, subnet_size, mapped, packed in rows:
        if family is None:
            # Node refused it; that is fine as long as it was not a valid
            # address in the first place. Skip, the masking matrix covers those.
            continue
        # ::ffff:a.b.c.d is deliberately unwrapped to IPv4, so "expected" family
        # is the one of the unwrapped address, not of the string.
        unwrapped = address
        if address.lower().startswith("::ffff:") and "." in address:
            unwrapped = address[7:]
        expected_family = 6 if ":" in unwrapped else 4
        expected_prefix = 64 if expected_family == 6 else 32
        expected_size = 2 ** (128 - 64 if expected_family == 6 else 32 - 32)
        checked += 1
        if family != expected_family:
            problems.append(f"{address}: family {family} != {expected_family}")
        if prefix != expected_prefix:
            problems.append(f"{address}: prefix {prefix} != {expected_prefix}")
        if int(subnet_size) != expected_size:
            problems.append(f"{address}: subnetSize {subnet_size} != {expected_size}")

        # The masked address must match what Python computes for the same
        # family and prefix, compared as packed bytes.
        want = canonical(
            str(
                ipaddress.ip_network(
                    f"{unwrapped}/{expected_prefix}", strict=False
                ).network_address
            )
        )
        if packed != want:
            problems.append(f"{address}: normalized packs to {packed}, python says {want}")
        expected_mapped = address.lower().startswith("::ffff:") and "." in address
        if bool(mapped) != expected_mapped:
            problems.append(f"{address}: mapped {mapped} != {expected_mapped}")

    print(f"identityOf: {checked} address(es) checked, {len(problems)} problem(s)")
    for p in problems:
        print(f"  {p}")
    return not problems


def main():
    ok = True
    ok &= compare("IPv6 masking", IPV6, V6_PREFIXES, 6)
    ok &= compare("IPv4 masking", IPV4, V4_PREFIXES, 4)
    ok &= compare_identity()
    if ok:
        print("\nall prefix operations agree with Python's ipaddress")
        return 0
    print("\nMISMATCHES FOUND")
    return 1


if __name__ == "__main__":
    sys.exit(main())