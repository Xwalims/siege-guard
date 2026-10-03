'use strict';

/**
 * The Redis path is the only part of this package that cannot be exercised
 * without infrastructure, so it is also the part most likely to be wrong
 * silently.
 *
 * ## What is actually verified here
 *
 * There is no Lua interpreter and no Redis on the build host, so the script's
 * *behaviour* cannot be run. What can be verified, and what broke in practice,
 * is the **contract between the script that writes a sorted-set member and the
 * two code paths that read it**: the script's own `string.match` reader and
 * `RedisStore#peek`.
 *
 * The first version of this file regex-matched the script's *shape* -- it
 * asserted that `ZREMRANGEBYSCORE` appeared and that the budget check came
 * before the `ZADD`. That passed while the store was completely broken, because
 * the members the script wrote did not encode the cost where either reader
 * looked for it.
 *
 * So these tests read the *actual expressions* out of SPEND_SCRIPT, translate
 * them faithfully, and run a real round trip: write members with the script's
 * writer, read them back with the script's reader, and require the cost to
 * survive. Change either side's field order and this fails.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { RedisStore, InMemoryStore } = require('../src/store.js');

const SCRIPT = new RedisStore({ client: {} }).SPEND_SCRIPT;

// ---------------------------------------------------------------------------
// Mechanical translation of the two Lua expressions into JavaScript.
//
// Deliberately not hand-written constants: reading them out of SPEND_SCRIPT is
// the whole point, so that the test tracks the script rather than a copy of it.
// ---------------------------------------------------------------------------

/** Pull the pattern out of `string.match(<x>, '<pat>')`. */
function scriptReaderPattern() {
  const m = /string\.match\([^,]+,\s*'([^']+)'\)/.exec(SCRIPT);
  assert.ok(m, 'SPEND_SCRIPT must call string.match to read the cost back');
  return m[1];
}

/** Pull the member expression out of `redis.call('ZADD', key, <score>, <member>)`. */
function scriptMemberExpression() {
  const m = /redis\.call\('ZADD',\s*key,\s*[^,]+,\s*(.+?)\)\s*\n/.exec(SCRIPT);
  assert.ok(m, 'SPEND_SCRIPT must ZADD with a member built from a string expression');
  return m[1].trim();
}

/** Describe a Lua concat expression as an ordered list of {kind, value} parts. */
function parseLuaConcat(expression) {
  const parts = [];
  for (const chunk of expression.split(/\s*\.\.\s*/)) {
    const literal = /^'([^']*)'$/.exec(chunk);
    if (literal) {
      parts.push({ kind: 'literal', value: literal[1] });
      continue;
    }
    const call = /^tostring\((\w+)\)$/.exec(chunk);
    const bare = /^(\w+)$/.exec(chunk);
    if (call) parts.push({ kind: 'var', value: call[1] });
    else if (bare) parts.push({ kind: 'var', value: bare[1] });
    else {
      // Anything more elaborate than `tostring(v)` or a literal is unhandled.
      assert.fail(`unhandled term in the ZADD member expression: ${chunk}`);
    }
  }
  return parts;
}

/** Evaluate a parsed member expression for one request. */
function buildMember(expression, vars) {
  return parseLuaConcat(expression)
    .map((part) => (part.kind === 'literal' ? part.value : String(vars[part.value])))
    .join('');
}

/**
 * Compile a Lua pattern to a JavaScript RegExp.
 *
 * Handles the escapes Lua patterns use for character classes: `%d` is a digit,
 * `%.` is a literal dot, `%-` a literal hyphen. `^`, `+`, `*` and capture groups
 * behave the same in both languages. Anything else is left alone, so an
 * unfamiliar escape shows up as a failing assertion rather than a silent
 * mis-translation.
 */
function luaPatternToJs(pattern) {
  const out = [];
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (ch === '%') {
      const next = pattern[i + 1];
      assert.ok(next !== undefined, `dangling % in Lua pattern ${pattern}`);
      out.push({ d: '\\d', D: '\\D', s: '[ \\t\\n\\r\\f\\v]', w: '\\w' }[next] ?? `\\${next}`);
      i += 1;
      continue;
    }
    out.push(ch === '(' || ch === ')' ? ch : `\\${ch}`.length === 1 && '\\^$.|?*+'.includes(ch) ? `\\${ch}` : ch);
  }
  return new RegExp(out.join(''));
}

/** The cost, as the Lua script's own reader sees it. Returns null if it cannot read one. */
function costAsLuaSeesIt(pattern, member) {
  const m = luaPatternToJs(pattern).exec(member);
  return m && m[1] !== undefined ? Number(m[1]) : null;
}

// ---------------------------------------------------------------------------
// The contract itself
// ---------------------------------------------------------------------------

test('the cost survives a round trip through the script\'s own writer and reader', () => {
  const pattern = scriptReaderPattern();
  const expression = scriptMemberExpression();

  // What RedisStore#spend actually passes as ARGV[5], captured from a live call
  // rather than guessed.
  const sent = [];
  const client = { async eval(_script, args) { sent.push(args); return [1, '0', '0']; } };
  const store = new RedisStore({ client });
  return store.spend('198.51.100.1', 5, 60_000, 100, 1_750_000_000_000).then(() => {
    const { arguments: argv } = sent[0];
    const vars = {
      cost: Number(argv[2]),
      now: Number(argv[3]),
      member: argv[4],
      ARGV1: argv[0],
    };

    const stored = buildMember(expression, vars);
    assert.ok(stored.includes(String(vars.cost)), 'the cost must reach the stored member');

    const read = costAsLuaSeesIt(pattern, stored);
    assert.ok(
      read !== null && !Number.isNaN(read),
      `the script's own reader could not read a cost out of the member it writes: ${stored}`
    );
    assert.equal(
      read,
      vars.cost,
      `the script's reader returned ${read} for a request that cost ${vars.cost}`
    );
  });
});

test('every cost shape survives the round trip', () => {
  const pattern = scriptReaderPattern();
  const expression = scriptMemberExpression();
  const member = 'k3f9az11';
  for (const cost of [1, 2, 5, 0.5, 0.25, 17, 100, 3.5]) {
    const stored = buildMember(expression, { cost, now: 1_750_000_000_000, member });
    const read = costAsLuaSeesIt(pattern, stored);
    assert.equal(read, cost, `cost ${cost} came back as ${read} from member ${stored}`);
  }
});

test('peek reads what the script writes', async () => {
  const pattern = scriptReaderPattern();
  const expression = scriptMemberExpression();
  const member = 'k3f9az11';
  const costs = [5, 5, 5];
  const now = 1_750_000_000_000;

  // A client that behaves like Redis: ZRANGE ... WITHSCORES flattens to
  // [member, score, member, score, ...].
  const rows = [];
  costs.forEach((cost, i) => {
    const at = now + i;
    rows.push(buildMember(expression, { cost, now: at, member: `${member}${i}` }), String(at));
  });

  const client = { async zrange() { return rows; } };
  const store = new RedisStore({ client });
  const peeked = await store.peek('198.51.100.1', 60_000, now + 10);

  const expectedByLua = costs.reduce((sum, _c, i) => sum + costAsLuaSeesIt(pattern, rows[i * 2]), 0);
  assert.equal(
    expectedByLua,
    costs.reduce((a, b) => a + b, 0),
    'sanity: the script\'s reader totals the same as the known costs'
  );
  assert.equal(
    peeked.used,
    expectedByLua,
    `peek reported ${peeked.used} where the script's reader reports ${expectedByLua}`
  );
});

test('peek and the script agree across a window boundary', async () => {
  const expression = scriptMemberExpression();
  const now = 1_750_000_000_000;
  const client = {
    async zrange() {
      return [
        buildMember(expression, { cost: 5, now: now - 120_000, member: 'old' }),
        String(now - 120_000),
        buildMember(expression, { cost: 3, now: now - 1_000, member: 'new' }),
        String(now - 1_000),
      ];
    },
  };
  const store = new RedisStore({ client });
  const peeked = await store.peek('k', 60_000, now);
  assert.equal(peeked.used, 3, 'only the member inside the window counts');
});

test('a member written by an older version reads as 0, not as a timestamp', async () => {
  // The bug that shipped: cost last, behind a colon. A leading-number reader
  // gets the arrival time. Requiring the reading to be sane is what stops a
  // silent 1.75e12-inflated budget from coming back.
  const client = {
    async zrange() {
      return ['1750000000000-5-d4nabsfx:5', '1750000000000'];
    },
  };
  const store = new RedisStore({ client });
  const peeked = await store.peek('k', 60_000, 1_750_000_010_000);
  assert.ok(
    peeked.used < 1_000,
    `a legacy member must not read as a multi-trillion budget, got ${peeked.used}`
  );
});

// ---------------------------------------------------------------------------
// The script's shape -- kept from the original test, now meaningful rather
// than sufficient
// ---------------------------------------------------------------------------

test('the script checks the budget before it writes', () => {
  const check = SCRIPT.indexOf('used + cost > limit');
  assert.ok(check > -1, 'the budget test must be in the script');
  assert.ok(check < SCRIPT.indexOf('ZADD'), 'or the gate is racy');
  assert.match(SCRIPT, /ZREMRANGEBYSCORE/, 'the window must be trimmed server side');
});

test('the reader cannot silently return nil for a member the writer produces', () => {
  // The original failure was `tonumber(string.match(...) or '0')` reading a
  // non-numeric field. Guard the shape: whatever the writer builds, a leading
  // number must exist in it.
  const pattern = scriptReaderPattern();
  const expression = scriptMemberExpression();
  const stored = buildMember(expression, { cost: 5, now: 1_750_000_000_000, member: 'abc123' });
  const read = costAsLuaSeesIt(pattern, stored);
  assert.equal(typeof read, 'number', 'a member this script wrote must yield a number');
  assert.ok(!Number.isNaN(read));
});

test('the static member helper and the script agree', () => {
  const expression = scriptMemberExpression();
  const scriptShape = buildMember(expression, { cost: 7, now: 42, member: 'u' });
  assert.equal(RedisStore.member(7, 42, 'u'), scriptShape, 'the JS helper must match the Lua writer');
});

test('costOf matches the script reader on anything either can produce', () => {
  const pattern = scriptReaderPattern();
  for (const cost of [1, 5, 0.5, 12.25]) {
    for (const member of ['ab12', 'z', '0009']) {
      const stored = buildMember(scriptMemberExpression(), { cost, now: 1_750_000_000_000, member });
      assert.equal(RedisStore.costOf(stored), costAsLuaSeesIt(pattern, stored), stored);
    }
  }
});

test('a full Redis-backed budget matches the in-process one', async () => {
  // Same arithmetic, run through the extraction rules both sides use: the Lua
  // script's reader for the write path, RedisStore#costOf for peek. Not a
  // substitute for running the script on a real server, but it does hold the
  // two implementations to the same answer.
  const local = new InMemoryStore();
  const expression = scriptMemberExpression();
  const pattern = scriptReaderPattern();
  const now = 1_750_000_000_000;
  const rows = [];

  const fake = {
    async zrange() { return rows.slice(); },
    async eval(_s, args) {
      const [winMs, limit, cost, at] = args.arguments;
      const costNum = Number(cost);
      let used = 0;
      for (let i = 0; i < rows.length; i += 2) used += costAsLuaSeesIt(pattern, rows[i]) || 0;
      if (used + costNum > Number(limit)) return [0, String(used), '1'];
      rows.push(buildMember(expression, { cost: costNum, now: Number(at), member: `m${rows.length}` }), String(Number(at)));
      return [1, String(used + costNum), '0'];
    },
    async del() { return 1; },
    async scan() { return ['0', []]; },
  };
  const store = new RedisStore({ client: fake });

  let remoteAllowed = 0;
  let localAllowed = 0;
  for (let i = 0; i < 200; i += 1) {
    const at = now + i;
    if ((await store.spend('k', 5, 60_000, 100, at)).allowed) remoteAllowed += 1;
    if (local.spend('k', 5, 60_000, 100, at).allowed) localAllowed += 1;
  }
  assert.equal(remoteAllowed, localAllowed, 'the shared store and the local one must agree');
  assert.equal(remoteAllowed, 20, '100 budget at cost 5 is 20 requests');
});
