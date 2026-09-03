/**
 * tests/session-engine.test.js — TTL / cleanup / capacity behavior added to
 * src/core/session-engine in the Phase 1 architecture pass (upgrade-spec
 * Section 57). Pure unit test against the module directly — no live server
 * needed, and tests/run-all.js spawns every *.test.js file as its own
 * fresh child process, so requiring session-engine here starts from a
 * clean, empty SESSIONS map every run.
 */
const assert = require("assert");
const se = require("../src/core/session-engine");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }

function makeReq(sid) {
  return { cookies: sid ? { sid } : {} };
}
function makeRes() {
  const cookies = {};
  return { cookie: (name, val) => { cookies[name] = val; }, _cookies: cookies };
}

function run() {
  // --- basic creation ------------------------------------------------
  const req1 = makeReq();
  const res1 = makeRes();
  const { sid: sid1, session: sess1 } = se.getOrInitSession(req1, res1);
  check("new session gets a sid", typeof sid1 === "string" && sid1.length > 0);
  check("new session cookie is set on the response", res1._cookies.sid === sid1);
  check("new session record has createdAt", typeof sess1.createdAt === "number");
  check("new session record has lastAccess", typeof sess1.lastAccess === "number");
  check("new session is tracked in SESSIONS", se.SESSIONS.has(sid1));

  // --- reuse updates lastAccess, doesn't re-issue a cookie ------------
  se.SESSIONS.get(sid1).lastAccess = Date.now() - 1000; // backdate
  const backdated = se.SESSIONS.get(sid1).lastAccess;
  const req2 = makeReq(sid1);
  const res2 = makeRes();
  const { sid: sid2, session: sess2 } = se.getOrInitSession(req2, res2);
  check("reusing an existing sid returns the same sid", sid2 === sid1);
  check("reusing an existing sid does not set a new cookie", res2._cookies.sid === undefined);
  check("reusing an existing sid bumps lastAccess forward", sess2.lastAccess >= backdated);

  // --- unknown sid gets a brand-new session, not an error ------------
  const req3 = makeReq("some-sid-that-was-never-issued");
  const res3 = makeRes();
  const { sid: sid3 } = se.getOrInitSession(req3, res3);
  check("an unrecognized sid cookie gets a fresh session instead of erroring", typeof sid3 === "string" && sid3 !== "some-sid-that-was-never-issued");

  // --- TTL cleanup -----------------------------------------------------
  const req4 = makeReq();
  const res4 = makeRes();
  const { sid: sidExpired } = se.getOrInitSession(req4, res4);
  se.SESSIONS.get(sidExpired).lastAccess = Date.now() - se.SESSION_TTL_MS - 5000; // well past TTL

  const req5 = makeReq();
  const res5 = makeRes();
  const { sid: sidFresh } = se.getOrInitSession(req5, res5); // stays fresh (lastAccess = now)

  const removed = se.cleanupExpiredSessions();
  check("cleanupExpiredSessions removes at least the one expired session", removed >= 1, "removed=" + removed);
  check("the expired session is actually gone", !se.SESSIONS.has(sidExpired));
  check("a fresh session survives cleanup", se.SESSIONS.has(sidFresh));

  // --- capacity cap ------------------------------------------------------
  se.SESSIONS.clear();
  const now = Date.now();
  // Fill to exactly MAX_SESSIONS, staggering lastAccess so there's an
  // unambiguous least-recently-used entry to evict.
  let oldestSid = null;
  for (let i = 0; i < se.MAX_SESSIONS; i++) {
    const sid = "synthetic-" + i;
    if (i === 0) oldestSid = sid;
    se.SESSIONS.set(sid, { canonicalId: null, notes: [], lab: {}, createdAt: now - (se.MAX_SESSIONS - i), lastAccess: now - (se.MAX_SESSIONS - i) });
  }
  check("synthetic fill reached MAX_SESSIONS", se.SESSIONS.size === se.MAX_SESSIONS, se.SESSIONS.size);

  const reqCap = makeReq();
  const resCap = makeRes();
  se.getOrInitSession(reqCap, resCap); // one more than capacity
  check("SESSIONS never exceeds MAX_SESSIONS after going over capacity", se.SESSIONS.size <= se.MAX_SESSIONS, se.SESSIONS.size);
  check("the least-recently-used synthetic session was evicted to make room", !se.SESSIONS.has(oldestSid));

  // --- sessionStats() ------------------------------------------------
  const stats = se.sessionStats();
  check("sessionStats reports a total", typeof stats.total === "number");
  check("sessionStats reports the configured max", stats.maxSessions === se.MAX_SESSIONS);
  check("sessionStats reports the configured TTL", stats.ttlMs === se.SESSION_TTL_MS);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run();
