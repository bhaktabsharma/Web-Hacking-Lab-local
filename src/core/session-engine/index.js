/**
 * src/core/session-engine — the platform's in-memory session store.
 *
 * Extracted from routes/vuln-common.js during the Phase 1 architecture
 * pass (see docs/UPGRADE-LOG.md). Behavior is unchanged EXCEPT for the
 * addition described below — this was the "Session Cleanup" gap called
 * out explicitly in upgrade-spec Section 57:
 *
 *   "The current in-memory session architecture is acceptable for local
 *   use, but add: TTL, last-access timestamp, cleanup, maximum session
 *   protection. Do not allow unlimited session accumulation."
 *
 * What's new here:
 *   - every session record now carries createdAt/lastAccess timestamps
 *   - a background sweep (unref'd — never keeps the process alive on its
 *     own, so it can't break the child-process test runner in
 *     tests/run-all.js) evicts sessions idle longer than SESSION_TTL_MS
 *   - a soft MAX_SESSIONS cap evicts the least-recently-used session
 *     before a new one would exceed it
 *
 * Still an in-memory Map, as the spec explicitly says is fine for local
 * use — this only adds the missing hygiene around it, it doesn't change
 * the storage model.
 */
const { randomHex } = require("../../utils/random");

const SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours of inactivity
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000; // sweep every 10 minutes
const MAX_SESSIONS = 5000; // generous ceiling for a local training tool, not a real capacity target

// sid -> { canonicalId, notes, lab: { [labId]: {...state} }, createdAt, lastAccess }
const SESSIONS = new Map();

function evictLeastRecentlyUsed() {
  let oldestSid = null;
  let oldestAccess = Infinity;
  for (const [sid, rec] of SESSIONS.entries()) {
    if (rec.lastAccess < oldestAccess) {
      oldestAccess = rec.lastAccess;
      oldestSid = sid;
    }
  }
  if (oldestSid) SESSIONS.delete(oldestSid);
}

function getOrInitSession(req, res) {
  let sid = req.cookies.sid;
  let record = sid ? SESSIONS.get(sid) : undefined;

  if (!sid || !record) {
    sid = randomHex(16);
    res.cookie("sid", sid, { httpOnly: false });
    if (SESSIONS.size >= MAX_SESSIONS) evictLeastRecentlyUsed();
    record = { canonicalId: null, notes: [], lab: {}, createdAt: Date.now(), lastAccess: Date.now() };
    SESSIONS.set(sid, record);
  } else {
    record.lastAccess = Date.now();
  }

  return { sid, session: record };
}

function cleanupExpiredSessions(now = Date.now()) {
  let removed = 0;
  for (const [sid, rec] of SESSIONS.entries()) {
    if (now - (rec.lastAccess || rec.createdAt || 0) > SESSION_TTL_MS) {
      SESSIONS.delete(sid);
      removed++;
    }
  }
  return removed;
}

function sessionStats() {
  return { total: SESSIONS.size, maxSessions: MAX_SESSIONS, ttlMs: SESSION_TTL_MS };
}

const sweepHandle = setInterval(() => cleanupExpiredSessions(), CLEANUP_INTERVAL_MS);
sweepHandle.unref();

module.exports = {
  SESSIONS,
  getOrInitSession,
  cleanupExpiredSessions,
  sessionStats,
  SESSION_TTL_MS,
  MAX_SESSIONS,
};
