/**
 * src/core/progress-engine — server-authoritative "solved" state.
 *
 * Extracted from routes/vuln-common.js (Phase 1 architecture pass, see
 * docs/UPGRADE-LOG.md). Behavior unchanged.
 *
 * Previously "solved" status lived ONLY in the browser's localStorage,
 * meaning it could be set directly from the frontend (e.g. via DevTools)
 * with no real exploit ever having happened. markSolved() is the only way
 * a lab is recorded as solved, and it is only ever called from
 * POST /api/validate-lab and POST /api/confirm-client-exploit, strictly
 * after flag-engine's checkFlag()/confirmClientProof() has confirmed a
 * genuine, session-issued flag was submitted. GET /api/progress exposes
 * this session's real state so the frontend can treat it as the source of
 * truth instead of trusting its own cache.
 */
function markSolved(session, labId, difficulty) {
  if (!session.progress) session.progress = {};
  const already = session.progress[labId];
  session.progress[labId] = { solved: true, difficulty, solvedAt: already ? already.solvedAt : Date.now() };
}

function getProgressSummary(session) {
  return { solved: session.progress || {}, hintsUsed: session.hints || {} };
}

module.exports = { markSolved, getProgressSummary };
