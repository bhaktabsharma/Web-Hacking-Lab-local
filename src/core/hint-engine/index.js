/**
 * src/core/hint-engine — hint-usage tracking.
 *
 * Extracted from routes/vuln-common.js (Phase 1 architecture pass, see
 * docs/UPGRADE-LOG.md). Behavior unchanged: purely a usage counter today,
 * fire-and-forget from the UI, never gates anything.
 *
 * PHASE 3 TODO (upgrade-spec Section 37): the spec asks for genuinely
 * progressive 3-level hint CONTENT (conceptual -> technical -> directional)
 * derived from structured per-lab metadata, not just a usage count. That
 * content model belongs to the lab-registry work in Phase 3 — this engine
 * is where the reveal-tracking logic for it will live once that content
 * exists, so the shape of recordHintUsed()'s counter is intentionally
 * compatible with becoming "which tier was last revealed" later.
 */
function recordHintUsed(session, labId) {
  if (!session.hints) session.hints = {};
  session.hints[labId] = (session.hints[labId] || 0) + 1;
  return session.hints[labId];
}

module.exports = { recordHintUsed };
