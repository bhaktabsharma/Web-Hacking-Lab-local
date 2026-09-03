/**
 * src/core/reset-engine — resets a single lab's state within one session.
 *
 * Extracted from routes/vuln-common.js (Phase 1 architecture pass, see
 * docs/UPGRADE-LOG.md). Behavior unchanged. Operates directly on the
 * session record's own properties (lab/flags/progress/hints) rather than
 * importing state-engine/flag-engine/etc., so there's no cross-engine
 * dependency to keep in sync — resetting is fundamentally "delete this
 * lab's slice of whatever's on the session object," which stays true no
 * matter how those other engines evolve internally.
 *
 * routes/reset-and-validate.js is the only caller today (POST
 * /api/reset-lab and POST /api/reset-all, the latter by calling this once
 * per labId the session has touched).
 */
function resetLabState(session, labId) {
  delete session.lab[labId];
  if (session.flags) {
    Object.keys(session.flags).forEach((k) => {
      if (k.indexOf(labId + ":") === 0) delete session.flags[k];
    });
  }
  if (session.progress) delete session.progress[labId];
  if (session.hints) delete session.hints[labId];
}

module.exports = { resetLabState };
