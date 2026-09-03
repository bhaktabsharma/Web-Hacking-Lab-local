/**
 * src/core/state-engine — per-lab, per-session state.
 *
 * Extracted from routes/vuln-common.js (Phase 1 architecture pass, see
 * docs/UPGRADE-LOG.md). Behavior unchanged: each session lazily gets a
 * deep-cloned default state object the first time a lab touches it, keyed
 * by labId. Deliberately has zero knowledge of flags/progress/hints — that
 * separation is what lets reset-engine, flag-engine, and progress-engine
 * evolve independently in later phases (e.g. the richer chain state
 * machine planned for Phase 4) without this module needing to change.
 */
function labState(session, labId, defaults) {
  if (!session.lab[labId]) session.lab[labId] = JSON.parse(JSON.stringify(defaults));
  return session.lab[labId];
}

module.exports = { labState };
