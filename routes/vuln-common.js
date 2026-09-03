/**
 * routes/vuln-common.js
 *
 * BACKWARD-COMPATIBLE FACADE — as of the Phase 1 architecture pass (see
 * docs/UPGRADE-LOG.md), the actual implementation lives under src/
 * (src/core/*-engine, src/services/, src/labs/fixtures/, src/utils/) per
 * the target architecture in the upgrade spec's Section 6. This file
 * re-exports everything under the EXACT SAME names every routes/vulns-*.js
 * file already imports via `const C = require("./vuln-common")`, so none
 * of the 87 existing labs' route files needed to change one line.
 *
 * If you're adding a NEW lab: prefer requiring the specific engine/service
 * you need directly from src/, e.g.
 *   const { getFlag } = require("../src/core/flag-engine");
 * `C = require("./vuln-common")` still works and will keep working, but
 * new code doesn't have to pull in everything through one shared object.
 */
const { randomHex } = require("../src/utils/random");
const { difficultyOf } = require("../src/utils/difficulty");
const sessionEngine = require("../src/core/session-engine");
const stateEngine = require("../src/core/state-engine");
const flagEngine = require("../src/core/flag-engine");
const progressEngine = require("../src/core/progress-engine");
const hintEngine = require("../src/core/hint-engine");
const resetEngine = require("../src/core/reset-engine");
const reportEngine = require("../src/core/report-engine");
const chainEngine = require("../src/core/chain-engine");
const { VFS } = require("../src/services/fake-filesystem");
const { FAKE_INTERNAL_SERVICES } = require("../src/services/fake-internal-network");
const { renderVulnPage } = require("../src/services/page-shell");
const { renderShopSpherePage } = require("../src/services/shopsphere-shell");
const { renderFinovaPage } = require("../src/services/finova-shell");
const { USERS, ADMIN, findUserByCanonicalId, encodeId, decodeId } = require("../src/labs/fixtures/users");
const { PRODUCTS, listProducts } = require("../src/labs/fixtures/products");

module.exports = {
  // utils
  randomHex,
  difficultyOf,

  // session-engine
  SESSIONS: sessionEngine.SESSIONS,
  getOrInitSession: sessionEngine.getOrInitSession,
  sessionStats: sessionEngine.sessionStats, // new in Phase 1 (upgrade-spec Section 57)

  // state-engine
  labState: stateEngine.labState,

  // reset-engine
  resetLabState: resetEngine.resetLabState,

  // flag-engine
  getFlag: flagEngine.getFlag,
  checkFlag: flagEngine.checkFlag,
  issueClientProofToken: flagEngine.issueClientProofToken,
  confirmClientProof: flagEngine.confirmClientProof,

  // progress-engine
  markSolved: progressEngine.markSolved,
  getProgressSummary: progressEngine.getProgressSummary,

  // hint-engine
  recordHintUsed: hintEngine.recordHintUsed,

  // report-engine (Phase 5 — upgrade-spec Section 42)
  submitReport: reportEngine.submitReport,
  listReports: reportEngine.listReports,

  // chain-engine (Phase 4 — upgrade-spec Section 33)
  advanceChainState: chainEngine.advanceChainState,
  chainProgressSummary: chainEngine.chainProgressSummary,
  isChainLab: (labId) => chainEngine.allChainIds().includes(labId),

  // services
  VFS,
  FAKE_INTERNAL_SERVICES,
  renderVulnPage,
  renderShopSpherePage,
  renderFinovaPage,

  // lab fixtures
  USERS,
  ADMIN,
  findUserByCanonicalId,
  encodeId,
  decodeId,
  PRODUCTS,
  listProducts,
};
