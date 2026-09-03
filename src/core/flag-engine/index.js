/**
 * src/core/flag-engine — real exploit verification.
 *
 * Extracted from routes/vuln-common.js (Phase 1 architecture pass, see
 * docs/UPGRADE-LOG.md). Behavior unchanged.
 *
 * Each session gets a unique, unguessable flag per lab+difficulty,
 * generated on first use. A lab's vulnerable route only reveals this flag
 * in the response when the actual exploit condition is genuinely met
 * (never on the "safe"/blocked path), so submitting the correct flag in
 * the Report tab proves the exploit actually happened server-side — not
 * just that the learner typed something payload-shaped into a textarea.
 *
 * --- Client-proof pattern -------------------------------------------------
 * For labs whose exploit happens ENTIRELY client-side (DOM XSS,
 * postMessage, prototype pollution, client-side template injection,
 * reading a cookie via JS, scanning Web Storage) there is no server
 * request to hook a flag-issue condition onto. The page embeds a random,
 * single-use PROOF TOKEN instead of the flag. Once the client-side JS
 * detects genuine exploitation, it POSTs the token to
 * POST /api/confirm-client-exploit. Only if the token matches what THIS
 * session was issued for THIS lab+difficulty does the server hand back the
 * real flag, and the token is consumed on first successful use.
 */
const { randomHex } = require("../../utils/random");
const { labState } = require("../state-engine");

function getFlag(session, labId, difficulty) {
  if (!session.flags) session.flags = {};
  const key = labId + ":" + difficulty;
  if (!session.flags[key]) session.flags[key] = "FLAG{" + labId + "-" + difficulty + "-" + randomHex(4) + "}";
  return session.flags[key];
}

function checkFlag(session, labId, difficulty, submitted) {
  if (!session.flags) return false;
  const expected = session.flags[labId + ":" + difficulty];
  return !!expected && String(submitted || "").trim() === expected;
}

function issueClientProofToken(session, labId, difficulty) {
  const st = labState(session, "_clientproof_" + labId, {});
  const token = randomHex(12);
  st[difficulty] = token;
  return token;
}

function confirmClientProof(session, labId, difficulty, token) {
  const st = labState(session, "_clientproof_" + labId, {});
  if (!token || !st[difficulty] || st[difficulty] !== token) return null;
  delete st[difficulty]; // single-use
  return getFlag(session, labId, difficulty);
}

module.exports = { getFlag, checkFlag, issueClientProofToken, confirmClientProof };
