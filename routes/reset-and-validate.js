const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

router.post("/api/reset-lab", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const labId = req.body.labId;
  if (labId) {
    C.resetLabState(session, labId);
    if (labId === "csrf") session.canonicalId = null;
  }
  res.json({ success: true });
});

// Wipes every lab's state/flags/progress/hints for the CALLING session only
// (session lookup is entirely cookie-based — there's no labId-only or
// session-only reset path, so this can never touch another session).
// Backs the homepage's "Reset ALL progress" control, replacing what used
// to be a client-only localStorage.clear().
router.post("/api/reset-all", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const labIds = new Set();
  Object.keys(session.lab || {}).forEach((id) => labIds.add(id));
  Object.keys(session.progress || {}).forEach((id) => labIds.add(id));
  Object.keys(session.flags || {}).forEach((k) => labIds.add(k.split(":")[0]));
  labIds.forEach((id) => C.resetLabState(session, id));
  session.canonicalId = null;
  res.json({ success: true });
});

// Real verification: the submitted answer must be the exact flag that was
// revealed to THIS session by THIS lab at THIS difficulty after genuinely
// triggering the vulnerable code path. See routes/vuln-common.js (getFlag)
// and each vulns-*.js file for where flags are revealed.
router.post("/api/validate-lab", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const { labId, difficulty, answer } = req.body;
  const trimmed = (answer || "").trim();
  if (trimmed.length < 3) return res.json({ success: false, message: "That doesn't look like a real flag yet. Go exploit the lab first — the flag appears in the response when the exploit actually works." });
  const success = C.checkFlag(session, labId, difficulty || "easy", trimmed);
  if (success) {
    C.markSolved(session, labId, difficulty || "easy");
    if (C.isChainLab(labId)) C.advanceChainState(session, labId, "SOLVED");
  }
  res.json({
    success,
    message: success
      ? "✅ Correct flag — verified. This lab is now marked solved."
      : "❌ That's not the flag for this lab/difficulty in your current session. Make sure you actually triggered the exploit (not just a guess), and that you're on the right difficulty."
  });
});

// Phase 2 flag-engine hardening: gates flag REVELATION for the handful of
// labs whose exploit is entirely client-side (see vuln-common.js's
// issueClientProofToken/confirmClientProof doc comment for the full
// rationale). The flag text itself never appears in any page's HTML/JS
// until this call succeeds.
router.post("/api/confirm-client-exploit", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const { labId, difficulty, token } = req.body || {};
  if (!labId || !difficulty || !token) return res.status(400).json({ success: false });
  const flag = C.confirmClientProof(session, labId, difficulty, token);
  if (!flag) return res.json({ success: false });
  C.markSolved(session, labId, difficulty);
  res.json({ success: true, flag });
});

// Server-authoritative progress: the homepage/lab page fetch this on load
// and use it as the source of truth for "solved" badges, rather than
// trusting client-only localStorage (which cannot be faked from the
// frontend anymore — see markSolved()'s doc comment in vuln-common.js).
router.get("/api/progress", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  res.json(C.getProgressSummary(session));
});

// Tracks that a hint was opened for a lab, for completion statistics.
// Never gates anything — purely informational, fire-and-forget from the UI.
router.post("/api/hint-used", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const labId = req.body && req.body.labId;
  if (!labId) return res.status(400).json({ success: false });
  const count = C.recordHintUsed(session, labId);
  res.json({ success: true, count });
});

module.exports = { router };

// ============================================================================
// PHASE 4 ADDITION (upgrade-spec Section 33: server-tracked chain state).
// Read-only — the actual state transitions happen inline in
// routes/vulns-chains.js at each real gated step; this just exposes the
// current progress for the training platform UI (or Burp/curl) to query.
// ============================================================================
router.get("/api/chain-progress/:chainId", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const summary = C.chainProgressSummary(session, req.params.chainId);
  if (!summary) return res.status(404).json({ error: "Unknown chain id." });
  res.json(summary);
});
// reporting). See src/core/report-engine for the scoring rubric and the
// rationale for why it's grounded in real session flag state rather than
// being a purely cosmetic form.
// ============================================================================

router.post("/api/reports", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const { labId, difficulty } = req.body || {};
  if (!labId || !difficulty) return res.status(400).json({ success: false, error: "labId and difficulty are required." });
  const fields = {};
  for (const f of ["title", "severity", "affectedAsset", "endpoint", "description", "stepsToReproduce", "impact", "evidence", "remediation"]) {
    fields[f] = typeof req.body[f] === "string" ? req.body[f].slice(0, 4000) : ""; // generous cap, not a magic-length gate
  }
  const report = C.submitReport(session, labId, difficulty, fields);
  res.json({ success: true, report });
});

// Lists this session's own submitted reports only — cookie-scoped, same
// isolation guarantee as every other session-bound endpoint in this file.
router.get("/api/reports", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const labId = typeof req.query.labId === "string" ? req.query.labId : undefined;
  res.json({ reports: C.listReports(session, labId) });
});
