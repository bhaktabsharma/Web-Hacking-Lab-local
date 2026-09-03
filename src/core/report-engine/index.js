/**
 * src/core/report-engine — scores and stores learner-submitted
 * vulnerability reports (upgrade-spec Section 42: "This should train the
 * learner to produce real bug-bounty reports, not just flags.").
 *
 * Deliberately grounded in real session state rather than being a purely
 * cosmetic form: a report can only score well if the CALLING SESSION
 * genuinely holds a real, server-issued flag for the exact lab+difficulty
 * being reported (checked directly against session.flags — the same
 * source of truth flag-engine and progress-engine already use), and that
 * flag must actually appear in the report's Evidence field. This mirrors
 * the real bug-bounty workflow: exploit first, document second, and a
 * report without reproducible proof gets rejected — not the other way
 * around.
 *
 * Reports are intentionally NOT cleared by reset-engine's resetLabState().
 * They're a learning artifact (a portfolio of practice write-ups), not
 * in-progress lab state — resetting a lab to practice it again shouldn't
 * erase a report the learner already wrote and got feedback on.
 */
const REQUIRED_FIELDS = ["title", "severity", "affectedAsset", "endpoint", "description", "stepsToReproduce", "impact", "evidence", "remediation"];
const VALID_SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const GENERIC_TITLES = ["bug", "vulnerability", "issue", "problem", "security bug", "vuln", "test", "flag"];

function wordCount(s) {
  return String(s || "").trim().split(/\s+/).filter(Boolean).length;
}
function stepCount(s) {
  // Counts distinct non-empty lines, OR numbered/bulleted list items —
  // whichever gives a higher count, so both "1. ... \n2. ..." and
  // freeform newline-separated steps are recognized.
  const lines = String(s || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const numbered = lines.filter((l) => /^(\d+[.)]|[-*•])\s*\S/.test(l));
  return Math.max(lines.length, numbered.length);
}

function scoreReport(session, labId, difficulty, fields) {
  const feedback = [];
  let score = 0;
  const pointsPerField = 10; // 9 fields * 10 = 90, + up to 10 for verified evidence = 100

  function grade_(area, ok, points, note) {
    if (ok) score += points;
    feedback.push({ area, ok, note });
  }

  const missing = REQUIRED_FIELDS.filter((f) => !String(fields[f] || "").trim());
  if (missing.length) {
    feedback.push({ area: "Completeness", ok: false, note: `Missing required field(s): ${missing.join(", ")}.` });
  }

  const title = String(fields.title || "").trim();
  grade_(
    "Title",
    title.length >= 8 && !GENERIC_TITLES.includes(title.toLowerCase()),
    pointsPerField,
    title.length < 8
      ? "Too short to be useful in a report queue with hundreds of other titles."
      : GENERIC_TITLES.includes(title.toLowerCase())
      ? `"${title}" is too generic — real triagers see dozens of reports titled "Bug" or "Vulnerability" a week. Name the actual weakness and where it lives, e.g. "IDOR on /api/invoices/:id allows viewing other tenants' invoices".`
      : "Specific and descriptive — this is what a real triager wants to see first."
  );

  const severity = String(fields.severity || "").trim().toLowerCase();
  grade_(
    "Severity",
    VALID_SEVERITIES.includes(severity),
    pointsPerField,
    VALID_SEVERITIES.includes(severity)
      ? "Uses a standard severity scale."
      : `"${fields.severity || "(empty)"}" isn't one of the standard tiers (${VALID_SEVERITIES.join(", ")}). Real programs triage on a consistent scale — pick the closest standard tier and justify it in Impact.`
  );

  const asset = String(fields.affectedAsset || "").trim();
  grade_("Affected Asset", asset.length >= 3, pointsPerField, asset.length >= 3 ? "Asset identified." : "Name the specific app/service affected (e.g. \"SecureCorp Intranet — Billing module\"), not just \"the website\".");

  const endpoint = String(fields.endpoint || "").trim();
  const endpointMatchesThisLab = endpoint.includes(`/vuln/${labId}`);
  grade_(
    "Endpoint",
    endpoint.length > 0 && endpointMatchesThisLab,
    pointsPerField,
    !endpoint
      ? "No endpoint given — a triager needs the exact URL/route to even start reproducing this."
      : !endpointMatchesThisLab
      ? `"${endpoint}" doesn't look like it points at this lab's actual route (expected something containing /vuln/${labId}). Double-check you're reporting the endpoint you actually tested.`
      : "Endpoint is specific and matches what you actually tested."
  );

  grade_("Description", wordCount(fields.description) >= 15, pointsPerField, wordCount(fields.description) >= 15 ? "Clear enough to stand alone without the Steps section." : "Too brief — explain the weakness itself (not just the impact) in at least a couple of sentences.");

  const steps = stepCount(fields.stepsToReproduce);
  grade_("Steps to Reproduce", steps >= 2, pointsPerField, steps >= 2 ? `${steps} distinct steps — reproducible by someone who's never seen this lab.` : "A single paragraph isn't reproducible. Break this into an actual numbered sequence someone else could follow exactly.");

  grade_("Impact", wordCount(fields.impact) >= 10, pointsPerField, wordCount(fields.impact) >= 10 ? "Explains real-world consequence, not just the mechanism." : "Say what an attacker could actually DO with this — data exposed, accounts compromised, money lost — not just \"it's a vulnerability\".");

  grade_("Remediation", wordCount(fields.remediation) >= 8, pointsPerField, wordCount(fields.remediation) >= 8 ? "Gives the team something actionable to fix." : "\"Fix it\" isn't remediation advice. Say what should change — e.g. \"validate X server-side\" or \"use parameterized queries\".");

  // Evidence, weighted highest of all — this is the field tied to real
  // session state instead of just prose quality.
  const sessionFlag = session.flags && session.flags[labId + ":" + difficulty];
  const evidence = String(fields.evidence || "").trim();
  let verified = false;
  if (sessionFlag && evidence.includes(sessionFlag)) {
    verified = true;
    grade_("Evidence", true, pointsPerField, "Verified — your evidence includes the real flag issued to your own session for this exact lab and difficulty. This is what makes a report credible instead of a guess.");
  } else if (sessionFlag) {
    grade_("Evidence", false, 0, "You solved this lab, but your Evidence field doesn't include the flag you actually captured. Paste concrete proof (the flag, a response snippet, a screenshot description) — not just a claim that it worked.");
  } else {
    grade_("Evidence", false, 0, "No verified exploit was recorded for this lab+difficulty in your session yet. Solve the lab first (Exploit tab) — real bug-bounty programs reject reports with no reproducible proof, no matter how well-written.");
  }

  score = Math.max(0, Math.min(100, score));
  const grade = score >= 85 ? "Excellent" : score >= 70 ? "Good" : score >= 50 ? "Needs work" : "Incomplete";

  return { score, grade, verified, feedback, missingFields: missing };
}

function submitReport(session, labId, difficulty, fields) {
  if (!session.reports) session.reports = [];
  const result = scoreReport(session, labId, difficulty, fields);
  const report = {
    id: session.reports.length + 1,
    labId,
    difficulty,
    submittedAt: Date.now(),
    fields,
    score: result.score,
    grade: result.grade,
    verified: result.verified,
    feedback: result.feedback,
  };
  session.reports.push(report);
  return report;
}

function listReports(session, labId) {
  const all = session.reports || [];
  return labId ? all.filter((r) => r.labId === labId) : all;
}

module.exports = { submitReport, listReports, scoreReport, REQUIRED_FIELDS, VALID_SEVERITIES };
