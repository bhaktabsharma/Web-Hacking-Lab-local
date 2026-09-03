/**
 * tests/report-engine.test.js — Phase 5 addition (upgrade-spec Section 42:
 * professional vulnerability reporting). Covers the scoring rubric in
 * src/core/report-engine, the POST/GET /api/reports endpoints in
 * routes/reset-and-validate.js, session isolation, and the deliberate
 * design choice that reports survive a lab reset (they're a learning
 * artifact, not in-progress lab state).
 */
const http = require("http");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function req(method, urlPath, { cookies, body } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = {};
    if (cookies) headers.Cookie = cookies;
    if (data) { headers["Content-Type"] = "application/json"; headers["Content-Length"] = Buffer.byteLength(data); }
    const r = http.request({ host: "localhost", port: 3000, path: urlPath, method, headers }, (res) => {
      let out = "";
      res.on("data", (d) => (out += d));
      res.on("end", () => resolve({ status: res.statusCode, json: () => JSON.parse(out), setCookies: res.headers["set-cookie"] || [] }));
    });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}
function extractCookie(setCookies, name) {
  const line = setCookies.find((c) => c.startsWith(name + "="));
  return line ? line.split(";")[0] : null;
}

const WEAK_FIELDS = { title: "bug", severity: "whatever", affectedAsset: "", endpoint: "", description: "broken", stepsToReproduce: "just try it", impact: "bad", evidence: "", remediation: "fix it" };

function strongFields(endpoint, evidence) {
  return {
    title: "IDOR on /vuln/idor/profile allows viewing any user's profile",
    severity: "high",
    affectedAsset: "SecureCorp Intranet — Profile module",
    endpoint,
    description: "The profile endpoint takes a numeric id parameter with no ownership check, allowing any authenticated user to view any other user's profile by changing the id value.",
    stepsToReproduce: "1. Log in as any user.\n2. Navigate to your own profile.\n3. Change the id parameter to another user's id.\n4. Observe their profile is returned.",
    impact: "An attacker can enumerate and read every user profile in the system, including the admin account, exposing PII and enabling further targeted attacks.",
    evidence,
    remediation: "Enforce server-side ownership checks so a user can only request their own id, or use non-sequential opaque identifiers.",
  };
}

async function run() {
  const rInit = await req("GET", "/vuln/idor?difficulty=easy");
  const cookies = extractCookie(rInit.setCookies, "sid");

  // --- validation -------------------------------------------------------
  const rMissing = await req("POST", "/api/reports", { cookies, body: { title: "x" } });
  check("POST /api/reports without labId/difficulty -> 400", rMissing.status === 400 && rMissing.json().success === false);

  // --- unverified report (never solved this lab in this session) -------
  const rUnverified = await req("POST", "/api/reports", { cookies, body: { labId: "idor", difficulty: "easy", ...strongFields("/vuln/idor/profile?id=100", "made up evidence") } });
  const unverifiedJson = rUnverified.json();
  check("report for an unsolved lab is NOT verified", unverifiedJson.report.verified === false);
  check("unverified report's Evidence feedback explains why", unverifiedJson.report.feedback.some((f) => f.area === "Evidence" && /no verified exploit/i.test(f.note)));
  check("unverified report still scores less than a fully verified one would (evidence contributes 0)", unverifiedJson.report.score <= 90);

  // --- weak report --------------------------------------------------------
  const rWeak = await req("POST", "/api/reports", { cookies, body: { labId: "idor", difficulty: "easy", ...WEAK_FIELDS } });
  const weakJson = rWeak.json();
  check("weak report scores very low", weakJson.report.score <= 20, weakJson.report.score);
  check("weak report is graded Incomplete", weakJson.report.grade === "Incomplete");
  check("weak report flags the generic title", weakJson.report.feedback.some((f) => f.area === "Title" && f.ok === false));
  check("weak report flags the invalid severity", weakJson.report.feedback.some((f) => f.area === "Severity" && f.ok === false));

  // --- now actually solve the lab, then submit with/without evidence ---
  const rProfile = await req("GET", "/vuln/idor/profile?id=100&difficulty=easy", { cookies });
  const flagMatch = rProfile.json ? null : null; // profile route returns HTML, not JSON — extract via regex below
  const profileBody = await (async () => {
    // re-fetch raw body (the helper above assumes JSON; grab text directly here)
    return new Promise((resolve, reject) => {
      const r = http.request({ host: "localhost", port: 3000, path: "/vuln/idor/profile?id=100&difficulty=easy", method: "GET", headers: { Cookie: cookies } }, (res) => {
        let out = "";
        res.on("data", (d) => (out += d));
        res.on("end", () => resolve(out));
      });
      r.end();
    });
  })();
  const flag = (profileBody.match(/FLAG\{[a-z0-9-]+\}/) || [])[0];
  check("a real flag was captured by exploiting idor", !!flag, profileBody.slice(0, 200));

  const rSolve = await req("POST", "/api/validate-lab", { cookies, body: { labId: "idor", difficulty: "easy", answer: flag } });
  check("validate-lab accepts the real flag", rSolve.json().success === true);

  const rNoEvidence = await req("POST", "/api/reports", { cookies, body: { labId: "idor", difficulty: "easy", ...strongFields("/vuln/idor/profile?id=100", "") } });
  const noEvJson = rNoEvidence.json();
  check("solved-but-no-evidence report is still NOT verified", noEvJson.report.verified === false);
  check("its Evidence feedback specifically says evidence is missing the flag", noEvJson.report.feedback.some((f) => f.area === "Evidence" && /doesn't include the flag/i.test(f.note)));

  const rStrong = await req("POST", "/api/reports", { cookies, body: { labId: "idor", difficulty: "easy", ...strongFields("/vuln/idor/profile?id=100", flag) } });
  const strongJson = rStrong.json();
  check("fully strong + verified report IS verified", strongJson.report.verified === true);
  check("fully strong + verified report scores high", strongJson.report.score >= 85, strongJson.report.score);
  check("fully strong + verified report is graded Excellent", strongJson.report.grade === "Excellent");
  check("every feedback area passes on the strong report", strongJson.report.feedback.every((f) => f.ok === true), JSON.stringify(strongJson.report.feedback.filter((f) => !f.ok)));

  // Endpoint-mismatch check: reporting a DIFFERENT lab's endpoint should
  // fail the Endpoint check even with everything else strong.
  const rWrongEndpoint = await req("POST", "/api/reports", { cookies, body: { labId: "idor", difficulty: "easy", ...strongFields("/vuln/sql-injection", flag) } });
  check("an endpoint that doesn't match the reported lab fails the Endpoint check", rWrongEndpoint.json().report.feedback.some((f) => f.area === "Endpoint" && f.ok === false));

  // --- listing -------------------------------------------------------
  const rList = await req("GET", "/api/reports?labId=idor", { cookies });
  const listJson = rList.json();
  check("GET /api/reports?labId=idor returns all reports submitted for idor in this session", listJson.reports.length === 5, listJson.reports.length);

  const rListAll = await req("GET", "/api/reports", { cookies });
  check("GET /api/reports with no labId filter returns the same reports (only idor was reported)", rListAll.json().reports.length === 5);

  // --- reports survive a lab reset (deliberate design choice) --------
  await req("POST", "/api/reset-lab", { cookies, body: { labId: "idor" } });
  const rListAfterReset = await req("GET", "/api/reports?labId=idor", { cookies });
  check("reports for a lab survive resetting that lab (they're a learning artifact, not lab state)", rListAfterReset.json().reports.length === 5);
  const rProgressAfterReset = await req("GET", "/api/progress", { cookies });
  check("...even though the lab's solved status WAS cleared by the reset", !rProgressAfterReset.json().solved["idor"]);

  // --- session isolation -------------------------------------------------
  const rOtherSession = await req("GET", "/api/reports?labId=idor"); // no cookie -> fresh session
  check("a different (fresh) session sees zero reports for idor — reports are session-scoped", rOtherSession.json().reports.length === 0);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
