/**
 * tests/target-realism.test.js — upgrade-spec Sections 7-9, 43-45: "the
 * target application must not look like a CTF page."
 *
 * Locks in the Phase 2 fix (see docs/UPGRADE-LOG.md) that removed a
 * literal `difficulty: ${difficulty}` / `sandbox` label from the shared
 * page-shell topbar rendered on every single target-app page, and removed
 * "training area" / "part of the platform" language from the /company
 * intranet hub's own copy.
 *
 * Two-tier scope, deliberately:
 *   - /company gets the FULL leak-phrase check, since its copy is fully
 *     under this migration's control (routes/company-hub.js) and has no
 *     legitimate reason to mention training/CTF/sandbox language at all.
 *   - individual lab pages only get checked for the specific chrome-level
 *     leak that was actually fixed (the topbar's difficulty label). They
 *     are NOT blanket-checked for "sandbox" — several labs' own body copy
 *     legitimately uses that word as a genuine safety disclosure (e.g. the
 *     SSRF lab explaining no real outbound requests are ever made),
 *     pre-existing intentional content this phase never touched. Nor for
 *     "flag" — every lab legitimately reveals a real `FLAG{...}` string
 *     once genuinely exploited; that's the intended proof-of-exploitation
 *     mechanic, not a leak.
 */
const http = require("http");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function httpGet(urlPath) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "localhost", port: 3000, path: urlPath, method: "GET" }, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

const CHROME_LEAK_PHRASES = ["difficulty: easy", "difficulty: medium", "difficulty: hard"];
// Every target-app shell shows a distinct fake logged-in persona instead
// of any difficulty/sandbox label (Phase 2a). As of Phase 2b, there are
// three shells (SecureCorp's "Alex Rivera", ShopSphere's "Jordan Kim",
// Finova's "Sam Chen") — this list is deliberately open-ended so a future
// fourth shell doesn't need this test rewritten, just its persona added.
const REALISTIC_PERSONAS = ["Alex Rivera", "Jordan Kim", "Sam Chen"];
const COMPANY_HUB_LEAK_PHRASES = [...CHROME_LEAK_PHRASES, "sandbox", "training area", "part of the platform", "ctf"];

async function checkPageForLeaks(urlPath, phrases) {
  const { status, body } = await httpGet(urlPath);
  check(`${urlPath} responds 200`, status === 200, "status=" + status);
  const lower = body.toLowerCase();
  for (const phrase of phrases) {
    check(`${urlPath} does not contain "${phrase}"`, !lower.includes(phrase));
  }
  check(`${urlPath} shows a realistic logged-in-user chrome instead`, REALISTIC_PERSONAS.some((p) => body.includes(p)), `expected one of ${REALISTIC_PERSONAS.join(", ")}`);
}

async function run() {
  // /company: stricter check. This page's own copy is fully under this
  // migration's control (routes/company-hub.js), so nothing here has a
  // legitimate reason to mention training/CTF/sandbox language.
  await checkPageForLeaks("/company", COMPANY_HUB_LEAK_PHRASES);

  // Individual lab pages: only check for the specific chrome-level leak
  // that was actually fixed (the topbar's difficulty label, present via
  // src/services/page-shell.js on every single page). Deliberately does
  // NOT blanket-check for "sandbox" here — several labs' own body content
  // legitimately uses that word as a genuine safety disclosure (e.g. the
  // SSRF lab explains no real outbound network requests are ever made),
  // which is pre-existing, intentional content this phase never touched
  // and has no reason to flag as a regression.
  for (const path of ["/vuln/idor", "/vuln/sql-injection", "/vuln/ssrf", "/vuln/price-tampering"]) {
    await checkPageForLeaks(path, CHROME_LEAK_PHRASES);
  }

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
