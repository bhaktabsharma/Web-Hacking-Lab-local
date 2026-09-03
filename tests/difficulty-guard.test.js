/**
 * tests/difficulty-guard.test.js — Phase 7 fix (upgrade-spec Section 15:
 * "Do not silently convert invalid difficulty to Easy. Return a proper
 * error."). Confirms src/middleware/difficulty-guard.js does what it
 * claims, AND — just as important given this is global middleware
 * touching every one of the 89 labs' /vuln/* routes — that normal,
 * legitimate requests are completely unaffected.
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
      res.on("end", () => resolve({ status: res.statusCode, body: out, json: () => JSON.parse(out) }));
    });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

async function run() {
  // --- the core fix ----------------------------------------------------
  // Uses csp-bypass as the "no expert content" control — deliberately NOT
  // idor (which used to be this control, until idor got real Expert
  // content of its own; see tests/idor-expert-tier.test.js). Same lesson
  // as Phase 2b/2c's re-skinning tests: pick a control lab from OUTSIDE
  // whatever category is actively being extended, so it doesn't keep
  // going stale as expert-tier coverage grows.
  const rExpert = await req("GET", "/vuln/csp-bypass?difficulty=expert");
  check("expert tier returns 501 for a lab without expert content, not 200", rExpert.status === 501, "status=" + rExpert.status + " body=" + rExpert.body.slice(0, 200));
  check("expert tier response explains it isn't implemented yet", /not yet implemented/i.test(rExpert.json().error));
  check("expert tier response lists the actually-available tiers", /easy, medium, hard/.test(rExpert.json().error));

  // Phase 7 follow-up: ssrf DOES have real expert content now — the guard
  // must let it through rather than 501ing every "expert" request
  // uniformly. See tests/ssrf-expert-tier.test.js for full coverage of
  // the actual expert-tier exploit logic; this just confirms the guard's
  // own routing decision.
  const rSsrfExpert = await req("GET", "/vuln/ssrf?difficulty=expert&url=http://example.com/");
  check("expert tier is let through for ssrf specifically (it has real expert logic)", rSsrfExpert.status === 200);

  const rJwtExpert = await req("GET", "/vuln/jwt-vulnerabilities?difficulty=expert");
  check("expert tier is also let through for jwt-vulnerabilities (2nd lab with real expert logic)", rJwtExpert.status === 200);

  // Phase 7 follow-up: graphql-authz-bypass's actual query execution
  // happens via the SHARED /graphql endpoint, not a /vuln/* path — the
  // guard needed a special case for this (see the guard's own scope-note
  // comment). Confirm both the landing page AND the shared endpoint work.
  const rGraphqlEndpoint = await req("POST", "/graphql?difficulty=expert", { body: { query: "{ me { id } }" } });
  check("expert tier is let through on the shared /graphql endpoint too (not just /vuln/* paths)", rGraphqlEndpoint.status === 200);

  const rIdorExpert = await req("GET", "/vuln/idor?difficulty=expert");
  check("expert tier is also let through for idor (6th lab with real expert logic)", rIdorExpert.status === 200);

  const rGarbage = await req("GET", "/vuln/idor?difficulty=banana");
  check("garbage difficulty returns 400, not 200", rGarbage.status === 400);
  check("garbage difficulty response names the bad value", /banana/.test(rGarbage.json().error));

  const rGarbagePost = await req("POST", "/vuln/price-tampering/checkout", { body: { difficulty: "nightmare", items: [] } });
  check("garbage difficulty via POST body is also caught (not just query string)", rGarbagePost.status === 400);

  // --- confirm no route silently proceeded and leaked a flag on an invalid tier ---
  check("the 501 response body contains no FLAG (no lab logic ran)", !/FLAG\{/.test(rExpert.body));
  check("the 400 response body contains no FLAG (no lab logic ran)", !/FLAG\{/.test(rGarbage.body));

  // --- legitimate usage is completely unaffected ------------------------
  const rEasy = await req("GET", "/vuln/idor?difficulty=easy");
  check("a valid tier (easy) still returns 200 normally", rEasy.status === 200);

  const rUpper = await req("GET", "/vuln/idor?difficulty=EASY");
  check("a valid tier in a different case (EASY) still works", rUpper.status === 200);

  const rNone = await req("GET", "/vuln/idor");
  check("no difficulty specified at all still works (falls through to the existing default, unaffected)", rNone.status === 200);

  const rMedium = await req("GET", "/vuln/sql-injection?difficulty=medium");
  check("a different lab, medium tier, still works normally", rMedium.status === 200);

  const rHard = await req("GET", "/vuln/ssrf?difficulty=hard");
  check("a different lab, hard tier, still works normally", rHard.status === 200);

  // --- scope: only /vuln/* is guarded, everything else is untouched ---
  const rCompany = await req("GET", "/company?difficulty=expert");
  check("/company (not a /vuln/* path) ignores an 'expert' difficulty param entirely — not in scope for this guard", rCompany.status === 200);

  const rApi = await req("GET", "/api/progress?difficulty=expert");
  check("/api/* routes are not in scope for this guard either", rApi.status === 200);

  const rHome = await req("GET", "/");
  check("the homepage is completely unaffected", rHome.status === 200);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
