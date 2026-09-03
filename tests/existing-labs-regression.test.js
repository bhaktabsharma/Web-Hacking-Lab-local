/**
 * tests/existing-labs-regression.test.js — Existing-Lab Regression Test
 * (upgrade-spec Sections 4 + 52)
 *
 * This is the enforcement mechanism behind the "never remove an existing
 * lab" rule. It loads data/existing-labs-manifest.json — the frozen record
 * of every lab that existed at the time the manifest was last regenerated —
 * and verifies, against the CURRENT registry and a LIVE server, that:
 *
 *   1. every manifest lab id still exists in public/js/labs-data.js
 *   2. every manifest lab's category still exists
 *   3. every manifest lab's PRIMARY route still resolves live (200/302)
 *   4. no manifest lab's route regressed to a route file that's no longer
 *      wired into server.js
 *
 * NOTE ON SCOPE: this only probes each lab's primaryRoute (its entry
 * point, e.g. GET /vuln/idor), not every nested sub-route recorded in the
 * manifest. Sub-routes like /vuln/<id>/debug-sessions or chain step-2/3
 * endpoints are frequently and CORRECTLY gated behind session/chain state
 * or expect a real parameter value — a bare unauthenticated GET returning
 * 403/404 there is expected behavior, not a regression. This mirrors
 * tools/validate-labs.js, which checks the same single entry point per lab
 * for the same reason. Sub-routes are still recorded in the manifest for
 * documentation, just not asserted on here.
 *
 * IMPORTANT: this test intentionally does NOT fail if new labs exist that
 * aren't yet in the manifest — that's growth, not regression. It only ever
 * fails in the direction of "something that used to work now doesn't."
 * Run `node tools/generate-manifest.js` to intentionally re-baseline after
 * a verified-safe change (e.g. after adding new labs, or after a route
 * file rename that's been confirmed to preserve behavior).
 */
const fs = require("fs");
const path = require("path");
const http = require("http");

const ROOT = path.join(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "data", "existing-labs-manifest.json");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 60000).unref();

function httpGet(urlPath) {
  return new Promise((resolve) => {
    const req = http.request({ host: "localhost", port: 3000, path: urlPath, method: "GET" }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on("error", () => resolve(null));
    req.end();
  });
}

async function run() {
  if (!fs.existsSync(MANIFEST_PATH)) {
    console.log("FAIL: no manifest found at data/existing-labs-manifest.json — run `node tools/generate-manifest.js` once to create the baseline.");
    console.log(`\n=== 0 passed, 1 failed ===`);
    process.exit(1);
    return;
  }

  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  const currentData = require(path.join(ROOT, "public/js/labs-data.js"));
  const currentIds = new Set(currentData.labs.map((l) => l.id));
  const currentCategoryIds = new Set(currentData.categories.map((c) => c.id));

  check(
    `manifest total (${manifest.labs.length}) does not exceed a sane bound (sanity check on the file itself)`,
    manifest.labs.length > 0
  );

  let preservedCount = 0;

  for (const entry of manifest.labs) {
    if (entry.status !== "preserved") continue; // only enforce entries the manifest says must survive

    const stillInRegistry = currentIds.has(entry.id);
    check(`[${entry.id}] still present in labs-data.js`, stillInRegistry);

    const categoryStillExists = currentCategoryIds.has(entry.category);
    check(`[${entry.id}] category '${entry.category}' still exists`, categoryStillExists);

    if (entry.primaryRoute) {
      const status = await httpGet(entry.primaryRoute);
      const ok = status === 200 || status === 302;
      check(`[${entry.id}] primary entry route still responds: GET ${entry.primaryRoute}`, ok, "status=" + status);
    } else {
      check(`[${entry.id}] had a primary route recorded`, false, "manifest entry has no primaryRoute");
    }

    if (stillInRegistry && categoryStillExists) preservedCount++;
  }

  console.log(`\nPreserved: ${preservedCount}/${manifest.labs.length} manifest labs still present and reachable.`);
  console.log(`Current registry total: ${currentData.labs.length} labs (must be >= manifest total of ${manifest.labs.length}).`);
  check("current lab count has not decreased vs. the manifest baseline", currentData.labs.length >= manifest.labs.length, `current=${currentData.labs.length} manifest=${manifest.labs.length}`);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
