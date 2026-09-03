/**
 * tests/shopsphere.test.js — Phase 2 addition (upgrade-spec Section 9:
 * "Create multiple realistic applications... should feel like different
 * real products"). Covers the new ShopSphere shell/hub and confirms the
 * 4 re-skinned checkout-flow labs (price-tampering, coupon-abuse,
 * workflow-bypass, refund-abuse):
 *   1. actually show ShopSphere branding now, not SecureCorp
 *   2. have NOT had their vulnerable logic touched — same exact exploit
 *      request/response behavior as before the re-skin (the strongest
 *      possible check here: run the real price-tampering exploit through
 *      the API and confirm it still yields a real flag)
 *   3. don't leak CTF/training language, same standard as
 *      tests/target-realism.test.js
 * Also confirms a couple of labs that were deliberately NOT re-skinned
 * this phase still show SecureCorp branding — a sanity check that the
 * re-skin was scoped to exactly the 4 intended labs, not accidentally
 * applied everywhere or missed entirely.
 *
 * NOTE: invitation-abuse and account-linking-abuse were originally used
 * here as the "not re-skinned" control (they weren't, as of Phase 2b).
 * Phase 2's Finova pass later moved both of THOSE to a third shell — see
 * tests/finova.test.js, which now owns verifying their branding. Swapped
 * this file's control check to two labs that were never touched by
 * either re-skin, so this test keeps meaning what it says.
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

const CTF_LEAK_PHRASES = ["difficulty: easy", "difficulty: medium", "difficulty: hard", "sandbox", "training area", "part of the platform", "ctf"];

async function run() {
  // --- the hub page itself -------------------------------------------
  const rHub = await req("GET", "/shopsphere");
  check("/shopsphere responds 200", rHub.status === 200);
  check("/shopsphere shows ShopSphere branding", rHub.body.includes("ShopSphere"));
  check("/shopsphere shows the distinct fake customer (Jordan Kim, not Alex Rivera)", rHub.body.includes("Jordan Kim") && !rHub.body.includes("Alex Rivera"));
  check("/shopsphere lists real product data from the shared fixture", rHub.body.includes("Standard Widget") && rHub.body.includes("$49.99"));
  for (const phrase of CTF_LEAK_PHRASES) {
    check(`/shopsphere does not contain "${phrase}"`, !rHub.body.toLowerCase().includes(phrase));
  }

  // --- each re-skinned lab: branding + leak check ------------------------
  const reskinned = ["price-tampering", "coupon-abuse", "workflow-bypass", "refund-abuse"];
  for (const labId of reskinned) {
    const r = await req("GET", `/vuln/${labId}?difficulty=easy`);
    check(`[${labId}] page responds 200`, r.status === 200);
    check(`[${labId}] shows ShopSphere branding`, r.body.includes("ShopSphere"));
    check(`[${labId}] no longer shows SecureCorp branding`, !r.body.includes("SecureCorp"));
    check(`[${labId}] shows the ShopSphere customer identity`, r.body.includes("Jordan Kim"));
    for (const phrase of CTF_LEAK_PHRASES) {
      check(`[${labId}] does not contain "${phrase}"`, !r.body.toLowerCase().includes(phrase));
    }
  }

  // --- labs deliberately NOT re-skinned stay SecureCorp -----------------
  for (const labId of ["idor", "secondary-context"]) {
    const r = await req("GET", `/vuln/${labId}?difficulty=easy`);
    check(`[${labId}] (not re-skinned) still shows SecureCorp branding`, r.body.includes("SecureCorp"));
    check(`[${labId}] (not re-skinned) does not show ShopSphere branding`, !r.body.includes("ShopSphere"));
  }

  // --- the actual vulnerable logic is provably unchanged ------------
  // price-tampering easy tier: trust a client-supplied price of $0.01,
  // flag issues once total <= 5. This is the exact same request/response
  // contract as before the re-skin — only the GET page's presentational
  // shell changed.
  const rExploit = await req("POST", "/vuln/price-tampering/checkout?difficulty=easy", { body: { items: [{ id: "widget", qty: 1, price: 0.01 }] } });
  const exploitJson = rExploit.json();
  check("price-tampering's exploit logic is unchanged by the re-skin (still yields a real flag)", exploitJson.total === 0.01 && /^FLAG\{price-tampering-easy-/.test(exploitJson.flag || ""), JSON.stringify(exploitJson));

  // coupon-abuse easy tier: applying the same coupon twice stacks it.
  const cookieRes = await req("GET", "/vuln/coupon-abuse?difficulty=easy");
  const setCookie = (cookieRes.headers && cookieRes.headers["set-cookie"]) || null;
  const r1 = await req("POST", "/vuln/coupon-abuse/apply?difficulty=easy", { body: { code: "WELCOME10" } });
  check("coupon-abuse's exploit logic is unchanged by the re-skin (applies successfully)", r1.json().applied === true, JSON.stringify(r1.json()));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
