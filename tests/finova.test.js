/**
 * tests/finova.test.js — Phase 2 addition: Finova, the third distinct
 * target application (upgrade-spec Section 9). Same verification pattern
 * as tests/shopsphere.test.js: branding actually changed, CTF language
 * didn't leak in, and — most importantly — the re-skinned labs' actual
 * exploit logic is provably untouched by re-running it through the API.
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
  const rHub = await req("GET", "/finova");
  check("/finova responds 200", rHub.status === 200);
  check("/finova shows Finova branding", rHub.body.includes("Finova"));
  check("/finova shows the distinct fake customer (Sam Chen, not Alex Rivera or Jordan Kim)", rHub.body.includes("Sam Chen") && !rHub.body.includes("Alex Rivera") && !rHub.body.includes("Jordan Kim"));
  check("/finova shows real account data from the hub's own fixtures", rHub.body.includes("Everyday Checking") && rHub.body.includes("$4,218.06"));
  for (const phrase of CTF_LEAK_PHRASES) {
    check(`/finova does not contain "${phrase}"`, !rHub.body.toLowerCase().includes(phrase));
  }

  // --- each re-skinned lab: branding + leak check ------------------------
  for (const labId of ["invitation-abuse", "account-linking-abuse"]) {
    const r = await req("GET", `/vuln/${labId}?difficulty=easy`);
    check(`[${labId}] page responds 200`, r.status === 200);
    check(`[${labId}] shows Finova branding`, r.body.includes("Finova"));
    check(`[${labId}] no longer shows SecureCorp branding`, !r.body.includes("SecureCorp"));
    check(`[${labId}] shows the Finova customer identity`, r.body.includes("Sam Chen"));
    for (const phrase of CTF_LEAK_PHRASES) {
      check(`[${labId}] does not contain "${phrase}"`, !r.body.toLowerCase().includes(phrase));
    }
  }

  // --- a lab deliberately NOT moved to Finova stays SecureCorp -----------
  const rTicket = await req("GET", "/vuln/secondary-context?difficulty=easy");
  check("secondary-context (not part of this re-skin) still shows SecureCorp branding", rTicket.body.includes("SecureCorp"));
  check("secondary-context does not show Finova branding", !rTicket.body.includes("Finova"));

  // --- the actual vulnerable logic is provably unchanged ------------
  const rInvite = await req("POST", "/vuln/invitation-abuse/redeem?difficulty=easy", { body: { email: "victim@example.test" } });
  check("invitation-abuse's exploit logic is unchanged by the re-skin", rInvite.json().credited === true, JSON.stringify(rInvite.json()));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
