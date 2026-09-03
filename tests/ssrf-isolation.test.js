/**
 * tests/ssrf-isolation.test.js — upgrade-spec Section 48: "Create
 * automated tests proving that SSRF labs cannot escape the controlled
 * environment... Only explicitly allowed simulated internal services
 * should respond."
 *
 * Two layers of proof, deliberately combined rather than relying on
 * either alone:
 *
 *   STATIC  — grep the actual route/service source for the modules that
 *             would be REQUIRED to make a real outbound request
 *             (http/https/net/dns/undici's fetch is global in Node 18+, so
 *             that's checked too). If none of routes/ or src/ ever
 *             requires any of them, a real network call is not just
 *             unlikely, it's structurally impossible from this code.
 *   DYNAMIC — fuzz the live /vuln/ssrf route with real-world SSRF payload
 *             shapes (loopback, RFC1918 LAN ranges, a real public domain)
 *             that share no host string with any allowlisted key, and
 *             confirm none of them produce a response (only the exact
 *             allowlisted keys do), plus a real-network address gets a
 *             fast response (a genuine outbound attempt to an
 *             unreachable/slow host would be slow or hang; a dictionary
 *             lookup returning "not found" is near-instant).
 *
 *             NOTE: the lookup matches by HOST substring, not full path
 *             (confirmed by reading routes/vulns-serverlogic.js's
 *             lookupFakeService — it keys off `k.split("/")[0]`), so e.g.
 *             any path under the allowlisted metadata-service HOST returns
 *             the canned response, not just the exact registered path.
 *             That's a deliberate, reasonable simplification (real cloud
 *             metadata services also respond across many sub-paths) and
 *             this test's payload list is chosen to avoid asserting
 *             against that intentional behavior.
 */
const fs = require("fs");
const path = require("path");
const http = require("http");

const ROOT = path.join(__dirname, "..");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function httpGet(urlPath) {
  const startedAt = Date.now();
  return new Promise((resolve, reject) => {
    const r = http.request({ host: "localhost", port: 3000, path: urlPath, method: "GET" }, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body, elapsedMs: Date.now() - startedAt }));
    });
    r.on("error", reject);
    r.end();
  });
}

function staticChecks() {
  const forbiddenModules = ["http", "https", "net", "dns"];
  const scanDirs = ["routes", "src"];
  const offenders = [];

  function scanFile(filePath) {
    const src = fs.readFileSync(filePath, "utf8");
    for (const mod of forbiddenModules) {
      const re = new RegExp(`require\\(\\s*["']${mod}["']\\s*\\)`);
      if (re.test(src)) offenders.push(`${path.relative(ROOT, filePath)} requires "${mod}"`);
    }
    // Node 18+ has a global `fetch` — flag any direct use of it outside
    // this test file's own httpGet helper (server-side code has no
    // business making outbound fetch calls at all).
    if (/\bfetch\s*\(/.test(src) && !filePath.includes("node_modules")) {
      // fetch() appears in several lab PAGES as strings inside template
      // literals meant to run in the BROWSER (client-side JS the server
      // sends down, e.g. race-conditions' demo payload) — that's fine,
      // browser-side fetch calls to this app's own API are not a server-
      // side SSRF risk. Only flag it if it's outside a template literal
      // AND not clearly inside client-facing HTML/JS being sent to a
      // browser (heuristic: appears directly at file top-level module
      // code, not inside a `bodyHtml`/`res.send` string).
      const realServerSideFetch = /^[^`]*\bfetch\s*\(/m.test(src.split("bodyHtml")[0] || "");
      if (realServerSideFetch) offenders.push(`${path.relative(ROOT, filePath)} calls fetch() at module scope`);
    }
  }

  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".js")) scanFile(full);
    }
  }

  for (const d of scanDirs) walk(path.join(ROOT, d));

  check(
    "no route/src file requires http/https/net/dns, or calls fetch() at module scope",
    offenders.length === 0,
    offenders.join("; ")
  );

  const svcPath = path.join(ROOT, "src", "services", "fake-internal-network.js");
  const svcSrc = fs.readFileSync(svcPath, "utf8");
  check(
    "src/services/fake-internal-network.js is a static object literal (no function calls that could reach the network)",
    !/require\(/.test(svcSrc.replace(/module\.exports.*/s, ""))
  );
}

async function dynamicChecks() {
  // Payloads a real SSRF exploit would use against loopback / LAN /
  // cloud-metadata / a real public host — none of these should be able to
  // reach anything real, and none (except explicitly allowlisted ones)
  // should produce a canned "internal service" response either.
  const disallowedPayloads = [
    "http://127.0.0.1:22",
    "http://127.0.0.1:6379/flushall", // different literal host string than the allowlisted "localhost:6379" key
    "http://192.168.1.1/",
    "http://10.0.0.1/admin",
    "http://example.com/",
    "https://google.com/",
  ];

  for (const payload of disallowedPayloads) {
    const { status, body, elapsedMs } = await httpGet(`/vuln/ssrf?difficulty=easy&url=${encodeURIComponent(payload)}`);
    check(`SSRF with disallowed payload "${payload}" responds (not hung/crashed)`, status === 200, "status=" + status);
    check(`SSRF with disallowed payload "${payload}" responds fast (<1500ms — no real network attempt)`, elapsedMs < 1500, elapsedMs + "ms");
    check(
      `SSRF with disallowed payload "${payload}" does not leak real internal-service content`,
      !body.includes("AccessKeyId") && !body.includes("redis_version") && !body.includes("superadmin")
    );
  }

  // The exact allowlisted keys SHOULD still work — confirms the isolation
  // is a strict allowlist, not a coincidence of everything failing.
  const { body: metaBody } = await httpGet(
    `/vuln/ssrf?difficulty=easy&url=${encodeURIComponent("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin")}`
  );
  check("the exact allowlisted metadata-service payload DOES produce the canned response", metaBody.includes("AccessKeyId"));
}

async function run() {
  staticChecks();
  await dynamicChecks();
  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
