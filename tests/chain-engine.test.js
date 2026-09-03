/**
 * tests/chain-engine.test.js — Phase 4 addition (upgrade-spec Section 33:
 * "Do not reduce complex chains to solved = true"). Covers the generic
 * chain-engine module directly (pure state-machine logic, no server
 * needed) plus the live end-to-end progression through all 3 real chains
 * wired into routes/vulns-chains.js, confirming every documented milestone
 * actually gets recorded server-side at the right moment — not just that
 * the final flag works (that's already covered by tests/chains.test.js).
 */
const http = require("http");
const chainEngine = require("../src/core/chain-engine");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function req(method, urlPath, { cookies, body, headers } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const h = Object.assign({}, headers);
    if (cookies) h.Cookie = cookies;
    if (data) { h["Content-Type"] = "application/json"; h["Content-Length"] = Buffer.byteLength(data); }
    const r = http.request({ host: "localhost", port: 3000, path: urlPath, method, headers: h }, (res) => {
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
  const line = (setCookies || []).find((c) => c.startsWith(name + "="));
  return line ? line.split(";")[0] : null;
}

function unitTests() {
  // Pure module-level tests — no server needed.
  const fakeSession = { lab: {} };
  const seq = chainEngine.fullSequence("chain-support-takeover");
  check("fullSequence starts NOT_STARTED and ends SOLVED", seq[0] === "NOT_STARTED" && seq[seq.length - 1] === "SOLVED");
  check("fullSequence for an unknown chain id is null", chainEngine.fullSequence("not-a-real-chain") === null);

  const s1 = chainEngine.getChainState(fakeSession, "chain-support-takeover");
  check("a fresh session starts at NOT_STARTED", s1.current === "NOT_STARTED");

  chainEngine.advanceChainState(fakeSession, "chain-support-takeover", "AUTHENTICATED");
  const s2 = chainEngine.getChainState(fakeSession, "chain-support-takeover");
  check("advancing to AUTHENTICATED skips over STARTED and CREDENTIAL_LEAK_FOUND but records both as reached", s2.current === "AUTHENTICATED" && "STARTED" in s2.reached && "CREDENTIAL_LEAK_FOUND" in s2.reached);

  chainEngine.advanceChainState(fakeSession, "chain-support-takeover", "STARTED");
  const s3 = chainEngine.getChainState(fakeSession, "chain-support-takeover");
  check("advancing to an EARLIER state than current is a safe no-op (never regresses)", s3.current === "AUTHENTICATED");

  chainEngine.advanceChainState(fakeSession, "chain-support-takeover", "NOT_A_REAL_STATE");
  const s4 = chainEngine.getChainState(fakeSession, "chain-support-takeover");
  check("advancing to an unrecognized state name is a safe no-op", s4.current === "AUTHENTICATED");

  check("getChainState for an unknown chain id is null", chainEngine.getChainState(fakeSession, "not-a-real-chain") === null);
  check("chainProgressSummary for an unknown chain id is null", chainEngine.chainProgressSummary(fakeSession, "not-a-real-chain") === null);
  check("allChainIds returns exactly the 3 chains this app has", chainEngine.allChainIds().length === 3, JSON.stringify(chainEngine.allChainIds()));
}

async function testChain1() {
  const chainId = "chain-support-takeover";
  const r0 = await req("GET", `/vuln/${chainId}?difficulty=easy`);
  const cookies = extractCookie(r0.setCookies, "sid");

  let p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] STARTED recorded on first page load`, p.current === "STARTED");

  await req("GET", `/vuln/${chainId}/backup/config.js.bak?difficulty=easy`, { cookies });
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] CREDENTIAL_LEAK_FOUND recorded after hitting the leaked backup file`, p.current === "CREDENTIAL_LEAK_FOUND");

  // Wrong-tier leak endpoint (404) must NOT advance state.
  await req("GET", `/vuln/${chainId}/.git-config?difficulty=easy`, { cookies }); // this is the HARD-tier leak, wrong for easy
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] a 404'd wrong-tier leak endpoint does NOT advance state`, p.current === "CREDENTIAL_LEAK_FOUND");

  await req("POST", `/vuln/${chainId}/login?difficulty=easy`, { cookies, body: { username: "wrong", password: "wrong" } });
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] a FAILED login attempt does NOT advance state`, p.current === "CREDENTIAL_LEAK_FOUND");

  await req("POST", `/vuln/${chainId}/login?difficulty=easy`, { cookies, body: { username: "support_temp", password: "Supp0rt_Temp_2026!" } });
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] AUTHENTICATED recorded after a real successful login`, p.current === "AUTHENTICATED");

  await req("GET", `/vuln/${chainId}/tickets/1?difficulty=easy`, { cookies });
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] TICKET_ACCESS_CONFIRMED recorded after viewing any ticket`, p.current === "TICKET_ACCESS_CONFIRMED");

  const rTicket2 = await req("GET", `/vuln/${chainId}/tickets/2?difficulty=easy`, { cookies });
  const flag = rTicket2.json().flag;
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] FLAG_ISSUED recorded after reaching the actual IDOR target ticket`, p.current === "FLAG_ISSUED");
  check(`[${chainId}] EXPLOIT_VERIFIED was recorded along the way (in 'reached')`, "EXPLOIT_VERIFIED" in p.reached);

  await req("POST", "/api/validate-lab", { cookies, body: { labId: chainId, difficulty: "easy", answer: flag } });
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] SOLVED recorded after submitting the correct flag`, p.current === "SOLVED");
  check(`[${chainId}] percentComplete reaches 100 at SOLVED`, p.percentComplete === 100);

  // A fresh, unrelated session must start at NOT_STARTED, not inherit progress.
  const pFresh = (await req("GET", `/api/chain-progress/${chainId}`)).json();
  check(`[${chainId}] a fresh session (no cookie) starts at NOT_STARTED — progress is session-scoped`, pFresh.current === "NOT_STARTED");
}

async function testChain2() {
  const chainId = "chain-internal-pivot";
  const r0 = await req("GET", `/vuln/${chainId}?difficulty=easy`);
  const cookies = extractCookie(r0.setCookies, "sid");

  let p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] STARTED recorded on first page load`, p.current === "STARTED");

  await req("POST", `/vuln/${chainId}/preview?difficulty=easy`, { cookies, body: { url: "https://example.com/not-internal" } });
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] a non-internal URL does NOT advance state`, p.current === "STARTED");

  const rPreview = await req("POST", `/vuln/${chainId}/preview?difficulty=easy`, { cookies, body: { url: "http://internal-admin.local/creds" } });
  const key = rPreview.json().internalKey;
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] SSRF_KEY_OBTAINED recorded once the SSRF genuinely reaches the internal target`, p.current === "SSRF_KEY_OBTAINED");

  await req("GET", `/vuln/${chainId}/admin-api/flag?difficulty=easy`, { cookies, headers: { "X-Internal-Key": "totally-wrong-key" } });
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] a wrong internal key does NOT advance state`, p.current === "SSRF_KEY_OBTAINED");

  const rFlag = await req("GET", `/vuln/${chainId}/admin-api/flag?difficulty=easy`, { cookies, headers: { "X-Internal-Key": key } });
  check(`[${chainId}] the real key is accepted`, rFlag.json().access === "granted");
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] FLAG_ISSUED recorded once the leaked key is actually used successfully`, p.current === "FLAG_ISSUED");
  check(`[${chainId}] percentComplete is < 100 before the flag is submitted via validate-lab`, p.percentComplete < 100);
}

async function testChain3() {
  const chainId = "chain-xss-to-admin-action";
  const r0 = await req("GET", `/vuln/${chainId}?difficulty=easy`);
  const cookies = extractCookie(r0.setCookies, "sid");

  let p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] STARTED recorded on first page load`, p.current === "STARTED");

  await req("POST", `/vuln/${chainId}/submit?difficulty=easy`, { cookies, body: { message: "just a normal support message, nothing live here" } });
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] submitting an inert (non-executable) message does NOT advance state`, p.current === "STARTED");

  await req("POST", `/vuln/${chainId}/submit?difficulty=easy`, { cookies, body: { message: "<img src=x onerror=\"fetch('/whatever')\">" } });
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] PAYLOAD_STORED recorded once a genuinely live payload survives the sanitizer`, p.current === "PAYLOAD_STORED");

  await req("POST", `/vuln/${chainId}/simulate-admin-review?difficulty=easy`, { cookies });
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] ADMIN_EXECUTION_CONFIRMED recorded once the simulated admin review detects the live payload`, p.current === "ADMIN_EXECUTION_CONFIRMED");

  const rApprove = await req("POST", `/vuln/${chainId}/admin-approve?difficulty=easy`, { cookies });
  check(`[${chainId}] the wire transfer is approved`, rApprove.json().transferApproved === true);
  p = (await req("GET", `/api/chain-progress/${chainId}`, { cookies })).json();
  check(`[${chainId}] FLAG_ISSUED recorded once the hijacked admin session takes the sensitive action`, p.current === "FLAG_ISSUED");
}

async function testUnknownChainId404s() {
  const r = await req("GET", "/api/chain-progress/not-a-real-chain");
  check("GET /api/chain-progress/:chainId for an unknown id returns 404", r.status === 404);
}

async function run() {
  unitTests();
  await testChain1();
  await testChain2();
  await testChain3();
  await testUnknownChainId404s();
  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
