/**
 * tests/csp-bypass.test.js — full coverage for the new csp-bypass lab
 * (Phase 3 addition, upgrade-spec Section 27). See routes/vulns-clientside.js
 * for the implementation and docs/UPGRADE-LOG.md for why this lab exists.
 *
 * Covers, per tier:
 *   - the real Content-Security-Policy response header is exactly what the
 *     lab claims (this is what makes it genuinely testable with curl -I /
 *     Burp, not just "trust the page copy")
 *   - the external app script is reachable and, at the hard tier, carries
 *     a nonce attribute matching the header's nonce-source
 *   - the client-proof-token flow: wrong token fails, correct token
 *     issues a real flag and marks the lab solved, and the token is
 *     single-use (mirrors the exact pattern already established for
 *     dom-xss/cstl/postmessage/prototype-pollution in tests/engine.test.js)
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
      res.on("end", () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: out,
        json: () => JSON.parse(out),
        setCookies: res.headers["set-cookie"] || [],
      }));
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

async function testTier(difficulty, expectedCspFragment) {
  const rInit = await req("GET", `/vuln/csp-bypass?difficulty=${difficulty}`);
  const sid = extractCookie(rInit.setCookies, "sid");
  const cookies = sid;

  check(`[${difficulty}] page responds 200`, rInit.status === 200);
  check(`[${difficulty}] a real CSP header is set`, !!rInit.headers["content-security-policy"]);
  check(`[${difficulty}] CSP header contains "${expectedCspFragment}"`, (rInit.headers["content-security-policy"] || "").includes(expectedCspFragment), rInit.headers["content-security-policy"]);
  check(`[${difficulty}] raw flag text is NOT present in initial page HTML`, !new RegExp("FLAG\\{csp-bypass").test(rInit.body));

  const tokenMatch = rInit.body.match(/data-token="([a-f0-9]+)"/);
  check(`[${difficulty}] a proof token IS present on the page`, !!tokenMatch, rInit.body.match(/data-token="[^"]*"/));
  let latestToken = tokenMatch ? tokenMatch[1] : null;

  if (difficulty === "hard") {
    const nonceMatch = rInit.body.match(/nonce="([a-f0-9]+)"/);
    check(`[hard] the app script tag carries a nonce attribute`, !!nonceMatch);
    if (nonceMatch) {
      const cspNonce = (rInit.headers["content-security-policy"] || "").match(/'nonce-([a-f0-9]+)'/);
      check(`[hard] the script tag's nonce matches the CSP header's nonce-source`, !!cspNonce && cspNonce[1] === nonceMatch[1]);
    }
    // The actual bug: reload and confirm the nonce did NOT rotate. Note:
    // reloading re-issues a fresh proof token too (same as every other
    // client-proof-token lab in this app — each page load gets its own
    // token), so the confirm step below deliberately uses THIS reload's
    // token, not the first request's.
    const rReload = await req("GET", `/vuln/csp-bypass?difficulty=hard`, { cookies });
    const nonceMatch2 = rReload.body.match(/nonce="([a-f0-9]+)"/);
    check(`[hard] the nonce is identical on a second request (the actual vulnerability)`, !!nonceMatch2 && nonceMatch2[1] === nonceMatch[1]);
    const tokenMatch2 = rReload.body.match(/data-token="([a-f0-9]+)"/);
    check(`[hard] a fresh proof token is issued on reload`, !!tokenMatch2);
    latestToken = tokenMatch2 ? tokenMatch2[1] : latestToken;
  }

  const rConfirmBad = await req("POST", "/api/confirm-client-exploit", { cookies, body: { labId: "csp-bypass", difficulty, token: "wrong-token-entirely" } });
  check(`[${difficulty}] confirm-client-exploit: wrong token -> success:false, no flag`, rConfirmBad.json().success === false && !rConfirmBad.json().flag);

  const rConfirmGood = await req("POST", "/api/confirm-client-exploit", { cookies, body: { labId: "csp-bypass", difficulty, token: latestToken } });
  const goodJson = rConfirmGood.json();
  check(`[${difficulty}] confirm-client-exploit: correct token -> success:true with a real flag`, goodJson.success === true && new RegExp(`^FLAG\\{csp-bypass-${difficulty}-`).test(goodJson.flag), JSON.stringify(goodJson));

  const rReplay = await req("POST", "/api/confirm-client-exploit", { cookies, body: { labId: "csp-bypass", difficulty, token: latestToken } });
  check(`[${difficulty}] confirm-client-exploit: token is single-use — replay fails`, rReplay.json().success === false);

  const rProgress = await req("GET", "/api/progress", { cookies });
  check(`[${difficulty}] progress marks csp-bypass solved`, !!rProgress.json().solved["csp-bypass"]);

  // Reset should clear it.
  await req("POST", "/api/reset-lab", { cookies, body: { labId: "csp-bypass" } });
  const rProgressAfterReset = await req("GET", "/api/progress", { cookies });
  check(`[${difficulty}] reset clears solved status`, !rProgressAfterReset.json().solved["csp-bypass"]);
}

async function run() {
  // Static asset check — the shared client script every tier depends on.
  const rAsset = await req("GET", "/js/csp-bypass-app.js");
  check("csp-bypass-app.js static asset is reachable", rAsset.status === 200);
  check("csp-bypass-app.js is served as JavaScript", (rAsset.headers["content-type"] || "").includes("javascript"));

  await testTier("easy", "'unsafe-inline'");
  await testTier("medium", "'unsafe-eval'");
  await testTier("hard", "'nonce-");

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
