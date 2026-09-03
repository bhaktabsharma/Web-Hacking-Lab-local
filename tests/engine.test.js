const http = require("http");
function req(method, path, { cookies = "", body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = { host: "localhost", port: 3000, path, method, headers: Object.assign({}, headers, cookies ? { Cookie: cookies } : {}, data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {}) };
    const r = http.request(opts, (res) => { let c = []; res.on("data", (d) => c.push(d)); res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString(), setCookie: res.headers["set-cookie"] || [], json: () => { try { return JSON.parse(Buffer.concat(c).toString()); } catch (e) { return null; } } })); });
    r.setTimeout(4000, () => r.destroy(new Error("timeout: " + method + " " + path)));
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}
function cookieStr(setCookieArr, existing) {
  const jar = {};
  (existing || "").split(";").forEach((p) => { const [k, v] = p.trim().split("="); if (k) jar[k] = v; });
  (setCookieArr || []).forEach((sc) => { const [kv] = sc.split(";"); const [k, v] = kv.split("="); jar[k] = v; });
  return Object.entries(jar).filter(([k]) => k).map(([k, v]) => `${k}=${v}`).join("; ");
}
let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 40000).unref();

async function run() {
  // ================= /api/progress: starts empty, requires session cookie =================
  let r0 = await req("GET", "/api/progress");
  let cookies = cookieStr(r0.setCookie, "");
  let d0 = r0.json();
  check("progress: fresh session starts with no solved labs", d0 && d0.solved && Object.keys(d0.solved).length === 0, JSON.stringify(d0));

  // ================= solving a lab for real marks it solved server-side =================
  let rMyProfile = await req("GET", "/vuln/idor?difficulty=easy", { cookies });
  cookies = cookieStr(rMyProfile.setCookie, cookies);
  const myIdMatch = rMyProfile.body.match(/pill">(\d+)</);
  const myId = myIdMatch ? myIdMatch[1] : "1";
  const targetId = myId === "1" ? "2" : "1"; // guaranteed to differ from my own randomly-assigned canonicalId
  let rEx = await req("GET", `/vuln/idor/profile?difficulty=easy&id=${targetId}`, { cookies });
  cookies = cookieStr(rEx.setCookie, cookies);
  const flagMatch = rEx.body.match(/FLAG\{[^}]+\}/);
  check("idor easy: viewing another user's profile yields a flag", !!flagMatch, rEx.body.slice(0, 300));

  let rBadValidate = await req("POST", "/api/validate-lab", { cookies, body: { labId: "idor", difficulty: "easy", answer: "FLAG{not-the-real-one}" } });
  check("validate-lab: wrong flag -> success:false", rBadValidate.json().success === false);

  let rProgressAfterWrong = await req("GET", "/api/progress", { cookies });
  check("validate-lab: wrong flag does NOT mark solved", !rProgressAfterWrong.json().solved.idor);

  let rValidate = await req("POST", "/api/validate-lab", { cookies, body: { labId: "idor", difficulty: "easy", answer: flagMatch[0] } });
  check("validate-lab: correct flag -> success:true", rValidate.json().success === true);

  let rProgress = await req("GET", "/api/progress", { cookies });
  let solved = rProgress.json().solved;
  check("progress: idor now marked solved server-side", !!solved.idor && solved.idor.difficulty === "easy", JSON.stringify(solved));

  // ================= cannot mark a lab solved from the frontend =================
  // (there is no client-writable path to /api/progress at all — GET only —
  // and validate-lab requires the actual session-issued flag string)
  let rFake = await req("POST", "/api/validate-lab", { cookies, body: { labId: "command-injection", difficulty: "hard", answer: "FLAG{command-injection-hard-deadbeef}" } });
  check("validate-lab: a well-formed but made-up flag is rejected", rFake.json().success === false);
  let rProgress2 = await req("GET", "/api/progress", { cookies });
  check("progress: the made-up submission did not mark command-injection solved", !rProgress2.json().solved["command-injection"]);

  // ================= reset invalidates the old flag AND clears solved state =================
  await req("POST", "/api/reset-lab", { cookies, body: { labId: "idor" } });
  let rProgress3 = await req("GET", "/api/progress", { cookies });
  check("reset-lab: solved status cleared after reset", !rProgress3.json().solved.idor);
  let rReplay = await req("POST", "/api/validate-lab", { cookies, body: { labId: "idor", difficulty: "easy", answer: flagMatch[0] } });
  check("reset-lab: the OLD flag no longer validates after reset", rReplay.json().success === false);
  let rExAgain = await req("GET", `/vuln/idor/profile?difficulty=easy&id=${targetId}`, { cookies });
  const flagMatch2 = rExAgain.body.match(/FLAG\{[^}]+\}/);
  check("reset-lab: a fresh exploit issues a NEW flag string", flagMatch2 && flagMatch2[0] !== flagMatch[0], flagMatch2 && flagMatch2[0]);

  // ================= flags are session-isolated: a different session can't reuse them =================
  let rOtherMyProfile = await req("GET", "/vuln/idor?difficulty=easy"); // no cookies = brand new session
  const otherCookiesBase = cookieStr(rOtherMyProfile.setCookie, "");
  const otherMyIdMatch = rOtherMyProfile.body.match(/pill">(\d+)</);
  const otherMyId = otherMyIdMatch ? otherMyIdMatch[1] : "1";
  const otherTargetId = otherMyId === "1" ? "2" : "1";
  let rOtherEx = await req("GET", `/vuln/idor/profile?difficulty=easy&id=${otherTargetId}`, { cookies: otherCookiesBase });
  const otherCookies = cookieStr(rOtherEx.setCookie, otherCookiesBase);
  const otherFlagMatch = rOtherEx.body.match(/FLAG\{[^}]+\}/);
  check("session isolation setup: session B got its own flag", !!otherFlagMatch, rOtherEx.body.slice(0, 300));
  let rCrossSession = await req("POST", "/api/validate-lab", { cookies: otherCookies, body: { labId: "idor", difficulty: "easy", answer: flagMatch2[0] } });
  check("session isolation: session B cannot redeem session A's flag", rCrossSession.json().success === false);
  let rCrossSessionOwn = await req("POST", "/api/validate-lab", { cookies: otherCookies, body: { labId: "idor", difficulty: "easy", answer: otherFlagMatch[0] } });
  check("session isolation: session B CAN redeem its own flag", rCrossSessionOwn.json().success === true);

  // ================= difficulty cannot be bypassed =================
  let rWrongTier = await req("POST", "/api/validate-lab", { cookies, body: { labId: "idor", difficulty: "hard", answer: flagMatch2[0] } });
  check("difficulty isolation: an easy-tier flag is rejected when submitted as hard", rWrongTier.json().success === false);

  // ================= reset-all wipes everything for the session =================
  await req("GET", "/vuln/xss?difficulty=easy&search=" + encodeURIComponent("<script>x</script>"), { cookies });
  await req("POST", "/api/validate-lab", { cookies, body: { labId: "idor", difficulty: "easy", answer: flagMatch2[0] } });
  let rBeforeResetAll = await req("GET", "/api/progress", { cookies });
  check("reset-all setup: idor is solved before reset-all", !!rBeforeResetAll.json().solved.idor);
  await req("POST", "/api/reset-all", { cookies });
  let rAfterResetAll = await req("GET", "/api/progress", { cookies });
  check("reset-all: every solved lab cleared", Object.keys(rAfterResetAll.json().solved).length === 0, JSON.stringify(rAfterResetAll.json().solved));

  // ================= hint tracking =================
  let rHint1 = await req("POST", "/api/hint-used", { cookies, body: { labId: "sql-injection" } });
  check("hint-used: first hint returns count 1", rHint1.json().count === 1, JSON.stringify(rHint1.json()));
  let rHint2 = await req("POST", "/api/hint-used", { cookies, body: { labId: "sql-injection" } });
  check("hint-used: second hint returns count 2", rHint2.json().count === 2);
  let rProgressHints = await req("GET", "/api/progress", { cookies });
  check("progress: hint count exposed via /api/progress", rProgressHints.json().hintsUsed["sql-injection"] === 2, JSON.stringify(rProgressHints.json().hintsUsed));

  // ================= client-proof pattern: flag never appears in page HTML before confirmation =================
  let rDomXss = await req("GET", "/vuln/dom-xss?difficulty=easy", { cookies });
  check("dom-xss: raw flag text is NOT present in initial page HTML", !/FLAG\{dom-xss/.test(rDomXss.body), rDomXss.body.includes("FLAG{") ? "FOUND A FLAG IN HTML" : "clean");
  check("dom-xss: a proof token IS present instead", /PROOF_TOKEN/.test(rDomXss.body));
  const tokenMatch = rDomXss.body.match(/PROOF_TOKEN\s*=\s*"([a-f0-9]+)"/);
  check("dom-xss: proof token extracted for confirm test", !!tokenMatch, rDomXss.body.match(/PROOF_TOKEN[^;]*/));

  let rConfirmBad = await req("POST", "/api/confirm-client-exploit", { cookies, body: { labId: "dom-xss", difficulty: "easy", token: "wrong-token-entirely" } });
  check("confirm-client-exploit: wrong token -> success:false, no flag leaked", rConfirmBad.json().success === false && !rConfirmBad.json().flag);

  let rConfirmGood = await req("POST", "/api/confirm-client-exploit", { cookies, body: { labId: "dom-xss", difficulty: "easy", token: tokenMatch[1] } });
  const confirmGoodJson = rConfirmGood.json();
  check("confirm-client-exploit: correct token -> success:true with real flag", confirmGoodJson.success === true && /^FLAG\{dom-xss-easy-/.test(confirmGoodJson.flag), JSON.stringify(confirmGoodJson));

  let rConfirmReplay = await req("POST", "/api/confirm-client-exploit", { cookies, body: { labId: "dom-xss", difficulty: "easy", token: tokenMatch[1] } });
  check("confirm-client-exploit: token is single-use — replay fails", rConfirmReplay.json().success === false);

  let rProgressAfterConfirm = await req("GET", "/api/progress", { cookies });
  check("confirm-client-exploit: also marks the lab solved server-side", !!rProgressAfterConfirm.json().solved["dom-xss"]);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}
run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
