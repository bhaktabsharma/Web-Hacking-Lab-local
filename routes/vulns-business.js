/**
 * routes/vulns-business.js
 *
 * NEW CATEGORY — "Business Logic" (Phase 3b, Section 15 of the upgrade
 * spec). These bugs aren't about broken escaping or missing auth checks —
 * they're about an application's WORKFLOW/RULES trusting something they
 * shouldn't (a client-supplied price, a client-asserted "I paid" flag, an
 * un-normalized coupon string). Every dataset here is isolated per-session,
 * fresh in-memory state, consistent with every other lab in this app.
 *
 * Deliberately NOT duplicated here (already covered elsewhere): duplicate
 * transaction / TOCTOU concurrency -> the existing race-conditions lab;
 * role-change abuse -> vertical-privesc and api-mass-assignment; feature
 * restriction bypass -> client-side-validation-bypass. See the Phase 3b
 * report for the full scoping rationale.
 */
const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

// Product catalog now lives in src/labs/fixtures/products.js (shared with
// the ShopSphere storefront's own listing) — same ids/prices as before,
// just no longer duplicated inline here.

// ================================================== PRICE / QTY TAMPERING ==
router.get("/vuln/price-tampering", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const catalogLines = C.listProducts().map((p) => `<div class="product-line"><span>${p.name}</span><span>$${p.price.toFixed(2)}</span></div>`).join("");
  res.send(C.renderShopSpherePage({
    appName: "ShopSphere — Checkout", difficulty,
    bodyHtml: `
      <h1>Checkout</h1>
      ${catalogLines}
      <div class="result">fetch('/vuln/price-tampering/checkout?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({items:[{id:'widget',qty:1,price:49.99${difficulty === "hard" ? ",giftWrapDiscount:0" : ""}}]})})</div>
      <button onclick="tryIt()">Send the request above</button>
      <div class="result" id="out" style="display:none;"></div>
      ${difficulty === "easy" ? `<p class="note">The total is computed from whatever "price" you send — try a very low one.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">Price is now looked up server-side from the real catalog. Quantity isn't bounds-checked though — try a negative "qty".</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Quantity must now be positive. There's a "giftWrapDiscount" field for a gift-wrap promotion, applied to the total with no bounds check at all.</p>` : ""}
      <script>
        async function tryIt(){
          const r = await fetch('/vuln/price-tampering/checkout?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({items:[{id:'widget',qty:1,price:0.01}]})});
          const d = await r.json();
          const out = document.getElementById('out'); out.style.display='block'; out.textContent = JSON.stringify(d, null, 2);
        }
      </script>
    `
  }));
});
router.post("/vuln/price-tampering/checkout", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const items = Array.isArray(req.body.items) ? req.body.items : [];
  let total = 0;
  for (const item of items) {
    const catalogEntry = C.PRODUCTS[item.id];
    if (!catalogEntry) continue;
    let qty = Number(item.qty) || 0;
    if (difficulty === "hard" && qty < 1) qty = 1; // hard: negative qty now rejected (medium is still vulnerable to it)
    const unitPrice = difficulty === "easy" ? Number(item.price) || 0 : catalogEntry.price; // easy: client price trusted
    total += unitPrice * qty;
  }
  if (difficulty === "hard") {
    const giftWrapDiscount = Number(req.body.giftWrapDiscount) || 0;
    total += giftWrapDiscount; // unbounded — can be arbitrarily negative
  }
  const flag = total <= 5 ? C.getFlag(session, "price-tampering", difficulty) : undefined;
  res.json({ total: Math.round(total * 100) / 100, flag });
});

// ========================================================= COUPON ABUSE ====
router.get("/vuln/coupon-abuse", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderShopSpherePage({
    appName: "ShopSphere — Apply Coupon", difficulty,
    bodyHtml: `
      <h1>Apply Coupon</h1>
      <p class="note">Cart total: $500.00. Coupon "WELCOME10" takes 10% off, intended for one use.</p>
      <label>Coupon code</label>
      <input type="text" id="code" value="WELCOME10" />
      <button onclick="apply()">Apply</button>
      <div class="result" id="out"></div>
      ${difficulty === "easy" ? `<p class="note">Click Apply several times in a row.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The exact string "WELCOME10" is now single-use. Try a trailing space or different casing.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Coupon codes are normalized consistently now. There's also a separate "referral code" field, meant to be a different discount type — try submitting the same code there too, alongside the coupon.</p><label>Referral code</label><input type="text" id="ref" value="" />` : ""}
      <script>
        async function apply(){
          const code = document.getElementById('code').value;
          const ref = document.getElementById('ref') ? document.getElementById('ref').value : undefined;
          const r = await fetch('/vuln/coupon-abuse/apply?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code, referralCode: ref})});
          const d = await r.json();
          document.getElementById('out').innerHTML += JSON.stringify(d) + '<br>';
          if (d.flag) document.getElementById('out').innerHTML += '<strong style="color:#4ade80;">🚩 FLAG: ' + d.flag + '</strong>';
        }
      </script>
    `
  }));
});
function normalizeCoupon(code) { return String(code || "").trim().toUpperCase(); }
router.post("/vuln/coupon-abuse/apply", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "coupon-abuse", { total: 500, usedRawCodes: [], usedNormalizedCodes: [], referralUsed: false });
  const raw = req.body.code || "";
  const normalized = normalizeCoupon(raw);
  let applied = false;

  if (normalized === "WELCOME10") {
    if (difficulty === "easy") {
      applied = true; // no tracking at all
    } else if (difficulty === "medium") {
      if (!st.usedRawCodes.includes(raw)) { applied = true; st.usedRawCodes.push(raw); } // tracks the EXACT raw string only
    } else {
      if (!st.usedNormalizedCodes.includes(normalized)) { applied = true; st.usedNormalizedCodes.push(normalized); } // properly normalized tracking
    }
    if (applied) st.total *= 0.9;
  }

  if (difficulty === "hard" && normalizeCoupon(req.body.referralCode) === "WELCOME10" && !st.referralUsed) {
    st.referralUsed = true;
    st.total *= 0.9; // stackable "referral" discount reusing the same code value
  }

  // A single legitimate application lands at exactly $450 (500 * 0.9). Any
  // stacked/repeated discount lands at or below $405 (500 * 0.9 * 0.9) —
  // 410 cleanly separates "one coupon applied" from "abuse occurred."
  const flag = st.total < 410 ? C.getFlag(session, "coupon-abuse", difficulty) : undefined;
  res.json({ total: Math.round(st.total * 100) / 100, applied, flag });
});

// ====================================================== WORKFLOW BYPASS ====
router.get("/vuln/workflow-bypass", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderShopSpherePage({
    appName: "ShopSphere — Multi-Step Checkout", difficulty,
    bodyHtml: `
      <h1>Checkout: Cart → Payment → Confirm</h1>
      <p class="note">Order total: $${difficulty === "hard" ? "49.99 (then re-priced to $999.00 — see hint)" : "199.00"}. The intended flow requires completing Payment before Confirm succeeds.</p>
      <div class="result">// Skip straight to confirm:
fetch('/vuln/workflow-bypass/confirm?difficulty=${difficulty}', {method:'POST'})</div>
      <button onclick="skipToConfirm()">Try confirming without paying</button>
      <div class="result" id="out" style="display:none;"></div>
      ${difficulty === "medium" ? `<p class="note">Confirm now checks a "paid" flag — but does /pay actually verify anything? Try calling it with an empty body, then confirm.</p><button onclick="payThenConfirm()">Call /pay with nothing, then /confirm</button>` : ""}
      ${difficulty === "hard" ? `<p class="note">/pay now requires a real-looking payment token for the CURRENT order. Pay for the $49.99 order first, then change the cart to the $999 item before confirming — does it re-check the amount?</p><button onclick="payCheapThenSwitchAndConfirm()">Pay for $49.99, switch cart to $999, confirm</button>` : ""}
      <script>
        async function skipToConfirm(){
          const r = await fetch('/vuln/workflow-bypass/confirm?difficulty=${difficulty}', {method:'POST'});
          show(await r.json());
        }
        async function payThenConfirm(){
          await fetch('/vuln/workflow-bypass/pay?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
          const r = await fetch('/vuln/workflow-bypass/confirm?difficulty=${difficulty}', {method:'POST'});
          show(await r.json());
        }
        async function payCheapThenSwitchAndConfirm(){
          const tokenResp = await fetch('/vuln/workflow-bypass/get-payment-token?difficulty=${difficulty}&amount=49.99');
          const {paymentToken} = await tokenResp.json();
          await fetch('/vuln/workflow-bypass/pay?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paymentToken, amount:49.99})});
          await fetch('/vuln/workflow-bypass/set-cart?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({amount:999.00})});
          const r = await fetch('/vuln/workflow-bypass/confirm?difficulty=${difficulty}', {method:'POST'});
          show(await r.json());
        }
        function show(d){ const out=document.getElementById('out'); out.style.display='block'; out.textContent = JSON.stringify(d, null, 2); }
      </script>
    `
  }));
});
router.get("/vuln/workflow-bypass/get-payment-token", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "workflow-bypass", { paid: false, cartAmount: 199.0, paidAmount: 0 });
  const amount = Number(req.query.amount) || st.cartAmount;
  st.pendingToken = "ptok_" + C.randomHex(8);
  st.pendingAmount = amount;
  res.json({ paymentToken: st.pendingToken });
});
router.post("/vuln/workflow-bypass/set-cart", express.json(), (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "workflow-bypass", { paid: false, cartAmount: 199.0, paidAmount: 0 });
  st.cartAmount = Number(req.body.amount) || st.cartAmount;
  res.json({ cartAmount: st.cartAmount });
});
router.post("/vuln/workflow-bypass/pay", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "workflow-bypass", { paid: false, cartAmount: 199.0, paidAmount: 0 });
  if (difficulty === "hard") {
    if (req.body.paymentToken && req.body.paymentToken === st.pendingToken) {
      st.paid = true;
      st.paidAmount = st.pendingAmount; // recorded, but confirm (below) never re-checks this against the CURRENT cart amount
    }
  } else {
    st.paid = true; // easy/medium: no real verification, any call marks paid
  }
  res.json({ paid: st.paid });
});
router.post("/vuln/workflow-bypass/confirm", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "workflow-bypass", { paid: false, cartAmount: 199.0, paidAmount: 0 });
  let ok = false;
  if (difficulty === "easy") {
    ok = true; // no check at all
  } else if (difficulty === "medium") {
    ok = st.paid === true; // checked, but /pay above never verified a REAL payment
  } else {
    ok = st.paid === true; // checked — but never re-validates paidAmount against the CURRENT cartAmount
  }
  const underpaid = difficulty === "hard" && st.paid && st.paidAmount < st.cartAmount;
  const flag = ok && (difficulty !== "hard" || underpaid) ? C.getFlag(session, "workflow-bypass", difficulty) : undefined;
  res.json({ orderCompleted: ok, paidAmount: st.paidAmount, cartAmount: st.cartAmount, flag });
});

// ========================================================= REFUND ABUSE ====
router.get("/vuln/refund-abuse", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderShopSpherePage({
    appName: "ShopSphere — Refunds", difficulty,
    bodyHtml: `
      <h1>Order #8842 — $200.00 (completed)</h1>
      <div class="result">fetch('/vuln/refund-abuse/refund?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({amount:200})})</div>
      <button onclick="doRefund(200)">Request a $200 refund</button>
      ${difficulty === "easy" ? `<button onclick="doRefund(2000)">Request a $2000 refund instead</button>` : ""}
      ${difficulty === "medium" ? `<button onclick="doRefundThrice()">Request the $200 refund THREE times</button>` : ""}
      ${difficulty === "hard" ? `<button onclick="doFullThenPartial()">Full refund, then a $150 "partial" refund via support</button>` : ""}
      <div class="result" id="out" style="display:none;"></div>
      <script>
        async function post(path, body){ const r = await fetch(path + '?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})}); return r.json(); }
        function show(d){ const out=document.getElementById('out'); out.style.display='block'; out.textContent = JSON.stringify(d, null, 2); }
        async function doRefund(amount){ show(await post('/vuln/refund-abuse/refund', {amount})); }
        async function doRefundThrice(){ let last; for(let i=0;i<3;i++) last = await post('/vuln/refund-abuse/refund', {amount:200}); show(last); }
        async function doFullThenPartial(){ await post('/vuln/refund-abuse/refund', {amount:200}); const d = await post('/vuln/refund-abuse/partial-refund', {amount:150}); show(d); }
      </script>
    `
  }));
});
router.post("/vuln/refund-abuse/refund", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "refund-abuse", { orderTotal: 200, totalRefunded: 0, mainRefundUsed: false });
  let amount = Number(req.body.amount) || 0;
  if (difficulty === "easy") {
    st.totalRefunded += amount; // no cap at all
  } else if (difficulty === "medium") {
    amount = Math.min(amount, st.orderTotal); // capped per-call...
    st.totalRefunded += amount; // ...but callable repeatedly, no single-use tracking
  } else {
    if (!st.mainRefundUsed) { amount = Math.min(amount, st.orderTotal); st.totalRefunded += amount; st.mainRefundUsed = true; }
    else amount = 0;
  }
  const flag = st.totalRefunded > st.orderTotal ? C.getFlag(session, "refund-abuse", difficulty) : undefined;
  res.json({ refundedThisCall: amount, totalRefunded: st.totalRefunded, orderTotal: st.orderTotal, flag });
});
router.post("/vuln/refund-abuse/partial-refund", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "refund-abuse", { orderTotal: 200, totalRefunded: 0, mainRefundUsed: false });
  if (difficulty !== "hard") return res.status(404).json({ error: "Not found." });
  const amount = Math.max(0, Math.min(Number(req.body.amount) || 0, st.orderTotal)); // bounded against orderTotal alone — never checks totalRefunded already issued via the OTHER endpoint
  st.totalRefunded += amount;
  const flag = st.totalRefunded > st.orderTotal ? C.getFlag(session, "refund-abuse", difficulty) : undefined;
  res.json({ refundedThisCall: amount, totalRefunded: st.totalRefunded, orderTotal: st.orderTotal, flag, note: "Support-issued partial refund." });
});

// ===================================================== INVITATION ABUSE ====
router.get("/vuln/invitation-abuse", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderFinovaPage({
    appName: "Finova — Referral Program", difficulty,
    bodyHtml: `
      <h1>Invite a Friend — Earn $25 Credit</h1>
      <p class="note">Your code: <span class="pill">REF-JORDAN-9F2</span>. Simulates a new signup redeeming it.</p>
      <label>New signup email</label>
      <input type="text" id="email" value="victim@example.test" />
      <button onclick="redeem()">Simulate signup redeeming your code</button>
      <div class="result" id="out"></div>
      ${difficulty === "easy" ? `<p class="note">Click redeem several times in a row with the same email.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The exact email is now single-use. Try Gmail-style plus-addressing: victim+1@example.test, victim+2@example.test...</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Plus-addressing is normalized away now. There's also a bulk corporate-domain invite endpoint with no per-email tracking at all.</p><button onclick="bulkInvite()">Use the bulk corporate invite endpoint instead</button>` : ""}
      <script>
        async function post(path, body){ const r = await fetch(path + '?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})}); return r.json(); }
        async function redeem(){
          const email = document.getElementById('email').value;
          const d = await post('/vuln/invitation-abuse/redeem', {email});
          document.getElementById('out').innerHTML += JSON.stringify(d) + '<br>';
          if (d.flag) document.getElementById('out').innerHTML += '<strong style="color:#4ade80;">🚩 FLAG: ' + d.flag + '</strong>';
        }
        async function bulkInvite(){
          for (let i=0;i<6;i++){ const d = await post('/vuln/invitation-abuse/bulk-invite', {email:'victim'+i+'@example.test'}); document.getElementById('out').innerHTML += JSON.stringify(d) + '<br>'; if (d.flag) document.getElementById('out').innerHTML += '<strong style="color:#4ade80;">🚩 FLAG: ' + d.flag + '</strong>'; }
        }
      </script>
    `
  }));
});
function normalizeEmail(email) {
  const [local, domain] = String(email || "").toLowerCase().split("@");
  if (!domain) return String(email || "").toLowerCase();
  return local.split("+")[0] + "@" + domain;
}
router.post("/vuln/invitation-abuse/redeem", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "invitation-abuse", { credit: 0, usedRaw: [], usedNormalized: [] });
  const raw = String(req.body.email || "");
  let ok = false;
  if (difficulty === "easy") {
    ok = true;
  } else if (difficulty === "medium") {
    if (!st.usedRaw.includes(raw)) { ok = true; st.usedRaw.push(raw); }
  } else {
    const norm = normalizeEmail(raw);
    if (!st.usedNormalized.includes(norm)) { ok = true; st.usedNormalized.push(norm); }
  }
  if (ok) st.credit += 25;
  const flag = st.credit >= 100 ? C.getFlag(session, "invitation-abuse", difficulty) : undefined;
  res.json({ credited: ok, totalCredit: st.credit, flag });
});
router.post("/vuln/invitation-abuse/bulk-invite", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "invitation-abuse", { credit: 0, usedRaw: [], usedNormalized: [] });
  if (difficulty !== "hard") return res.status(404).json({ error: "Not found." });
  st.credit += 25; // no per-email tracking at all on this endpoint
  const flag = st.credit >= 100 ? C.getFlag(session, "invitation-abuse", difficulty) : undefined;
  res.json({ credited: true, totalCredit: st.credit, flag, note: "Bulk corporate-domain invite." });
});

// ================================================ ACCOUNT LINKING ABUSE ====
const LINK_STORE = new Map(); // token -> { forSessionSid, ownerUsername, linkedAccountData, expired }
router.get("/vuln/account-linking-abuse", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session, sid } = C.getOrInitSession(req, res);
  const st = C.labState(session, "account-linking-abuse", { myUsername: "you-" + C.randomHex(2) });

  // Seed a "victim" pending link (simulating another user mid-flow) once per difficulty.
  const victimKey = "victim_" + difficulty;
  if (!LINK_STORE.has(victimKey)) {
    let token;
    if (difficulty === "easy") token = String(1000 + Math.floor(Math.random() * 20)); // small, guessable range
    else token = "lnk_" + C.randomHex(10);
    LINK_STORE.set(victimKey, { token, forSid: "victim-session-does-not-exist", ownerUsername: "victim_amoore", linkedAccountData: "Visa •••• 4471, exp 09/28", expired: false });
    if (difficulty === "easy") LINK_STORE.set("bytoken_" + token, victimKey);
  }
  const victimRecord = LINK_STORE.get(victimKey);

  res.send(C.renderFinovaPage({
    appName: "Finova — Link a Payment Account", difficulty,
    bodyHtml: `
      <h1>Link an External Payment Account</h1>
      <p class="note">Logged in as: <strong>${st.myUsername}</strong></p>
      <label>Linking token</label>
      <input type="text" id="tok" value="" placeholder="paste a token" />
      <button onclick="link()">Complete Link</button>
      <div class="result" id="out" style="display:none;"></div>
      ${difficulty === "easy" ? `<p class="note">Another user (victim_amoore) currently has a pending link with a small, guessable token. Try values around ${victimRecord.token}.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">A victim's real pending token is: <code>${victimRecord.token}</code> (in real life this would leak via a referrer header, an email preview, or a shared link — here it's just shown for the exercise). Try submitting it as YOUR link.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Tokens are now properly bound to the session that requested them — the victim's token alone won't link via the normal flow anymore. There's a separate "link via support" override endpoint for customer-service-assisted linking, though, that accepts a token and a target username directly. <a href="/vuln/account-linking-abuse/support-log?difficulty=hard" target="_blank">A recent support ticket</a> might have exactly what you need.</p><button onclick="linkViaSupport()">Try /link-via-support instead</button>` : ""}
      <script>
        async function link(){
          const token = document.getElementById('tok').value;
          const r = await fetch('/vuln/account-linking-abuse/link?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});
          const d = await r.json();
          const out = document.getElementById('out'); out.style.display='block'; out.textContent = JSON.stringify(d, null, 2);
        }
        async function linkViaSupport(){
          const r = await fetch('/vuln/account-linking-abuse/link-via-support?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:${JSON.stringify(victimRecord.token)}, targetUsername:'me'})});
          const d = await r.json();
          const out = document.getElementById('out'); out.style.display='block'; out.textContent = JSON.stringify(d, null, 2);
        }
      </script>
    `
  }));
});
router.get("/vuln/account-linking-abuse/support-log", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const victimKey = "victim_" + difficulty;
  const victimRecord = LINK_STORE.get(victimKey);
  res.send(C.renderFinovaPage({
    appName: "Finova Support — Ticket #7734", difficulty,
    bodyHtml: `
      <h1>📋 Support Ticket #7734</h1>
      <p class="note">"...hi, I'm trying to link my bank account but the page timed out — here's the link I was on when it happened, can you finish it for me?"</p>
      <div class="result">https://securecorp-demo.test/vuln/account-linking-abuse?token=${victimRecord.token}&user=victim_amoore</div>
    `
  }));
});
router.post("/vuln/account-linking-abuse/link", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session, sid } = C.getOrInitSession(req, res);
  const submitted = String(req.body.token || "");
  const victimKey = "victim_" + difficulty;
  const victimRecord = LINK_STORE.get(victimKey);
  let matched = false;

  if (difficulty === "easy") {
    matched = submitted === victimRecord.token; // small guessable range, no ownership binding at all
  } else if (difficulty === "medium") {
    matched = submitted === victimRecord.token; // exists-check only — no verification the token was ever issued to THIS session
  } else {
    matched = false; // hard: tokens are properly bound to the session they were issued to — a victim's token alone can never satisfy this check via the normal flow
  }

  if (matched) {
    const flag = C.getFlag(session, "account-linking-abuse", difficulty);
    return res.json({ linked: true, accountData: victimRecord.linkedAccountData, flag });
  }
  res.json({ linked: false });
});
router.post("/vuln/account-linking-abuse/link-via-support", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (difficulty !== "hard") return res.status(404).json({ error: "Not found." });
  const submitted = String(req.body.token || "");
  const victimKey = "victim_" + difficulty;
  const victimRecord = LINK_STORE.get(victimKey);
  // "support override" convenience path — checks the token EXISTS as a
  // valid pending link, but never verifies it belongs to the CALLING
  // session, unlike the main /link endpoint above.
  if (submitted === victimRecord.token) {
    const flag = C.getFlag(session, "account-linking-abuse", difficulty);
    return res.json({ linked: true, accountData: victimRecord.linkedAccountData, flag, note: "Linked via support override." });
  }
  res.json({ linked: false });
});

module.exports = { router };
