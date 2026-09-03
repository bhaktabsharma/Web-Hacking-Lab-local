const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

const crypto = require("crypto");
const initSqlJs = require("sql.js");
// =================================================== INFO DISCLOSURE =======
router.get("/vuln/info-disclosure", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  let flag = null;
  if (difficulty === "hard") {
    flag = C.getFlag(session, "info-disclosure", difficulty);
    res.setHeader("X-Internal-Build", `securecorp-app v3.2.1-rc4 (build 20260614, node18-alpine) FLAG:${flag}`);
  }
  const amount = req.query.amount;
  let errorBox = "";
  if (difficulty === "easy" && amount !== undefined && isNaN(Number(amount))) {
    flag = C.getFlag(session, "info-disclosure", difficulty);
    errorBox = `<div class="result">TypeError: Cannot convert "${amount}" to a number
  at calculateTotal (/app/src/controllers/checkout.js:42:18)
  at processOrder (/app/src/services/orderService.js:87:5)
  env dump: DB_PASS=Tr41n1ng_DB_2026! (fake, simulating a verbose error leaking env vars)
FLAG: ${flag}</div>`;
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Checkout", difficulty,
    bodyHtml: `
      <h1>Checkout</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Order amount</label><input type="text" name="amount" placeholder="49.99" />
        <button type="submit">Submit</button>
      </form>
      ${errorBox}
      ${difficulty === "medium" ? `<p class="note">Psst — some deployments accidentally ship their <code>.git</code> folder: <a href="/vuln/info-disclosure/.git-config?difficulty=${difficulty}">/.git-config</a></p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Nothing looks unusual on the page itself here — check the response headers (Network tab / DevTools) for this request. The flag is inside the X-Internal-Build header value.</p>` : ""}
    `
  }));
});
router.get("/vuln/info-disclosure/.git-config", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (difficulty !== "medium") return res.status(404).send("Not found.");
  const flag = C.getFlag(session, "info-disclosure", difficulty);
  res.type("text/plain").send(`[remote "origin"]\n  url = https://ci:ghp_FAKEtoken1234567890abcdef@github.com/securecorp-demo/app.git\n[user]\n  db_password = Tr41n1ng_DB_2026! (fake credential)\n# FLAG: ${flag}`);
});

// ============================================== CLOUD STORAGE MISCONFIG ====
const FAKE_BUCKET = {
  "readme.txt": "Public readme — this one's actually meant to be public.",
  "employee-backup.csv": "id,name,note\n1,Alice,fake demo record\n2,Bob,fake demo record",
  "private/ceo-notes.txt": "Board meeting notes (fake, confidential) — Q3 numbers look good."
};
router.get("/vuln/cloud-storage-misconfig", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const action = req.query.action;
  const key = req.query.key;
  const sig = req.query.sig;
  let output = "", flag = null;

  if (action === "list") {
    if (difficulty !== "easy") output = "🚫 403 — listing is disabled for this bucket.";
    else output = "Bucket contents:\n" + Object.keys(FAKE_BUCKET).join("\n");
  } else if (action === "get" && key) {
    if (difficulty === "hard" && !sig) {
      output = "🚫 403 — signed request required (sig param missing).";
    } else if (FAKE_BUCKET[key]) {
      output = `${key}:\n${FAKE_BUCKET[key]}`;
      if (key !== "readme.txt") flag = C.getFlag(session, "cloud-storage-misconfig", difficulty);
    } else {
      output = `404 — no object named "${key}".`;
    }
  }

  res.send(C.renderVulnPage({
    appName: "SecureCorp Cloud Storage", difficulty,
    bodyHtml: `
      <h1>Simulated Storage Bucket</h1>
      <p class="note">This mimics a real cloud storage bucket (e.g. S3) misconfiguration — no real cloud account involved.</p>
      <a class="btn secondary" href="/vuln/cloud-storage-misconfig?difficulty=${difficulty}&action=list">List bucket</a>
      <form method="GET" style="margin-top:14px;">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <input type="hidden" name="action" value="get" />
        <label>Object key</label><input type="text" name="key" placeholder="employee-backup.csv" />
        ${difficulty === "hard" ? `<label>sig</label><input type="text" name="sig" placeholder="(any value)" />` : ""}
        <button type="submit">Get object</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Private object accessed without authorization.</strong>\nFLAG: ${flag}</div>` : ""}
    `
  }));
});

// ==================================================== SUBDOMAIN TAKEOVER ===
const CLAIMED_SLUGS = {};
function fakeDns(difficulty) {
  if (difficulty === "easy") {
    return {
      "www.securecorp-demo.test": { type: "A", value: "93.184.216.34" },
      "api.securecorp-demo.test": { type: "A", value: "93.184.216.35" },
      "shop.securecorp-demo.test": { type: "CNAME", value: "shop.trusted-cdn.test" },
      "old-blog.securecorp-demo.test": { type: "CNAME", value: "sc-oldblog.fakehost-service.test" }
    };
  }
  if (difficulty === "medium") {
    return {
      "www.securecorp-demo.test": { type: "A", value: "93.184.216.34" },
      "api.securecorp-demo.test": { type: "A", value: "93.184.216.35" },
      "shop.securecorp-demo.test": { type: "CNAME", value: "shop.trusted-cdn.test" },
      "mail.securecorp-demo.test": { type: "MX", value: "mail.securecorp-demo.test" },
      "cdn.securecorp-demo.test": { type: "CNAME", value: "cdn.trusted-cdn.test" },
      "status.securecorp-demo.test": { type: "CNAME", value: "status.trusted-statuspage.test" },
      "dev.securecorp-demo.test": { type: "A", value: "10.0.0.9" },
      "beta.securecorp-demo.test": { type: "CNAME", value: "sc-beta.fakehost-service.test" }
    };
  }
  return {
    "www.securecorp-demo.test": { type: "A", value: "93.184.216.34" },
    "api.securecorp-demo.test": { type: "A", value: "93.184.216.35" },
    "shop.securecorp-demo.test": { type: "CNAME", value: "shop.trusted-cdn.test" },
    "mail.securecorp-demo.test": { type: "MX", value: "mail.securecorp-demo.test" },
    "cdn.securecorp-demo.test": { type: "CNAME", value: "cdn.trusted-cdn.test" },
    "status.securecorp-demo.test": { type: "CNAME", value: "status.trusted-statuspage.test" },
    "dev.securecorp-demo.test": { type: "A", value: "10.0.0.9" },
    "archive.securecorp-demo.test": { type: "CNAME", value: "sc-archive.fakehost-service.test" }
  };
}
router.get("/vuln/subdomain-takeover", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const host = req.query.host;
  const dns = fakeDns(difficulty);
  const danglingHost = difficulty === "easy" ? "old-blog.securecorp-demo.test" : difficulty === "medium" ? "beta.securecorp-demo.test" : "archive.securecorp-demo.test";
  let output = "";
  if (host) {
    const rec = dns[host];
    if (!rec) output = "NXDOMAIN — no such record.";
    else {
      output = `${host} → ${rec.type} ${rec.value}`;
      if (rec.type === "CNAME") {
        const isClaimed = difficulty === "hard" ? (req.query.verify === "true" ? !!CLAIMED_SLUGS[rec.value] : true) : !!CLAIMED_SLUGS[rec.value];
        output += isClaimed ? "\n✅ Target service slot is claimed." : "\n⚠️ Target service slot appears UNCLAIMED — a classic subdomain takeover setup.";
        if (difficulty === "hard" && req.query.verify !== "true") output += "\n(add the verify checkbox to actually check claim status)";
      }
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp DNS Zone Lookup", difficulty,
    bodyHtml: `
      <h1>DNS Lookup Tool</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Hostname</label><input type="text" name="host" placeholder="${danglingHost}" />
        ${difficulty === "hard" ? `<label><input type="checkbox" name="verify" value="true" style="width:auto;display:inline-block;margin-right:6px;" /> verify claim status</label>` : ""}
        <button type="submit">Lookup</button>
      </form>
      ${output ? `<div class="result">${output}</div>` : ""}
      <p class="note">Known subdomains to check: ${Object.keys(dns).join(", ")}</p>
      <p class="note" style="margin-top:12px;"><a href="/vuln/subdomain-takeover/claim?difficulty=${difficulty}">Claim an unclaimed hosting slot →</a></p>
    `
  }));
});
router.get("/vuln/subdomain-takeover/claim", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const slug = req.query.slug, content = req.query.content;
  const danglingHost = difficulty === "easy" ? "old-blog.securecorp-demo.test" : difficulty === "medium" ? "beta.securecorp-demo.test" : "archive.securecorp-demo.test";
  const danglingSlug = difficulty === "easy" ? "sc-oldblog.fakehost-service.test" : difficulty === "medium" ? "sc-beta.fakehost-service.test" : "sc-archive.fakehost-service.test";
  let message = "";
  if (slug) {
    CLAIMED_SLUGS[slug] = content || "(this space intentionally left blank by the attacker)";
    message = `<div class="result">✅ Claimed "${slug}". Now visit the subdomain preview to see your content served under SecureCorp's domain.</div>`;
  }
  res.send(C.renderVulnPage({
    appName: "Fakehost Hosting (simulated)", difficulty,
    bodyHtml: `
      <h1>Claim a Hosting Slot</h1>
      <p class="note">Simulates registering an abandoned third-party hosting slug that a dangling DNS CNAME still points to.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Slug</label><input type="text" name="slug" placeholder="${danglingSlug}" />
        <label>Content to serve</label><input type="text" name="content" placeholder="Pwned by a training exercise" />
        <button type="submit">Claim</button>
      </form>
      ${message}
      <p class="note"><a href="/vuln/subdomain-takeover/preview?host=${danglingHost}&difficulty=${difficulty}" target="_blank">Preview ${danglingHost} →</a></p>
    `
  }));
});
router.get("/vuln/subdomain-takeover/preview", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const dns = fakeDns(difficulty);
  const rec = dns[req.query.host];
  const claimed = rec && rec.type === "CNAME" ? CLAIMED_SLUGS[rec.value] : null;
  const flag = claimed ? C.getFlag(session, "subdomain-takeover", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: req.query.host || "Unknown host", difficulty,
    bodyHtml: claimed
      ? `<h1>${req.query.host}</h1><div class="result">${claimed}</div><p class="note">This content is now served under SecureCorp's own domain via the dangling CNAME.</p><div class="result" style="border-color:#4ade80;"><strong>🚩 Subdomain takeover confirmed.</strong>\nFLAG: ${flag}</div>`
      : `<h1>${req.query.host}</h1><p class="note">This hosting slot is currently unclaimed.</p>`
  }));
});

// ==================================================== SOURCE MAP LEAKAGE ===
// Input context: static file discovery, with a build-manifest discovery
// chain at the hard tier.
router.get("/vuln/source-map-leak", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Web App", difficulty,
    bodyHtml: `
      <h1>SecureCorp Marketing Site</h1>
      <p class="note">A normal-looking public site. Its minified JS bundle might reveal more than intended.</p>
      <a class="btn secondary" href="/vuln/source-map-leak/app.min.js?difficulty=${difficulty}" target="_blank">View /assets/app.min.js →</a>
      ${difficulty === "medium" ? `<p class="note">The JS file no longer links its map — but the conventional filename.map naming pattern is worth trying directly.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Neither the JS link nor the conventional filename work here. Build tools sometimes leave a manifest listing every generated asset.</p><a class="btn secondary" href="/vuln/source-map-leak/manifest.json?difficulty=hard" target="_blank">View /assets/manifest.json →</a>` : ""}
    `
  }));
});
router.get("/vuln/source-map-leak/app.min.js", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.type("application/javascript");
  let js = `!function(){console.log("SecureCorp app loaded")}();`;
  if (difficulty === "easy") js += `\n//# sourceMappingURL=app.min.js.map`;
  res.send(js);
});
function sourceMapPayload(flag) {
  return { version: 3, file: "app.min.js", sourcesContent: [`// app.js (original source)\nconst INTERNAL_API_KEY = 'sk_internal_FAKE_7f2a9c3d1e';\n// FLAG: ${flag}\nfunction init(){ console.log('SecureCorp app loaded'); }\ninit();`] };
}
router.get("/vuln/source-map-leak/app.min.js.map", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (difficulty === "hard") return res.status(404).send("Not found.");
  res.json(sourceMapPayload(C.getFlag(session, "source-map-leak", difficulty)));
});
router.get("/vuln/source-map-leak/bundle.7f3a9c.js.map", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (difficulty !== "hard") return res.status(404).send("Not found.");
  res.json(sourceMapPayload(C.getFlag(session, "source-map-leak", difficulty)));
});
router.get("/vuln/source-map-leak/manifest.json", (req, res) => {
  const difficulty = C.difficultyOf(req);
  if (difficulty !== "hard") return res.status(404).send("Not found.");
  res.json({ "app.js": "/vuln/source-map-leak/bundle.7f3a9c.js", "app.js.map": "/vuln/source-map-leak/bundle.7f3a9c.js.map" });
});

// ==================================================== EXPOSED DEV ENDPOINT =
// Input context: hidden API endpoint, gated by simulated headers, with a
// chained discovery step via /robots.txt at the hard tier.
router.get("/vuln/exposed-dev-endpoint", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp API Gateway", difficulty,
    bodyHtml: `
      <h1>API Gateway</h1>
      <p class="note">Public endpoints: /health (fine). A debug endpoint may have been left enabled from development.</p>
      <a class="btn secondary" href="/vuln/exposed-dev-endpoint/debug?difficulty=${difficulty}" target="_blank">Try /debug →</a>
      ${difficulty !== "easy" ? `<h4 style="color:#5b6470;margin-top:20px;">Raw request console</h4>
        <label>Simulated Host header</label><input type="text" id="h" placeholder="internal.securecorp-demo.test" />
        ${difficulty === "hard" ? `<label>X-Debug-Token</label><input type="text" id="tok" />` : ""}
        <button class="secondary" onclick="callDebug()">Call /debug</button>
        <div id="out" style="display:none;"></div>
        <script>
          async function callDebug(){
            const headers = {'X-Simulated-Host': document.getElementById('h').value};
            const tokEl = document.getElementById('tok');
            if (tokEl) headers['X-Debug-Token'] = tokEl.value;
            const r = await fetch('/vuln/exposed-dev-endpoint/debug?difficulty=${difficulty}', {headers});
            const t = await r.text();
            const o = document.getElementById('out');
            o.style.display = 'block';
            o.innerHTML = t;
          }
        </script>` : ""}
      ${difficulty === "hard" ? `<p class="note">Check <a href="/vuln/exposed-dev-endpoint/robots.txt?difficulty=hard" target="_blank">/robots.txt</a> — sometimes it discloses more than intended.</p>` : ""}
    `
  }));
});
router.get("/vuln/exposed-dev-endpoint/robots.txt", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.type("text/plain");
  if (difficulty !== "hard") return res.send("User-agent: *\nDisallow: /admin");
  res.send("User-agent: *\nDisallow: /admin\n# TODO remove before launch: debug token = temp-debug-2026");
});
router.get("/vuln/exposed-dev-endpoint/debug", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const resultStyle = "background:#f4f5f7;border:1px solid #e2e5e9;border-radius:8px;padding:14px 16px;font-family:ui-monospace,Menlo,monospace;font-size:.85rem;white-space:pre-wrap;";
  let allowed;
  if (difficulty === "easy") allowed = true;
  else if (difficulty === "medium") allowed = req.headers["x-simulated-host"] === "internal.securecorp-demo.test";
  else allowed = req.headers["x-simulated-host"] === "internal.securecorp-demo.test" && req.headers["x-debug-token"] === "temp-debug-2026";

  if (!allowed) return res.status(404).send(`<div style="${resultStyle}">404 Not Found</div>`);
  const flag = C.getFlag(session, "exposed-dev-endpoint", difficulty);
  res.send(`<div style="${resultStyle}">DEBUG DUMP\nnode_env: development\nfeature_flags: {new_checkout: true, beta_search: true}\ninternal_db_host: 10.0.0.12\n\n🚩 FLAG: ${flag}</div>`);
});


// ============================================================================
// Consolidated from vulns-infra-new.js during the Phase 1 architecture cleanup —
// same labs, same behavior, just no longer a separate "-new" module.
// ============================================================================
// ========================================= SENSITIVE DATA IN WEB STORAGE ===
router.get("/vuln/web-storage-secrets", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const proofToken = C.issueClientProofToken(session, "web-storage-secrets", difficulty);
  const rawSecret = "sk_live_" + C.randomHex(10);
  let storeScript, hint;
  if (difficulty === "easy") {
    storeScript = `localStorage.setItem('authToken', ${JSON.stringify(rawSecret)});`;
    hint = `Run in DevTools console: <code>localStorage.getItem('authToken')</code>`;
  } else if (difficulty === "medium") {
    const encoded = Buffer.from(rawSecret).toString("base64");
    storeScript = `localStorage.setItem('_scfg_v3', ${JSON.stringify(encoded)});`;
    hint = `Key name is obfuscated. Run: <code>Object.keys(localStorage)</code> to find it, then <code>atob(localStorage.getItem('_scfg_v3')))</code>`;
  } else {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64").replace(/=+$/, "");
    const payload = Buffer.from(JSON.stringify({ sub: "amoore", apiToken: rawSecret, role: "user" })).toString("base64").replace(/=+$/, "");
    const fakeJwt = `${header}.${payload}.${crypto.randomBytes(16).toString("hex")}`;
    storeScript = `sessionStorage.setItem('sc_session_jwt', ${JSON.stringify(fakeJwt)});`;
    hint = `Run: <code>JSON.parse(atob(sessionStorage.getItem('sc_session_jwt').split('.')[1]))</code> — no signature verification needed just to READ the claims.`;
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Wallet Dashboard", difficulty,
    bodyHtml: `
      <h1>Wallet Dashboard</h1>
      <p class="note">For "convenience," this page keeps your API session token in Web Storage rather than an HttpOnly cookie — meaning ANY script on this page (any XSS anywhere on the origin, or just an open DevTools console) can read it directly. No injection needed to demonstrate the exposure itself.</p>
      <button onclick="scan()">Simulate malicious script scanning storage</button>
      <div class="result" id="out" style="display:none;"></div>
      <p class="note">${hint}</p>
      <script>
        ${storeScript}
        const PROOF_TOKEN = ${JSON.stringify(proofToken)};
        const DIFFICULTY = ${JSON.stringify(difficulty)};
        async function scan(){
          let found = null;
          for (const store of [localStorage, sessionStorage]) {
            for (let i=0;i<store.length;i++){
              const k = store.key(i), v = store.getItem(k);
              if (DIFFICULTY === 'easy' && k === 'authToken') found = v;
              if (DIFFICULTY === 'medium' && k === '_scfg_v3') { try { found = atob(v); } catch(e){} }
              if (DIFFICULTY === 'hard' && k === 'sc_session_jwt') { try { found = JSON.parse(atob(v.split('.')[1])).apiToken; } catch(e){} }
            }
          }
          const out = document.getElementById('out');
          out.style.display = 'block';
          if (found) {
            const r = await fetch('/api/confirm-client-exploit', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({labId:'web-storage-secrets', difficulty:DIFFICULTY, token:PROOF_TOKEN}) });
            const d = await r.json();
            out.innerHTML = d.success ? '<strong>🚩 Secret extracted from client-side storage.</strong>\\nFound: ' + found + '\\nFLAG: ' + d.flag : 'Scan ran but did not extract the right value.';
            out.style.borderColor = d.success ? '#4ade80' : '';
          } else {
            out.textContent = 'Nothing recognizable found in storage.';
          }
        }
      </script>
    `
  }));
});

// ================================================== BASE64-ENCODED SECRETS =
router.get("/vuln/base64-secrets", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const realSecret = "SC-API-KEY-7f3d9c";
  let blob, note;
  if (difficulty === "easy") { blob = Buffer.from(`apiKey:${realSecret}`).toString("base64"); note = "Single base64 pass."; }
  else if (difficulty === "medium") { blob = Buffer.from(Buffer.from(`apiKey:${realSecret}`).toString("base64")).toString("base64"); note = "Encoded twice."; }
  else { blob = Buffer.from(`apiKey:${realSecret}`.split("").reverse().join("")).toString("base64"); note = "Reversed, then base64-encoded."; }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Developer Portal — Config Export", difficulty,
    bodyHtml: `
      <h1>Sanitized Config Export</h1>
      <p class="note">"Sensitive fields are obfuscated for the public export." (${note})</p>
      <div class="result">${blob}</div>
      <form method="GET" action="/vuln/base64-secrets/submit">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Decoded secret value</label><input type="text" name="decoded" placeholder="apiKey:..." />
        <button type="submit">Submit</button>
      </form>
      ${difficulty === "easy" ? `<p class="note">Decode the blob (base64) and submit the full "apiKey:..." string.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">This one needs decoding TWICE.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Decode it, then you'll notice the result reads backwards — reverse the string too. Still zero real cryptographic protection either way.</p>` : ""}
    `
  }));
});
router.get("/vuln/base64-secrets/submit", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const expected = "apiKey:SC-API-KEY-7f3d9c";
  const ok = (req.query.decoded || "").trim() === expected;
  const flag = ok ? C.getFlag(session, "base64-secrets", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Developer Portal — Config Export", difficulty,
    bodyHtml: ok ? `<h1>✅ Correct</h1><div class="result" style="border-color:#4ade80;"><strong>🚩 Encoding mistaken for encryption.</strong>\nFLAG: ${flag}</div>` : `<h1>❌ Not quite</h1><p class="note">That doesn't match the fully-decoded secret.</p><p><a href="/vuln/base64-secrets?difficulty=${difficulty}">← Back</a></p>`
  }));
});

// ========================================== HEARTBLEED (SIMULATED) =========
// ⚠️ SIMULATED — real Heartbleed (CVE-2014-0160) requires a malformed raw
// TLS heartbeat packet against a vulnerable OpenSSL version; that's
// impossible to replicate with a normal HTTP request. This reproduces the
// real bug's REQUEST/RESPONSE SHAPE: declare a payload_length larger than
// your actual payload, and the (fake) server echoes back extra bytes from
// its "memory" buffer instead of validating the length — the exact logic
// error of the real CVE, applied to entirely fake in-memory data.
const HB_MEMORY = [
  "...normal traffic fragment...",
  "Authorization: Bearer fake_leaked_session_8a12 (fake demo data)",
  "...more normal traffic...",
  "X-Internal-Flag: PLACEHOLDER",
  "...padding padding padding..."
];
router.get("/vuln/heartbleed-sim", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp API Gateway (legacy TLS 1.0, OpenSSL 1.0.1f)", difficulty,
    bodyHtml: `
      <h1>⚠️ SIMULATED Heartbleed (CVE-2014-0160)</h1>
      <p class="note">Real Heartbleed needs a raw malformed TLS heartbeat packet — impossible over normal HTTP. This reproduces the exact bug LOGIC (server trusts a claimed length instead of the real payload size) against fake in-memory data only.</p>
      <form method="GET" action="/vuln/heartbleed-sim/beat">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>payload</label><input type="text" name="payload" value="PING" />
        <label>payload_length (the bug: this is trusted blindly)</label><input type="text" name="payload_length" value="4" />
        <button type="submit">Send Heartbeat</button>
      </form>
      ${difficulty === "easy" ? `<p class="note">Set payload_length much larger than payload (e.g. 200) to over-read the fake memory buffer.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The leaked flag is further into the buffer this time — push payload_length even higher.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Real Heartbleed leaks DIFFERENT memory each time depending on server activity. Send a heartbeat once to "warm up," then send a second one with a large payload_length — the flag only appears on a repeat request.</p>` : ""}
    `
  }));
});
router.get("/vuln/heartbleed-sim/beat", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "heartbleed-sim", { requestCount: 0 });
  st.requestCount++;
  const flag = C.getFlag(session, "heartbleed-sim", difficulty);
  const memoryLines = HB_MEMORY.map((l) => l === "X-Internal-Flag: PLACEHOLDER" ? `X-Internal-Flag: ${flag}` : l);
  const payload = req.query.payload || "";
  const declaredLen = parseInt(req.query.payload_length, 10) || 0;
  const overreadAmount = Math.max(0, declaredLen - payload.length);
  const thresholds = { easy: 30, medium: 80, hard: 150 };
  let leaked = null;
  const enoughOverread = overreadAmount >= thresholds[difficulty];
  const enoughRequests = difficulty !== "hard" || st.requestCount >= 2;
  if (enoughOverread && enoughRequests) {
    leaked = memoryLines.slice(0, Math.min(memoryLines.length, Math.ceil(overreadAmount / 20)));
  }
  const response = payload + (leaked ? "\n[LEAKED MEMORY BEYOND PAYLOAD]\n" + leaked.join("\n") : "");
  const includesFlag = response.includes(flag);
  res.send(C.renderVulnPage({
    appName: "SecureCorp API Gateway (legacy TLS 1.0, OpenSSL 1.0.1f)", difficulty,
    bodyHtml: `<h1>Heartbeat response</h1><div class="result">${response.replace(/</g, "&lt;")}</div>${includesFlag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Server memory over-read — sensitive data leaked.</strong>\nFLAG: ${flag}</div>` : ""}<p style="margin-top:16px;"><a class="btn secondary" href="/vuln/heartbleed-sim?difficulty=${difficulty}">← Send another</a></p>`
  }));
});

// ====================================================== SHELLSHOCK =========
// ⚠️ SIMULATED — reproduces the real Bash function-definition parser bug
// signature (CVE-2014-6271), pattern-matched only. Never touches a real
// shell. Distinct from command-injection: no shell metacharacters needed at
// all — the entire payload lives inside the "() { :; };" magic prefix.
const SS_CMD_OUTPUTS = { whoami: "trainee", id: "uid=1000(trainee) gid=1000(trainee) groups=1000(trainee)", "cat /etc/passwd": C.VFS["/etc/passwd"] };
function detectShellshock(headerVal, difficulty) {
  const v = String(headerVal || "");
  // what a REAL vulnerable bash would parse as a function definition,
  // tolerant of leading whitespace the way bash's own parser is.
  const realPattern = /^\s*\(\)\s*\{/.test(v);
  if (!realPattern) {
    // hard tier's decoy-prefix bypass: the magic bytes appear later in the
    // string rather than at the very start.
    if (difficulty === "hard") return /\(\)\s*\{[^}]*\}\s*;/.test(v);
    return false;
  }
  if (difficulty === "easy") return true; // no filter at all
  if (difficulty === "medium") return !v.startsWith("() {"); // naive EXACT-prefix filter catches the literal form; anything else (e.g. leading whitespace) — which bash still parses identically — slips straight through
  return false; // hard: the anchored regex above already blocks every real-pattern match correctly
}
router.get("/vuln/shellshock", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Legacy Diagnostics (CGI)", difficulty,
    bodyHtml: `
      <h1>⚠️ SIMULATED Shellshock (CVE-2014-6271)</h1>
      <p class="note">A legacy bash-CGI diagnostics script reads a "User-Agent"-style header. ⚙️ Simulated — pattern-matched only, never a real shell.</p>
      <form method="GET" action="/vuln/shellshock/run">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Simulated User-Agent header</label><input type="text" name="ua" placeholder='() { :; }; echo vulnerable' />
        <button type="submit">Run Diagnostics</button>
      </form>
      ${difficulty === "easy" ? `<p class="note">Try: <code>() { :; }; cat /etc/passwd</code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">Values are checked against the EXACT literal prefix "() {" — try a leading space: <code> () { :; }; cat /etc/passwd</code></p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The prefix pattern is now robustly blocked. But the check only looks at the START of the header — try prepending decoy content: <code>Mozilla/5.0 () { :; }; cat /etc/passwd</code></p>` : ""}
    `
  }));
});
router.get("/vuln/shellshock/run", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const ua = req.query.ua || "";
  const vulnerable = detectShellshock(ua, difficulty);
  let output = "Diagnostics: OK (no anomalies)", flag = null;
  if (vulnerable) {
    const key = Object.keys(SS_CMD_OUTPUTS).find((k) => ua.toLowerCase().includes(k));
    output = "[SIMULATED RCE PROOF] " + (key ? SS_CMD_OUTPUTS[key] : "uid=1000(trainee) gid=1000(trainee) — Shellshock parser bug triggered");
    flag = C.getFlag(session, "shellshock", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Legacy Diagnostics (CGI)", difficulty,
    bodyHtml: `<h1>Result</h1><div class="result">${output}</div>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Shellshock parser bug triggered.</strong>\nFLAG: ${flag}</div>` : ""}<p style="margin-top:16px;"><a class="btn secondary" href="/vuln/shellshock?difficulty=${difficulty}">← Back</a></p>`
  }));
});

// ==================================================== DRUPAGEDDON ==========
// ⚠️ SIMULATED — replicates the real logic error behind CVE-2014-3704:
// Drupal's DB layer auto-expanded ARRAY-shaped input into extra SQL
// placeholders, using the array's KEYS directly as unvalidated SQL. Own
// isolated sql.js instance — does not touch any other lab's database.
let drupalDbReady;
function getDrupalDb() {
  if (!drupalDbReady) {
    drupalDbReady = initSqlJs().then((SQL) => {
      const db = new SQL.Database();
      db.run(`CREATE TABLE comments (id INTEGER, name TEXT, body TEXT);`);
      db.run(`INSERT INTO comments VALUES (1,'alice','Nice article!'),(2,'bob','Thanks for sharing.');`);
      db.run(`CREATE TABLE admin_secrets (id INTEGER, token TEXT);`);
      db.run(`INSERT INTO admin_secrets VALUES (1,'DRUPAL-ADMIN-c92a1f');`);
      return db;
    });
  }
  return drupalDbReady;
}
router.get("/vuln/drupageddon", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Blog (Drupal-Compatible Comments Module)", difficulty,
    bodyHtml: `
      <h1>⚠️ SIMULATED Drupageddon (CVE-2014-3704)</h1>
      <p class="note">POST a JSON body to <code>/vuln/drupageddon/comment</code>. Normally <code>name</code> is a plain string — but if you send it as an OBJECT, this (simulated) DB layer auto-expands each key directly into the SQL WHERE clause, unvalidated — the exact real bug.</p>
      <div class="result">fetch('/vuln/drupageddon/comment?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name: {"x') OR ('1'='1": "y"}, email:"a@b.com"})})</div>
      ${difficulty === "medium" ? `<p class="note">The "name" field is now validated as a plain string. The "email" field on the same endpoint never got the same check.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both "name" and "email" are validated now. There's also a "meta" object for extra form data, merged in without the same guard: <code>{"name":"x","email":"a@b.com","meta":{"name":{"...injection...":"y"}}}</code></p>` : ""}
    `
  }));
});
router.post("/vuln/drupageddon/comment", async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const body = req.body || {};
  let injectableKey = null;

  function extractIfArrayLike(val) {
    if (val && typeof val === "object" && !Array.isArray(val)) return Object.keys(val)[0];
    return null;
  }

  if (difficulty === "easy") {
    injectableKey = extractIfArrayLike(body.name);
  } else if (difficulty === "medium") {
    if (typeof body.name !== "string") return res.json({ error: "name must be a string." });
    injectableKey = extractIfArrayLike(body.email);
  } else {
    if (typeof body.name !== "string") return res.json({ error: "name must be a string." });
    if (typeof body.email !== "string") return res.json({ error: "email must be a string." });
    if (body.meta && typeof body.meta === "object") injectableKey = extractIfArrayLike(body.meta.name);
  }

  if (!injectableKey) return res.json({ error: "No comment posted (nothing array-shaped to expand)." });
  const query = `SELECT id, token FROM admin_secrets WHERE ('${injectableKey}')`;
  try {
    const db = await getDrupalDb();
    const r = db.exec(query);
    const rows = r.length ? r[0].values : [];
    const flag = rows.length ? C.getFlag(session, "drupageddon", difficulty) : undefined;
    res.json({ query, rows, flag });
  } catch (e) {
    res.json({ query, error: e.message });
  }
});

// =================================================== PHP-CGI RCE ===========
// ⚠️ SIMULATED — replicates CVE-2012-1823: when PHP runs via CGI (not as an
// Apache module), php-cgi misinterprets certain query-string content as
// command-line flags to the php-cgi binary itself. Detected here purely by
// pattern, never a real interpreter invocation.
const PHPCGI_DANGEROUS_DIRECTIVES = ["allow_url_include", "auto_prepend_file", "disable_functions", "safe_mode"];
function detectPhpCgiRce(qs, difficulty) {
  // '+' represents a space in this exploit's real-world convention (php-cgi
  // reads the raw query string as CLI args; PoCs for this CVE conventionally
  // write spaces between flags as '+' in the URL).
  const lower = qs.replace(/\+/g, " ").toLowerCase();
  const hasFlag = /-d\s+\S+=/.test(lower);
  if (!hasFlag) return false;
  let denylist = [];
  if (difficulty === "medium") denylist = ["allow_url_include"];
  else if (difficulty === "hard") denylist = ["allow_url_include", "auto_prepend_file"];
  const mentionsDangerous = PHPCGI_DANGEROUS_DIRECTIVES.some((d) => lower.includes(d));
  const blockedByDenylist = denylist.some((d) => lower.includes(d));
  return mentionsDangerous && !blockedByDenylist;
}
router.get("/vuln/php-cgi-rce", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const rawQs = req.originalUrl.split("?")[1] || "";
  let output = "Invoice generated (simulated).", flag = null;
  if (rawQs && detectPhpCgiRce(decodeURIComponent(rawQs), difficulty)) {
    output = "[SIMULATED RCE PROOF] php-cgi interpreted query-string content as CLI flags — uid=1000(trainee) gid=1000(trainee)";
    flag = C.getFlag(session, "php-cgi-rce", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Invoice Generator (PHP-CGI)", difficulty,
    bodyHtml: `
      <h1>⚠️ SIMULATED PHP-CGI RCE (CVE-2012-1823)</h1>
      <p class="note">This legacy endpoint runs PHP via CGI, not as a proper module — a real, historically very widespread misconfiguration. Append PHP CLI flags directly to the query string.</p>
      <div class="result">${output}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 CGI query-string-as-CLI-flags bug confirmed.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "easy" ? `<p class="note">Try appending to the URL: <code>?-d+allow_url_include=1+-d+auto_prepend_file=php://input</code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">"allow_url_include" is now blocked. The real CVE has another well-documented flag combo that doesn't need it: <code>?-d+auto_prepend_file=php://input+-d+cgi.force_redirect=0</code></p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both flags above are blocked now. Try the disable_functions reset variant instead: <code>?-d+disable_functions=+-d+safe_mode=0</code></p>` : ""}
      <p class="note">Current query string: <code>${rawQs ? decodeURIComponent(rawQs) : "(none — append one to the URL and reload)"}</code></p>
    `
  }));
});

// ================================================ CROSS-SITE TRACING (XST) =
// A real HTTP TRACE handler (Express genuinely supports the TRACE verb).
// Browsers block script-initiated TRACE requests (a real, deliberate
// mitigation), so genuine exploitation needs a raw HTTP client — exactly
// how you'd really test this with curl -X TRACE or Burp Repeater. A
// same-page "simulate" button is offered too, clearly labeled as a
// convenience stand-in for that real workflow.
router.get("/vuln/xst", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  res.cookie("xst_authToken", "tok_" + C.randomHex(6), { httpOnly: true }); // HttpOnly — JS genuinely cannot read this
  const base = req.protocol + "://" + req.get("host");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Legacy Web Server", difficulty,
    bodyHtml: `
      <h1>Cross-Site Tracing (XST)</h1>
      <p class="note">An HttpOnly-protected <code>xst_authToken</code> cookie was just set — <code>document.cookie</code> genuinely can't read it. But TRACE requests echo back whatever headers (including cookies) arrived with them, and that echo is NOT subject to HttpOnly.</p>
      <p class="note">Real testing needs a raw HTTP client (browsers block script-initiated TRACE requests by design) — try: <code>curl -v -X TRACE ${base}/vuln/xst${difficulty === "hard" ? "" : ""}?difficulty=${difficulty} -b "xst_authToken=&lt;paste from your browser's DevTools&gt;"</code></p>
      <button onclick="simulate()">Simulate a raw TRACE request (convenience stand-in for curl)</button>
      <div class="result" id="out" style="display:none;"></div>
      ${difficulty === "medium" ? `<p class="note">TRACE is blocked only when the request looks like it came from a cross-site browser context — a check curl never triggers at all.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">TRACE is disabled on this exact path now — but a pre-migration path was left mounted: try the same request against <code>/vuln/xst/legacy</code>.</p>` : ""}
      <script>
        async function simulate(){
          const out = document.getElementById('out');
          out.style.display = 'block';
          const r = await fetch('/vuln/xst/simulate-trace?difficulty=${difficulty}', { credentials: 'include' });
          out.textContent = await r.text();
        }
      </script>
    `
  }));
});
function traceHandler(req, res, difficulty, session) {
  if (difficulty === "medium" && req.headers["sec-fetch-site"] && req.headers["sec-fetch-site"] !== "same-origin") {
    return res.status(403).send("Blocked — cross-site browser TRACE request.");
  }
  const cookie = req.headers.cookie || "";
  const flag = cookie.includes("xst_authToken") ? C.getFlag(session, "xst", difficulty) : null;
  res.send(`TRACE echo:\n${req.method} ${req.originalUrl} HTTP/1.1\nCookie: ${cookie}\n` + (flag ? `\n🚩 HttpOnly cookie recovered via TRACE echo.\nFLAG: ${flag}` : "\n(no cookie present on this request)"));
}
router.trace("/vuln/xst", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (difficulty === "hard") return res.status(404).send("TRACE disabled on this path — try /vuln/xst/legacy");
  traceHandler(req, res, difficulty, session);
});
router.trace("/vuln/xst/legacy", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  traceHandler(req, res, difficulty === "hard" ? "easy" : difficulty, session); // forgotten path — never got the fix
});
router.get("/vuln/xst/simulate-trace", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  // convenience GET stand-in mirroring the exact same decision logic, since
  // a real browser cannot script a TRACE request itself.
  const fakeReq = { headers: { cookie: req.headers.cookie, "sec-fetch-site": "same-origin" }, method: "TRACE", originalUrl: "/vuln/xst" };
  traceHandler(fakeReq, res, difficulty, session);
});

module.exports = { router };
