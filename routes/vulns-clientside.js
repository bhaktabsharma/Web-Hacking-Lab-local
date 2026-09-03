const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

// ============================================================= XSS =========
function sanitizeForXss(input, difficulty) {
  if (difficulty === "easy") return input;
  if (difficulty === "medium") return input.replace(/<script/gi, "");
  return input.replace(/<script/gi, "").replace(/onerror\s*=/gi, "").replace(/onload\s*=/gi, "");
}
router.get("/vuln/xss", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.redirect(`/vuln/xss/search?difficulty=${difficulty}`);
});
router.get("/vuln/xss/search", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const rawQuery = req.query.q || "";
  const rendered = rawQuery ? sanitizeForXss(rawQuery, difficulty) : "";
  const exploited = /<[a-z]/i.test(rendered);
  const flag = exploited ? C.getFlag(session, "xss", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Notes Search", difficulty,
    bodyHtml: `
      <h1>Search Notes</h1>
      <form method="GET" action="/vuln/xss/search">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <input type="text" name="q" placeholder="Search notes..." value="${rendered.replace(/"/g, "&quot;")}" />
        <button type="submit">Search</button>
      </form>
      <div class="result">Results for: ${rendered || "(nothing yet — try a query)"}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 A live tag survived the filter — your script would execute here.</strong>\nFLAG: ${flag}</div>` : ""}
      <p class="note">Session cookie is deliberately readable from JS for this lab (non-HttpOnly).</p>
    `
  }));
});

// ============================================================= CSRF ========
router.get("/vuln/csrf", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.redirect(`/vuln/csrf/account?difficulty=${difficulty}`);
});
router.get("/vuln/csrf/account", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (!session.canonicalId) session.canonicalId = C.USERS[Math.floor(Math.random() * C.USERS.length)].canonicalId;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Account", difficulty,
    bodyHtml: `
      <h1>Account Settings</h1>
      <p class="note">Logged in as user #${session.canonicalId}.</p>
      <div class="result" style="border-color:#f2b8b5;background:#fff5f5;">
        <strong>⚠ Danger Zone</strong><br/><br/>
        <a class="btn danger" href="/vuln/csrf/delete?difficulty=${difficulty}">Delete My Account</a>
      </div>
      <p class="note" style="margin-top:16px;">This deletes the account via a plain GET request — no confirmation, no CSRF token.</p>
      <p class="note"><a href="/vuln/csrf/poc?difficulty=${difficulty}" target="_blank">Open the simulated attacker page →</a></p>
    `
  }));
});
router.get("/vuln/csrf/delete", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { sid, session } = C.getOrInitSession(req, res);

  if (difficulty === "medium") {
    const origin = req.headers.origin;
    if (origin && !origin.includes(req.headers.host)) {
      return res.send(C.renderVulnPage({ appName: "SecureCorp Account", difficulty, bodyHtml: `<h1>Blocked</h1><p class="note">Cross-origin Origin header present.</p>` }));
    }
  }
  if (difficulty === "hard") {
    const mode = req.headers["sec-fetch-mode"];
    if (mode && mode !== "navigate") {
      return res.send(C.renderVulnPage({ appName: "SecureCorp Account", difficulty, bodyHtml: `<h1>Blocked</h1><p class="note">Request looks like a subresource load (img/fetch), not a top-level navigation. Try a real link click.</p>` }));
    }
  }
  session.canonicalId = null;
  const flag = C.getFlag(session, "csrf", difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Account", difficulty,
    bodyHtml: `<h1>💥 Account Deleted</h1><p class="note">This account was deleted via a forged GET request with no CSRF protection.</p><div class="result" style="border-color:#4ade80;"><strong>🚩 Exploit confirmed.</strong>\nFLAG: ${flag}</div>`
  }));
});
router.get("/vuln/csrf/poc", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8" /><title>You Won a Prize!</title>
  <style>body{background:#111;color:#eee;font-family:sans-serif;padding:2rem;}</style></head>
  <body>
    <h2>🎉 You won a free prize! 🎉</h2>
    <p style="color:#999;">(Simulated attacker-controlled page embedding the CSRF exploit.)</p>
    <img src="/vuln/csrf/delete?difficulty=${difficulty}" style="display:none" alt="" />
    <p><a href="/vuln/csrf/delete?difficulty=${difficulty}">Click here to claim it</a> (a real top-level link click — needed for hard mode)</p>
  </body></html>`);
});

// ===================================================== OPEN REDIRECT =======
router.get("/vuln/open-redirect", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const next = req.query.next;
  if (!next) {
    return res.send(C.renderVulnPage({
      appName: "SecureCorp SSO", difficulty,
      bodyHtml: `
        <h1>Continue to your destination</h1>
        <form method="GET">
          <input type="hidden" name="difficulty" value="${difficulty}" />
          <label>Continue to (next)</label>
          <input type="text" name="next" placeholder="/dashboard" />
          <button type="submit">Continue</button>
        </form>
        <p class="note">This mimics a real "log in, then continue to ?next=" SSO flow.</p>
      `
    }));
  }
  if (difficulty === "medium" && !next.startsWith("/")) {
    return res.send(C.renderVulnPage({ appName: "SecureCorp SSO", difficulty, bodyHtml: `<h1>Blocked</h1><p class="note">next must be a relative path starting with "/".</p>` }));
  }
  if (difficulty === "hard" && !next.includes("securecorp-demo.test")) {
    return res.send(C.renderVulnPage({ appName: "SecureCorp SSO", difficulty, bodyHtml: `<h1>Blocked</h1><p class="note">next must reference the securecorp-demo.test domain.</p>` }));
  }
  const offDomain = /^https?:\/\//i.test(next) || next.startsWith("//");
  const looksLikeRealAttackerTarget = offDomain && !/^https?:\/\/securecorp-demo\.test(\/|$|\?)/i.test(next.startsWith("//") ? "https:" + next : next);
  const flag = looksLikeRealAttackerTarget ? C.getFlag(session, "open-redirect", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp SSO", difficulty,
    bodyHtml: `<h1>Redirecting…</h1><p class="note">This app would now redirect you to:</p><div class="result">${next}</div><p class="note">(No real external navigation happens in this sandbox — but a real app would call res.redirect(next) here.)</p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Off-domain redirect confirmed.</strong>\nFLAG: ${flag}</div>` : ""}`
  }));
});

// ================================================ CLIENT-SIDE TEMPLATE INJ ==
router.get("/vuln/cstl", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const proofToken = C.issueClientProofToken(session, "cstl", difficulty);
  const examplePayload = { easy: "{{constructor.constructor('alert(1)')()}}", medium: "{{Function('alert(1)')()}}", hard: "{{globalThis['Func'+'tion']('alert(1)')()}}" }[difficulty];
  res.send(C.renderVulnPage({
    appName: "SecureCorp Comment Preview", difficulty,
    bodyHtml: `
      <h1>Live Comment Preview</h1>
      <p class="note">This preview evaluates {{ }} expressions client-side as you type (a real, sandboxed AngularJS-style template evaluator, running only in your own browser tab).</p>
      <label>Your comment</label>
      <textarea id="commentInput" oninput="renderPreview()">Nice product, {{7*7}}!</textarea>
      <div class="result" id="preview"></div>
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      ${difficulty === "medium" ? `<p class="note">The word "constructor" is now stripped before evaluation. Try a payload built around the global <code>Function</code> instead.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both "constructor" and "Function" are stripped as literal words. Try building "Function" at runtime via string concatenation so the literal word never appears in your payload.</p>` : ""}
      <script>
        const PROOF_TOKEN = ${JSON.stringify(proofToken)};
        const DIFFICULTY = ${JSON.stringify(difficulty)};
        let confirmed = false;
        function filterExpr(expr){
          if (DIFFICULTY === 'easy') return expr;
          if (DIFFICULTY === 'medium') return expr.replace(/constructor/gi, '');
          return expr.replace(/constructor/gi, '').replace(/\\bfunction\\b/gi, '');
        }
        function isExploited(rawExpr){
          const noConstructor = !/constructor/i.test(rawExpr);
          const noFunction = !/\\bfunction\\b/i.test(rawExpr);
          if (DIFFICULTY === 'easy') return /constructor/i.test(rawExpr);
          if (DIFFICULTY === 'medium') return noConstructor && /\\bfunction\\b/i.test(rawExpr);
          return noConstructor && noFunction && /globalthis/i.test(rawExpr);
        }
        async function revealFlag(){
          if (confirmed) return;
          confirmed = true;
          const r = await fetch('/api/confirm-client-exploit', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({labId:'cstl', difficulty:DIFFICULTY, token:PROOF_TOKEN}) });
          const d = await r.json();
          if (d.success) {
            document.getElementById('flagBox').style.display = 'block';
            document.getElementById('flagBox').innerHTML = '<strong>🚩 Exploit confirmed — real JS execution achieved.</strong>\\nFLAG: ' + d.flag;
          } else { confirmed = false; }
        }
        function evalExpr(rawExpr){
          const filtered = filterExpr(rawExpr);
          try {
            const result = String(Function('"use strict"; return (' + filtered + ')')());
            if (isExploited(rawExpr)) revealFlag();
            return result;
          } catch(e){ return '[error: ' + e.message + ']'; }
        }
        function renderPreview(){
          const raw = document.getElementById('commentInput').value;
          const rendered = raw.replace(/\\{\\{(.*?)\\}\\}/g, (m, expr) => evalExpr(expr));
          document.getElementById('preview').innerHTML = rendered;
        }
        renderPreview();
      </script>
      <p class="note">Try: <code>${examplePayload}</code></p>
    `
  }));
});

// ============================================================ POSTMESSAGE ==
router.get("/vuln/postmessage", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const proofToken = C.issueClientProofToken(session, "postmessage", difficulty);
  const st = C.labState(session, "postmessage", { token: C.randomHex(4) });
  const pageToken = st.token;
  const widgetMsg = difficulty === "easy"
    ? "parent.postMessage({balance:150.00},'*')"
    : difficulty === "medium"
    ? "parent.postMessage({balance:150.00, source:'legit-widget'},'*')"
    : `parent.postMessage({balance:150.00, source:'legit-widget', token:'${pageToken}'},'*')`;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Wallet", difficulty,
    bodyHtml: `
      <h1>Wallet Widget</h1>
      <p class="note">Balance: <strong id="bal">$120.00</strong></p>
      <p class="note">This page listens for postMessage updates from the widget iframe below <strong>without checking the sender's origin</strong>.</p>
      <iframe style="width:100%;height:80px;border:1px solid #e2e5e9;border-radius:8px;" srcdoc="<button onclick=&quot;${widgetMsg}&quot;>Simulate legit widget update (+$30)</button>"></iframe>
      <p class="note" style="margin-top:14px;"><a href="/vuln/postmessage/attacker?difficulty=${difficulty}" target="_blank">Open the simulated attacker page →</a> (lets you craft a forged message)</p>
      ${difficulty === "medium" ? `<p class="note">The listener now also checks for a <code>source</code> field. View-source the widget iframe above to see what value it expects.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The listener also checks a per-session <code>token</code> field. It's embedded in this page's source (view-source) as a hidden JS variable — not shown anywhere in the visible UI.</p><!-- PAGE_TOKEN (for view-source discovery): ${pageToken} -->` : ""}
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      <script>
        const PROOF_TOKEN = ${JSON.stringify(proofToken)};
        const PAGE_TOKEN = ${JSON.stringify(pageToken)};
        const DIFFICULTY = ${JSON.stringify(difficulty)};
        let confirmed = false;
        async function revealFlag(){
          if (confirmed) return;
          confirmed = true;
          const r = await fetch('/api/confirm-client-exploit', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({labId:'postmessage', difficulty:DIFFICULTY, token:PROOF_TOKEN}) });
          const d = await r.json();
          if (d.success) {
            document.getElementById('flagBox').style.display = 'block';
            document.getElementById('flagBox').innerHTML = '<strong>🚩 Forged balance accepted from an unverified origin.</strong>\\nFLAG: ' + d.flag;
          } else { confirmed = false; }
        }
        window.addEventListener('message', function(event){
          // vulnerable: no event.origin check, at any difficulty
          if (!event.data || typeof event.data.balance !== 'number') return;
          if (DIFFICULTY !== 'easy' && event.data.source !== 'legit-widget') return;
          if (DIFFICULTY === 'hard' && event.data.token !== PAGE_TOKEN) return;
          document.getElementById('bal').textContent = '$' + event.data.balance.toFixed(2);
          if (event.data.balance !== 120 && event.data.balance !== 150) revealFlag();
        });
      </script>
    `
  }));
});
router.get("/vuln/postmessage/attacker", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Attacker Page</title>
  <style>body{font-family:sans-serif;background:#111;color:#eee;padding:2rem;} input{padding:8px;margin:6px 0;width:280px;background:#222;border:1px solid #444;color:#eee;border-radius:4px;} label{display:block;font-size:.85rem;color:#aaa;margin-top:10px;} button{background:#f5a524;color:#1c1200;border:none;padding:10px 18px;border-radius:6px;font-weight:700;cursor:pointer;margin-top:14px;}</style></head><body>
    <h2>Attacker-controlled page</h2>
    <p>Open the Wallet Widget in another tab first (so this page's "opener" is set), then click the link back here, fill in the fields, and send.</p>
    <label>Forged balance</label><input type="text" id="balance" value="999999.99" />
    ${difficulty !== "easy" ? `<label>source field (find the expected value by viewing the wallet page's iframe source)</label><input type="text" id="source" placeholder="?" />` : ""}
    ${difficulty === "hard" ? `<label>token field (find it by viewing the wallet page's source)</label><input type="text" id="token" placeholder="?" />` : ""}
    <br/><button onclick="send()">Post forged message to opener</button>
    <p id="status" style="color:#4ade80;"></p>
    <script>
      function send(){
        if (!window.opener) { document.getElementById('status').textContent = 'Open this page BY CLICKING the link from the Wallet tab (so window.opener is set), not by typing the URL directly.'; return; }
        const msg = { balance: parseFloat(document.getElementById('balance').value) };
        const sourceEl = document.getElementById('source');
        if (sourceEl) msg.source = sourceEl.value;
        const tokenEl = document.getElementById('token');
        if (tokenEl) msg.token = tokenEl.value;
        window.opener.postMessage(msg, '*');
        document.getElementById('status').textContent = 'Message sent to opener window.';
      }
    </script>
  </body></html>`);
});

// ===================================================== PROTOTYPE POLLUTION =
router.get("/vuln/prototype-pollution", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const proofToken = C.issueClientProofToken(session, "prototype-pollution", difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Theme Customizer", difficulty,
    bodyHtml: `
      <h1>Theme Customizer</h1>
      <p class="note">This page merges URL query parameters into a settings object client-side (a common real-world "extend/merge" bug), then checks <code>settings.isAdmin</code> to decide whether to show the Admin Panel link.</p>
      <div id="adminLink" style="display:none;"><a class="btn" href="#">⚙ Admin Panel (unlocked)</a></div>
      <div class="result" id="settingsOut"></div>
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      ${difficulty === "easy" ? `<p class="note">Try visiting this page with <code>?__proto__[isAdmin]=true</code> appended to the URL.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The direct <code>__proto__</code> key is now blocked by a denylist. Try going through <code>constructor[prototype]</code> instead — it reaches the same shared prototype.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The denylist now blocks <code>__proto__</code>, <code>constructor</code>, AND <code>prototype</code> as keys at any level. This is actually a complete, correct fix for this class of bug — there's no bypass here. (Confirm that for yourself, and note it in your report.)</p>` : ""}
      <script>
        const PROOF_TOKEN = ${JSON.stringify(proofToken)};
        const DIFFICULTY = ${JSON.stringify(difficulty)};
        const DENYLIST = DIFFICULTY === 'easy' ? [] : DIFFICULTY === 'medium' ? ['__proto__'] : ['__proto__','constructor','prototype'];
        async function revealFlag(){
          const r = await fetch('/api/confirm-client-exploit', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({labId:'prototype-pollution', difficulty:DIFFICULTY, token:PROOF_TOKEN}) });
          const d = await r.json();
          if (d.success) {
            document.getElementById('flagBox').style.display = 'block';
            document.getElementById('flagBox').innerHTML = '<strong>🚩 Object.prototype polluted — admin check bypassed.</strong>\\nFLAG: ' + d.flag;
          }
        }
        function merge(target, src){
          for (const key in src){
            if (DENYLIST.includes(key)) continue;
            if (typeof src[key] === 'object' && src[key] !== null) { target[key] = target[key] || {}; merge(target[key], src[key]); }
            else target[key] = src[key];
          }
          return target;
        }
        function parseQueryToObject(qs){
          // Built with null-prototype objects so "__proto__" is just a normal
          // key while parsing — the ONLY place pollution can occur is inside
          // merge() below, exactly where the denylist check lives.
          const obj = Object.create(null);
          new URLSearchParams(qs).forEach((value, key) => {
            const parts = key.replace(/\\]/g,'').split('[');
            let cur = obj;
            for (let i=0;i<parts.length-1;i++){
              if (!cur[parts[i]] || typeof cur[parts[i]] !== 'object') cur[parts[i]] = Object.create(null);
              cur = cur[parts[i]];
            }
            cur[parts[parts.length-1]] = value;
          });
          return obj;
        }
        const settings = {};
        merge(settings, parseQueryToObject(location.search));
        document.getElementById('settingsOut').textContent = 'Merged settings: ' + JSON.stringify(settings) + ' | denylist active: [' + DENYLIST.join(', ') + ']';
        if (({}).isAdmin || settings.isAdmin) {
          document.getElementById('adminLink').style.display = 'block';
          revealFlag();
        }
      </script>
    `
  }));
});


// ============================================================================
// Consolidated from vulns-clientside-new.js during the Phase 1 architecture cleanup —
// same labs, same behavior, just no longer a separate "-new" module.
// ============================================================================
// ========================================================= DOM-BASED XSS ===
// The defining trait: the payload NEVER touches the server. Source and sink
// are both purely client-side JS. Flags are still real & server-issued
// (embedded at page-load, same established pattern as the existing
// prototype-pollution/postmessage labs) — but the exploit itself runs
// entirely in the browser.
router.get("/vuln/dom-xss", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const proofToken = C.issueClientProofToken(session, "dom-xss", difficulty);

  let sourceNote, script;
  if (difficulty === "easy") {
    sourceNote = "Source: <code>location.hash</code>. Sink: <code>innerHTML</code>. No filtering at all.";
    script = `
      function render(){
        const name = decodeURIComponent(location.hash.slice(1)) || 'guest';
        document.getElementById('greeting').innerHTML = 'Welcome back, ' + name + '!';
        checkExploited();
      }
      window.addEventListener('hashchange', render);
      render();
    `;
  } else if (difficulty === "medium") {
    sourceNote = "Source: <code>location.search</code> (the <code>?name=</code> param). Sink: <code>innerHTML</code>. The literal substring <code>&lt;script</code> is stripped client-side before insertion.";
    script = `
      function render(){
        let name = new URLSearchParams(location.search).get('name') || 'guest';
        name = name.replace(/<script/gi, '');
        document.getElementById('greeting').innerHTML = 'Welcome back, ' + name + '!';
        checkExploited();
      }
      render();
    `;
  } else {
    sourceNote = "Source: <code>simReferrer</code> query param (standing in for <code>document.referrer</code> from a link on another page). Sink: <code>document.write()</code>. <code>&lt;script</code>, <code>onerror=</code> and <code>onload=</code> are all stripped.";
    script = `
      function render(){
        let ref = new URLSearchParams(location.search).get('simReferrer') || '(direct visit, no referrer)';
        ref = ref.replace(/<script/gi, '').replace(/onerror\\s*=/gi, '').replace(/onload\\s*=/gi, '');
        document.open(); document.write('<p>Referred from: ' + ref + '</p>'); document.close();
        checkExploited();
      }
      render();
    `;
  }

  res.send(C.renderVulnPage({
    appName: "SecureCorp Welcome Widget", difficulty,
    bodyHtml: `
      <h1>Welcome Widget</h1>
      <p class="note">${sourceNote}</p>
      <p class="note" style="color:#a15c00;">This entire exploit runs in YOUR browser — nothing here is ever sent to the server. Editing the URL and reloading is the whole attack.</p>
      <div id="greeting" class="result">Welcome back, guest!</div>
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      ${difficulty === "easy" ? `<p class="note">Try appending to the URL: <code>#<img src=x onerror=alert(1)></code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">Try: <code>?name=<img src=x onerror=alert(1)></code> — <code>&lt;script</code> is blocked, but this doesn't need it.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Try: <code>?simReferrer=<svg onbegin=alert(1)></code> or an <code>autofocus</code>+<code>onfocus</code> payload — <code>onerror</code>/<code>onload</code> are both blocked.</p>` : ""}
      <script>
        const PROOF_TOKEN = ${JSON.stringify(proofToken)};
        const DOM_XSS_DIFFICULTY = ${JSON.stringify(difficulty)};
        let domXssConfirmed = false;
        async function revealDomXssFlag(){
          if (domXssConfirmed) return;
          domXssConfirmed = true;
          const r = await fetch('/api/confirm-client-exploit', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({labId:'dom-xss', difficulty:DOM_XSS_DIFFICULTY, token:PROOF_TOKEN}) });
          const d = await r.json();
          if (d.success) {
            const box = document.getElementById('flagBox');
            if (box) { box.style.display = 'block'; box.innerHTML = '<strong>🚩 DOM XSS confirmed — payload never touched the server.</strong>\\nFLAG: ' + d.flag; }
          } else { domXssConfirmed = false; }
        }
        function checkExploited(){
          const marker = document.createElement('div');
          marker.id = '__domxss_probe';
          document.body.appendChild(marker);
          // A live injected element proves the sink actually rendered markup
          // (not merely text) — check for any element the app itself never creates.
          const injected = document.querySelectorAll('#greeting img, #greeting svg, #greeting a, #greeting *:not(#greeting)').length > 0
            || /<[a-z]/i.test(document.getElementById('greeting') ? document.getElementById('greeting').innerHTML.replace('Welcome back, guest!','') : '')
            || document.body.innerHTML.includes('Referred from:') && /<(img|svg|a)/i.test(document.body.innerHTML);
          if (injected) revealDomXssFlag();
        }
      </script>
    `
  }));
});

// =================================================== XSS VIA HTTP HEADERS ==
// Distinct input surface from the existing xss lab (query param): here the
// vector is request HEADERS reflected into an admin log viewer. Since
// browsers won't let a normal page set arbitrary outgoing User-Agent/Referer
// values, these are modeled as explicit "simulated incoming header" fields
// — exactly the same established pattern this app already uses for
// host-header-injection. (In real testing you'd set these via Burp/curl.)
router.get("/vuln/header-xss", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "header-xss", { log: [] });
  const ua = req.query.ua, ref = req.query.referer;
  if (ua !== undefined || ref !== undefined) {
    st.log.unshift({ ua: ua || "(none)", ref: ref || "(none)", ts: new Date().toISOString().slice(11, 19) });
    st.log = st.log.slice(0, 5);
  }
  function sanitize(v, allow) { return allow ? v : v.replace(/<script/gi, "").replace(/onerror\s*=/gi, "").replace(/onload\s*=/gi, ""); }
  const rows = st.log.map((entry) => {
    let uaOut = entry.ua, refOut = entry.ref;
    if (difficulty === "easy") { /* both unescaped */ }
    else if (difficulty === "medium") { uaOut = sanitize(uaOut, false); /* referer left unescaped */ }
    else { uaOut = sanitize(uaOut, false); refOut = sanitize(refOut, false); }
    return { uaOut, refOut, ts: entry.ts };
  });
  // "exploited" means a genuinely live event-handler or <script> survived —
  // not merely that some tag-like fragment is present (a partially-stripped
  // payload, e.g. onerror= removed from an <img>, is inert, not a real find).
  const looksLive = (s) => /<script/i.test(s) || /on\w+\s*=/i.test(s);
  const exploited = rows.some((r) => looksLive(r.uaOut) || looksLive(r.refOut));
  const flag = exploited ? C.getFlag(session, "header-xss", difficulty) : null;
  const tableRows = rows.map((r) => `<tr><td>${r.ts}</td><td>${r.uaOut}</td><td>${r.refOut}</td></tr>`).join("");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Admin — Visitor Log", difficulty,
    bodyHtml: `
      <h1>Recent Visitor Log (admin view)</h1>
      <p class="note">This simulates real incoming request headers as form fields — in a real test you'd set these with Burp Repeater or <code>curl -A</code> / <code>-H "Referer: ..."</code>.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Simulated User-Agent header</label><input type="text" name="ua" placeholder="Mozilla/5.0..." />
        <label>Simulated Referer header</label><input type="text" name="referer" placeholder="https://google.com" />
        <button type="submit">Submit request (adds a log row)</button>
      </form>
      <table><tr><th>Time</th><th>User-Agent</th><th>Referer</th></tr>${tableRows || '<tr><td colspan="3">No visits logged yet.</td></tr>'}</table>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 A header value rendered as live markup in the admin log.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "easy" ? `<p class="note">Try User-Agent: <code>&lt;img src=x onerror=alert(document.cookie)&gt;</code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">User-Agent now strips &lt;script — Referer doesn't. Try it there instead.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both fields strip &lt;script, onerror=, onload=. Try: <code>&lt;svg onbegin=alert(1)&gt;</code></p>` : ""}
    `
  }));
});

// ============================================================ CLICKJACKING
// Real response headers per tier (verifiable with curl -I), plus a visual
// overlay PoC (same-origin so it always visually renders — that's expected
// and is explicitly framed as the PoC step, not the security decision).
function clickjackHeaders(res, difficulty) {
  if (difficulty === "easy") { /* nothing set */ }
  else if (difficulty === "medium") { res.setHeader("X-Frame-Options", "ALLOW-FROM https://trusted-partner.securecorp-demo.test"); }
  else { res.setHeader("X-Frame-Options", "SAMEORIGIN"); res.setHeader("Content-Security-Policy", "frame-ancestors 'self'"); }
}
router.get("/vuln/clickjacking", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  clickjackHeaders(res, difficulty);
  // easy + medium (ALLOW-FROM is deprecated & ignored by every modern
  // browser) are genuinely still exploitable; hard's SAMEORIGIN + real
  // frame-ancestors CSP is a genuine, correct fix — honestly not
  // exploitable via this vector, same "honest hard tier" precedent as the
  // existing prototype-pollution lab.
  const flag = difficulty !== "hard" ? C.getFlag(session, "clickjacking", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Wire Transfer Approval", difficulty,
    bodyHtml: `
      <h1>Approve Pending Wire Transfer</h1>
      <p class="note">Transfer #4471 — $12,000.00 to an external account.</p>
      <button class="btn danger" id="approveBtn" onclick="document.getElementById('confirmed').style.display='block'">Approve Transfer</button>
      <div id="confirmed" class="result" style="display:none;border-color:#4ade80;">✅ Transfer approved.${flag ? `\n\n🚩 This page can be framed by any origin at this difficulty (check the response headers with curl -I).\nFLAG: ${flag}` : ""}</div>
      <p style="margin-top:16px;"><a href="/vuln/clickjacking/poc?difficulty=${difficulty}" target="_blank">Open the simulated attacker overlay page →</a></p>
      ${difficulty === "easy" ? `<p class="note">No X-Frame-Options / CSP frame-ancestors is set at all.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">X-Frame-Options: ALLOW-FROM is set — but this directive was deprecated years ago and every modern browser (Chrome, Firefox, Edge, Safari) ignores it entirely, so it provides zero real protection.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">X-Frame-Options: SAMEORIGIN + Content-Security-Policy: frame-ancestors 'self' — this is a real, correct, modern fix. Confirm it for yourself and note it in your report.</p>` : ""}
    `
  }));
});
router.get("/vuln/clickjacking/poc", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"/><title>You Won a Prize!</title>
  <style>
    body{background:#111;color:#eee;font-family:sans-serif;padding:2rem;}
    .stage{position:relative;width:520px;}
    .decoy{position:relative;z-index:1;background:linear-gradient(135deg,#7c3aed,#ec4899);color:#fff;padding:60px 20px;text-align:center;border-radius:12px;font-size:1.4rem;font-weight:800;}
    iframe{position:absolute;top:0;left:0;width:520px;height:400px;opacity:0.15;z-index:2;border:2px dashed #f5a524;}
  </style></head>
  <body>
    <h2>🎉 Simulated attacker overlay</h2>
    <p style="color:#999;">The real target page is framed underneath (opacity lowered so you can see the trick — a real attack would use opacity:0). Your click on the "Claim Prize" decoy actually lands on the real Approve button beneath it.</p>
    <div class="stage">
      <div class="decoy">🎁 Click here to claim your prize! 🎁</div>
      <iframe src="/vuln/clickjacking?difficulty=${difficulty}"></iframe>
    </div>
  </body></html>`);
});

// ============================================ CLIENT-SIDE VALIDATION BYPASS
router.get("/vuln/client-side-validation-bypass", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Employee Discount Request", difficulty,
    bodyHtml: `
      <h1>Request an Employee Discount</h1>
      <p class="note">The form below enforces a max of 15% client-side (HTML <code>max</code> attribute + a JS check before submit). That's the ONLY place it's enforced at this difficulty — inspect what the API actually accepts directly.</p>
      <label>Discount % (max 15, enforced in this box only)</label>
      <input type="number" id="pct" value="15" max="15" min="0" />
      <button onclick="submitForm()">Submit Request</button>
      <div class="result" id="out" style="display:none;"></div>
      <script>
        function submitForm(){
          const pct = Number(document.getElementById('pct').value);
          if (pct > 15) { alert('Blocked client-side: max is 15%.'); return; }
          send(pct);
        }
        async function send(pct){
          const r = await fetch('/vuln/client-side-validation-bypass/apply?difficulty=${difficulty}', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({discountPct: pct}) });
          const d = await r.json();
          const out = document.getElementById('out'); out.style.display='block'; out.textContent = JSON.stringify(d, null, 2);
        }
      </script>
      <p class="note" style="margin-top:14px;">Bypass the UI entirely — send the request directly. Try:</p>
      <div class="result">fetch('/vuln/client-side-validation-bypass/apply?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({discountPct: ${difficulty === "easy" ? 100 : difficulty === "medium" ? 90 : 14.9}})})</div>
      ${difficulty === "hard" ? `<p class="note">The top-level discountPct is now correctly capped at 15 server-side. But there's also a bulk request path for multiple items — try: <code>{"bulkItems":[{"item":"A","discountPct":90}]}</code></p>` : ""}
    `
  }));
});
router.post("/vuln/client-side-validation-bypass/apply", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const body = req.body || {};
  let effectivePct = 0, flag;
  if (difficulty === "easy") {
    effectivePct = Number(body.discountPct) || 0; // zero validation at all
  } else if (difficulty === "medium") {
    let n = Number(body.discountPct);
    if (Number.isNaN(n)) n = 0;
    effectivePct = Math.max(0, Math.min(100, n)); // type/range checked, business rule (<=15) never enforced
  } else {
    let n = Number(body.discountPct);
    effectivePct = Math.max(0, Math.min(15, Number.isNaN(n) ? 0 : n)); // top-level correctly capped at 15
    if (Array.isArray(body.bulkItems)) {
      // nested array items forgot the same 15% cap entirely
      effectivePct = Math.max(effectivePct, ...body.bulkItems.map((it) => Number(it && it.discountPct) || 0));
    }
  }
  if (effectivePct > 15) flag = C.getFlag(session, "client-side-validation-bypass", difficulty);
  res.json({ appliedDiscountPct: effectivePct, flag, note: effectivePct > 15 ? "Business rule (max 15%) was never enforced server-side for this request shape." : "Within policy." });
});

// ============================================================================
// PHASE 3 ADDITION (upgrade-spec Section 27: "CSP training", "CSP
// weaknesses"). Genuinely new lab, not a variant of an existing one — the
// only pre-existing CSP touchpoint in this codebase was the clickjacking
// lab's `frame-ancestors` directive, which is about framing, not script
// execution. This teaches three distinct real-world CSP MISCONFIGURATIONS
// that each defeat script-src in a different, well-documented way:
//   easy   — 'unsafe-inline' present (the #1 real-world CSP mistake: teams
//            add a CSP but leave unsafe-inline so they don't have to
//            refactor existing inline scripts, which defeats the entire
//            point of having one)
//   medium — 'unsafe-eval' present, reached through a realistic
//            "internal formula preview" tool that naively eval()s user
//            input
//   hard   — a nonce-based CSP that LOOKS correctly configured, except the
//            nonce is a static value that never rotates per-request (a
//            real, well-known anti-pattern: nonces must be unique and
//            unpredictable per response, or they provide zero protection)
//
// All three tiers set a REAL Content-Security-Policy response header
// (verifiable with curl -I) and contain a genuinely reflected sink, so
// this is testable with an actual browser/Burp exactly the way the spec's
// Section 38 asks for — nothing here is a "click this button to exploit"
// shortcut.
// ============================================================================
const STATIC_NONCE = "b7e21af9"; // the bug at hard tier: this is never regenerated per-request

function cspBypassHeaders(res, difficulty) {
  if (difficulty === "easy") {
    res.setHeader("Content-Security-Policy", "script-src 'self' 'unsafe-inline'; object-src 'none'");
  } else if (difficulty === "medium") {
    res.setHeader("Content-Security-Policy", "script-src 'self' 'unsafe-eval'; object-src 'none'");
  } else {
    res.setHeader("Content-Security-Policy", `script-src 'self' 'nonce-${STATIC_NONCE}'; object-src 'none'`);
  }
}

router.get("/vuln/csp-bypass", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const proofToken = C.issueClientProofToken(session, "csp-bypass", difficulty);
  cspBypassHeaders(res, difficulty);

  const note = typeof req.query.note === "string" ? req.query.note : "All systems operational.";
  const appScriptNonceAttr = difficulty === "hard" ? ` nonce="${STATIC_NONCE}"` : "";

  let hint;
  if (difficulty === "easy") {
    hint = `Try posting a status update with <code>?note=&lt;script&gt;window.__cspBypassConfirmed()&lt;/script&gt;</code> — the policy still allows 'unsafe-inline'.`;
  } else if (difficulty === "medium") {
    hint = `The note field no longer executes injected scripts — 'unsafe-inline' is gone. But the Formula Preview below still uses <code>eval()</code>, and the policy still allows 'unsafe-eval'. Try typing <code>window.__cspBypassConfirmed()</code> as the "formula".`;
  } else {
    hint = `This policy uses a per-script nonce instead of 'unsafe-inline' — view-source and notice the legitimate app script's <code>nonce</code> attribute never changes between reloads. Reuse that exact value on your own injected tag: <code>?note=&lt;script nonce="${STATIC_NONCE}"&gt;window.__cspBypassConfirmed()&lt;/script&gt;</code>`;
  }

  res.send(C.renderVulnPage({
    appName: "SecureCorp Status Page", difficulty,
    bodyHtml: `
      <h1>Status Page</h1>
      <p class="note">Current status, reflected from the query string (a real, server-rendered reflection point — try viewing the page source).</p>
      <div class="result">${note}</div>
      <p class="note">Response header set on this page: <code>Content-Security-Policy</code> (check with <code>curl -I</code>).</p>
      ${difficulty === "medium" ? `
      <label style="margin-top:16px;">Formula Preview (internal tool — evaluates expressions client-side)</label>
      <input type="text" id="formulaInput" placeholder="e.g. 2 * (3 + 4)" />
      <div class="result" id="formulaResult"></div>` : ""}
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      <p class="note">${hint}</p>
      <script src="/js/csp-bypass-app.js"${appScriptNonceAttr} data-token="${proofToken}" data-difficulty="${difficulty}"></script>
    `
  }));
});

module.exports = { router, sanitizeForXss };
