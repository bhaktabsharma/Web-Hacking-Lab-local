const express = require("express");
const router = express.Router();
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const C = require("./vuln-common");

// =============================================================== SSRF ======
function toIp(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."); }
function hostOf(url) { const m = url.match(/^https?:\/\/([^\/]+)/i); return m ? m[1].split(":")[0] : url; }
function isKnownInternalLiteral(s) { return /169\.254\.169\.254|127\.0\.0\.1|\blocalhost\b|internal-api\.local/i.test(s); }
function numericHostToInternalIp(hostToken) {
  if (/^\d+$/.test(hostToken)) { const ip = toIp(parseInt(hostToken, 10)); if (ip === "127.0.0.1" || ip === "169.254.169.254") return ip; }
  if (/^0x[0-9a-f]+$/i.test(hostToken)) { const ip = toIp(parseInt(hostToken, 16)); if (ip === "127.0.0.1" || ip === "169.254.169.254") return ip; }
  return null;
}
function lookupFakeService(effectiveUrl) {
  const lower = effectiveUrl.toLowerCase();
  const key = Object.keys(C.FAKE_INTERNAL_SERVICES).find((k) => lower.includes(k.split("/")[0]));
  return key ? C.FAKE_INTERNAL_SERVICES[key] : null;
}
// Expert tier's distinct gap (upgrade-spec Section 15: "partial
// mitigations" — the filter is genuinely more thorough than hard tier's,
// it just has a different blind spot). isKnownInternalLiteral and
// numericHostToInternalIp above only ever look for IPv4-style patterns —
// bracketed IPv6 loopback / IPv4-mapped-IPv6 representations of the exact
// same internal targets are a real, historically common thing SSRF
// filters have missed entirely (upgrade-spec Section 24's own "alternate
// address representations" example).
function ipv6InternalTarget(url) {
  const lower = url.toLowerCase();
  if (/\[::1\]|\[0:0:0:0:0:0:0:1\]|\[::ffff:127\.0\.0\.1\]/.test(lower)) return "127.0.0.1";
  if (/\[::ffff:a9fe:a9fe\]|\[::ffff:169\.254\.169\.254\]/.test(lower)) return "169.254.169.254";
  return null;
}
router.get("/vuln/ssrf", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const url = req.query.url;
  let output = "", flag = null;
  if (url !== undefined) {
    let effectiveUrl = url;
    let blocked = false;

    if (difficulty !== "easy" && isKnownInternalLiteral(url)) blocked = true;

    if (difficulty === "medium" || difficulty === "hard") {
      // Numeric/hex IPv4 obfuscation is the INTENDED bypass starting at
      // medium, and stays open at hard — expert is the tier that finally
      // closes it (see below), so this block deliberately excludes expert.
      const numericIp = numericHostToInternalIp(hostOf(url));
      if (numericIp) { blocked = false; effectiveUrl = url.replace(hostOf(url), numericIp); }
    }

    if (difficulty === "hard") {
      const redirMatch = url.match(/safe-redirector\.securecorp-demo\.test\/go\?to=([^&]+)/i);
      if (redirMatch) {
        const target = decodeURIComponent(redirMatch[1]);
        effectiveUrl = target;
        blocked = false;
      }
    }

    if (difficulty === "expert") {
      // Expert closes BOTH of hard tier's holes — numeric/hex IPv4
      // obfuscation (excluded from the medium/hard block above) and the
      // open redirector are both explicitly blocked here — but leaves a
      // genuinely different gap open: bracketed IPv6 representations of
      // the same internal targets.
      if (numericHostToInternalIp(hostOf(url))) blocked = true;
      if (/safe-redirector\.securecorp-demo\.test\/go\?to=/i.test(url)) blocked = true;

      const ipv6Target = ipv6InternalTarget(url);
      if (ipv6Target) {
        blocked = false;
        effectiveUrl = url.replace(hostOf(url), ipv6Target);
      }
    }

    if (blocked) {
      output = `Request to ${url} was blocked — that host looked internal.`;
    } else {
      const fake = lookupFakeService(effectiveUrl);
      if (fake) {
        output = `Response from ${effectiveUrl}:\n${fake}`;
        flag = C.getFlag(session, "ssrf", difficulty);
      } else {
        output = `No internal service responded at that address. (This sandbox never makes real outbound requests — try 169.254.169.254, 127.0.0.1, localhost:6379, or internal-api.local.)`;
      }
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Health Check Tool", difficulty,
    bodyHtml: `
      <h1>Internal Health Check</h1>
      <p class="note">Paste a URL and we'll (simulate) checking it. No real outbound requests are ever made by this sandbox.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>URL</label><input type="text" name="url" value="${(url || "").replace(/"/g, "&quot;")}" placeholder="http://169.254.169.254/latest/meta-data/iam/security-credentials/admin" />
        <button type="submit">Check</button>
      </form>
      ${output ? `<div class="result">${output}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Internal service reached via SSRF.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "expert" ? `<p class="note">This filter blocks known internal hostnames, numeric/hex IP obfuscation, and the open redirector — all three hard-tier techniques are closed here. Try an address family the filter never checks at all.</p>` : ""}
    `
  }));
});

// ======================================================== FILE UPLOAD ======
const UPLOAD_DIR = path.join(__dirname, "..", "uploads_sandbox");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 2 * 1024 * 1024 } });

router.get("/vuln/file-upload", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Profile Picture Upload", difficulty,
    extraHead: `<meta charset="utf-8" />`,
    bodyHtml: `
      <h1>Upload Profile Picture</h1>
      <p class="note">Files are saved to a private sandbox folder on your own machine (never web-served or executed) — this teaches the validation-bypass technique with zero real risk.</p>
      <form method="POST" action="/vuln/file-upload?difficulty=${difficulty}" enctype="multipart/form-data">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>File</label><input type="file" name="file" />
        <button type="submit">Upload</button>
      </form>
    `
  }));
});
router.post("/vuln/file-upload", upload.single("file"), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const file = req.file;
  let message, flag = null;
  if (!file) {
    message = "No file received.";
  } else {
    const name = file.originalname || "";
    let blocked = false, reason = "";
    if (difficulty === "medium" && /\.php$/.test(name)) { blocked = true; reason = 'Blocked: ".php" extension not allowed.'; }
    if (difficulty === "hard" && /\.(php|phtml|php5|asp|jsp)$/i.test(name)) { blocked = true; reason = "Blocked: executable-looking extension not allowed."; }
    try { fs.unlinkSync(file.path); } catch (e) { /* ignore */ }
    if (blocked) {
      message = reason;
    } else {
      message = `✅ Accepted "${name}" (${file.mimetype}, ${file.size} bytes). In a real (misconfigured) deployment, this would be stored at a web-accessible path and, with an executable extension, would run as server-side code.`;
      flag = C.getFlag(session, "file-upload", difficulty);
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Profile Picture Upload", difficulty,
    bodyHtml: `<h1>Upload Result</h1><div class="result">${message}</div>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Upload validation bypassed.</strong>\nFLAG: ${flag}</div>` : ""}<p style="margin-top:16px;"><a class="btn secondary" href="/vuln/file-upload?difficulty=${difficulty}">← Try another file</a></p>`
  }));
});

// ============================================ PATH TRAVERSAL & LFI (shared) =
function traverse(baseParts, userInput, difficulty) {
  let p = userInput || "";
  if (difficulty === "medium") {
    p = p.split("../").join("");
  } else if (difficulty === "hard") {
    let prev;
    do { prev = p; p = p.split("../").join(""); } while (p !== prev);
    try { p = decodeURIComponent(p); } catch (e) { /* ignore */ }
  }
  const stack = baseParts.slice();
  for (const seg of p.split("/")) {
    if (seg === "..") stack.pop();
    else if (seg === "" || seg === ".") continue;
    else stack.push(seg);
  }
  return "/" + stack.join("/");
}

router.get("/vuln/path-traversal", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const file = req.query.file;
  let output = "", flag = null;
  if (file !== undefined) {
    const resolved = traverse(["app", "documents"], file, difficulty);
    const escaped = resolved.indexOf("/app/documents") !== 0;
    const content = C.VFS[resolved];
    output = `Resolved path: ${resolved}\n\n` + (content || "[not found in sandbox]");
    if (escaped && content) flag = C.getFlag(session, "path-traversal", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Document Viewer", difficulty,
    bodyHtml: `
      <h1>View a Document</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>File</label><input type="text" name="file" value="${(file || "").replace(/"/g, "&quot;")}" placeholder="report1.txt" />
        <button type="submit">View</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Escaped the documents directory.</strong>\nFLAG: ${flag}</div>` : ""}
    `
  }));
});

router.get("/vuln/lfi", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const lang = req.query.lang;
  let output = "", flag = null;
  if (lang !== undefined) {
    const resolved = traverse(["app", "templates"], lang, difficulty);
    const withExt = C.VFS[resolved] ? resolved : resolved + ".txt";
    const content = C.VFS[withExt] || C.VFS[resolved];
    const escaped = resolved.indexOf("/app/templates") !== 0;
    output = `Included: ${withExt}\n\n` + (content || "[not found in sandbox]");
    if (escaped && content) flag = C.getFlag(session, "lfi", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Multilingual Loader", difficulty,
    bodyHtml: `
      <h1>Choose a Language</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Language (lang) — try en, fr, es, or a traversal payload</label>
        <input type="text" name="lang" value="${(lang || "").replace(/"/g, "&quot;")}" placeholder="en" />
        <button type="submit">Load</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Escaped the templates directory.</strong>\nFLAG: ${flag}</div>` : ""}
      <p class="note">Try: <code>../../../etc/passwd</code></p>
    `
  }));
});

// ===================================================== CACHE POISONING =====
const POISON_CACHE = new Map();
const POISON_PARAM = { easy: "utm_source", medium: "ref", hard: "lang" };
router.get("/vuln/cache-poisoning", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const vulnParam = POISON_PARAM[difficulty];
  // Cache key includes every OTHER known tracking param (simulating "we fixed the last bug we found")
  // but always omits this tier's specific unkeyed param.
  const otherParams = Object.values(POISON_PARAM).filter((p) => p !== vulnParam);
  const keyParts = otherParams.map((p) => `${p}=${req.query[p] || ""}`).join("&");
  const cacheKey = req.path + "?" + keyParts;
  const now = Date.now();
  const cached = POISON_CACHE.get(cacheKey);
  if (cached && now - cached.time < 30000) {
    return res.send(cached.html + (difficulty === "easy" ? "\n<!-- served from shared cache -->" : ""));
  }
  const source = req.query[vulnParam] || "direct";
  const flag = source !== "direct" ? C.getFlag(session, "cache-poisoning", difficulty) : null;
  const html = C.renderVulnPage({
    appName: "SecureCorp Homepage", difficulty,
    bodyHtml: `<h1>Welcome!</h1><p class="note">Thanks for visiting from: <strong>${source}</strong> (via the "${vulnParam}" parameter)</p><p class="note">This whole page is cached for 30 seconds for every visitor. The cache key includes every OTHER known tracking parameter, but not "${vulnParam}".</p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 This flag was baked into a cached response — reload this exact URL with NO query string within 30s and it'll still appear.</strong>\nFLAG: ${flag}</div>` : ""}`
  });
  POISON_CACHE.set(cacheKey, { html, time: now });
  res.send(html);
});

// ===================================================== CACHE DECEPTION =====
const DECEPTION_CACHE = new Map();
router.get(/^\/vuln\/cache-deception\/account(\/.*)?$/, (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const fullPath = req.path;
  const fullUrl = req.originalUrl;

  if (difficulty !== "easy" && fullPath !== "/vuln/cache-deception/account") {
    return res.status(404).send("Not found. (The trailing-path-segment trick from easier tiers is fixed here.)");
  }

  let cacheable, cacheKey;
  if (difficulty === "easy") {
    cacheable = /\.(js|css|jpg|png|json|ico)$/i.test(fullPath);
    cacheKey = fullPath;
  } else if (difficulty === "medium") {
    cacheable = /\.(js|css|jpg|png|json|ico)/i.test(fullUrl); // naive: matches anywhere in the full URL, including query
    cacheKey = fullUrl;
  } else {
    cacheable = /=[^&]*\.(js|css|jpg|png|json|ico)/i.test(fullUrl); // only matches a query VALUE specifically
    cacheKey = fullUrl;
  }

  if (cacheable) {
    const cached = DECEPTION_CACHE.get(cacheKey);
    if (cached) return res.send(cached);
  }
  const apiKey = "sk_live_FAKE_" + (session.canonicalId || Math.floor(Math.random() * 9000 + 1000)) + "_demo";
  const flag = cacheable ? C.getFlag(session, "cache-deception", difficulty) : null;
  const html = C.renderVulnPage({
    appName: "SecureCorp My Account", difficulty,
    bodyHtml: `<h1>My Account</h1><p class="note">Email: demo-user@securecorp-demo.test</p><p class="note">API Key: <span class="field-hidden-value">${apiKey}</span></p><p class="note">Requested: ${fullUrl}</p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Private data cached under a deceptive URL.</strong>\nFLAG: ${flag}</div>` : ""}`
  });
  if (cacheable) DECEPTION_CACHE.set(cacheKey, html);
  res.send(html);
});
router.get("/vuln/cache-deception", (req, res) => res.redirect(`/vuln/cache-deception/account?difficulty=${C.difficultyOf(req)}`));

// =================================================== REQUEST SMUGGLING =====
// A textual analyzer (not a live two-server exploit) — parses a pasted raw
// request two different ways, mirroring how a front-end (Content-Length)
// and back-end (Transfer-Encoding) can disagree about where a request ends.
// The front-end here always trusts Content-Length only (never looks at TE —
// a realistic legacy-proxy simulation). What changes per difficulty is how
// strict the BACK-END is about recognizing a Transfer-Encoding header as
// chunked — each tier requires a genuinely different header construction.
function frontendView(raw) {
  const lines = raw.split("\n");
  const headerEnd = lines.findIndex((l) => l.trim() === "");
  const headers = lines.slice(0, headerEnd === -1 ? lines.length : headerEnd);
  const bodyLines = headerEnd === -1 ? [] : lines.slice(headerEnd + 1);
  const bodyText = bodyLines.join("\n");
  const clHeader = headers.find((h) => /^content-length:/i.test(h));
  const cl = clHeader ? parseInt(clHeader.split(":")[1].trim(), 10) : null;
  if (cl === null || Number.isNaN(cl)) return { request1: bodyText, leftover: "" };
  return { request1: bodyText.slice(0, cl), leftover: bodyText.slice(cl) };
}
function getTELines(headers) { return headers.filter((h) => /^transfer-encoding\s*:/i.test(h)); }
function backendRecognizesChunked(headers, difficulty) {
  const teLines = getTELines(headers);
  if (teLines.length === 0) return false;
  if (difficulty === "easy") return teLines.some((h) => /^transfer-encoding:\s*chunked\s*$/i.test(h));
  if (difficulty === "medium") return teLines.some((h) => /^transfer-encoding:\s*[\w-]+\s*,\s*chunked\s*$/i.test(h));
  if (teLines.length < 2) return false; // hard: requires two SEPARATE Transfer-Encoding lines
  return /^transfer-encoding:\s*chunked\s*$/i.test(teLines[teLines.length - 1]);
}
function backendView(raw, difficulty) {
  const lines = raw.split("\n");
  const headerEnd = lines.findIndex((l) => l.trim() === "");
  const headers = lines.slice(0, headerEnd === -1 ? lines.length : headerEnd);
  const bodyLines = headerEnd === -1 ? [] : lines.slice(headerEnd + 1);
  if (!backendRecognizesChunked(headers, difficulty)) return { request1: bodyLines.join("\n"), leftover: "" };
  let idx = 0, collected = [];
  while (idx < bodyLines.length) {
    const sizeLine = (bodyLines[idx] || "").trim();
    if (sizeLine === "0" || sizeLine === "") { idx++; break; }
    const size = parseInt(sizeLine, 16);
    idx++;
    if (Number.isNaN(size)) break;
    collected.push(bodyLines[idx]);
    idx++;
  }
  return { request1: collected.join("\n"), leftover: bodyLines.slice(idx).join("\n") };
}
const SMUGGLING_EXAMPLE = `POST /vuln/request-smuggling/target HTTP/1.1
Host: securecorp-demo.test
Content-Length: 4
Transfer-Encoding: chunked

0

SMUGGLED_REQUEST_HERE`;
router.get("/vuln/request-smuggling", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const raw = req.query.raw !== undefined ? req.query.raw : SMUGGLING_EXAMPLE;
  let output = "", flag = null;
  if (req.query.raw !== undefined) {
    const front = frontendView(raw);
    const back = backendView(raw, difficulty);
    const desync = !!back.leftover.trim();
    output = `FRONT-END sees body as:\n"${front.request1}"\nleftover (front-end ignores this): "${front.leftover}"\n\nBACK-END sees body as:\n"${back.request1}"\nleftover (back-end treats this as the START of the NEXT request): "${back.leftover}"` +
      (desync ? "\n\n🚩 Desync: the back-end's leftover text would be smuggled into the next user's request." : "\n\nNo desync detected — the back-end doesn't recognize this Transfer-Encoding header as chunked at this difficulty.");
    if (desync) flag = C.getFlag(session, "request-smuggling", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Protocol Analyzer", difficulty,
    bodyHtml: `
      <h1>Request Smuggling Analyzer</h1>
      <p class="note">This is a textual analyzer, not a live two-server exploit: paste a raw HTTP request and see how a Content-Length-based front-end and a Transfer-Encoding-based back-end disagree about where it ends.</p>
      ${difficulty === "easy" ? `<p class="note">The back-end recognizes a plain <code>Transfer-Encoding: chunked</code> header. The pre-filled example already triggers a desync.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The back-end now only recognizes chunked encoding when it's part of a comma-separated list, e.g. <code>Transfer-Encoding: identity, chunked</code>. Edit the header below to that form.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The back-end now requires TWO separate <code>Transfer-Encoding</code> header lines (it uses the last one). Try adding a line <code>Transfer-Encoding: identity</code> directly above the existing <code>Transfer-Encoding: chunked</code> line.</p>` : ""}
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Raw request</label>
        <textarea name="raw" style="min-height:180px;">${raw.replace(/</g, "&lt;")}</textarea>
        <button type="submit">Analyze</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;">FLAG: ${flag}</div>` : ""}
    `
  }));
});

// ===================================================== SECONDARY CONTEXT ===
const TICKETS = [];
function sanitizeShared(input, difficulty) {
  if (difficulty === "easy") return input;
  if (difficulty === "medium") return input.replace(/<script/gi, "");
  return input.replace(/<script/gi, "").replace(/onerror\s*=/gi, "").replace(/onload\s*=/gi, "");
}
router.get("/vuln/secondary-context", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const name = req.query.name, msg = req.query.message;
  let confirmMsg = "";
  if (msg !== undefined) {
    TICKETS.push({ name: name || "anonymous", message: msg });
    confirmMsg = `<div class="result">✅ Ticket submitted. It looks perfectly safe here — but check the admin view.</div>`;
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Support", difficulty,
    bodyHtml: `
      <h1>Submit a Support Ticket</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Name</label><input type="text" name="name" />
        <label>Message</label><textarea name="message"></textarea>
        <button type="submit">Submit</button>
      </form>
      ${confirmMsg}
      <p class="note"><a href="/vuln/secondary-context/admin?difficulty=${difficulty}" target="_blank">Open the Admin Ticket Viewer →</a> (this is the "secondary context" where your input gets reused)</p>
    `
  }));
});
router.get("/vuln/secondary-context/admin", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  let flag = null;
  const rows = TICKETS.slice(-15).map((t) => {
    const rendered = sanitizeShared(t.message, difficulty);
    if (/<[a-z]/i.test(rendered)) flag = C.getFlag(session, "secondary-context", difficulty);
    return `<div class="result"><strong>${t.name}</strong>: ${rendered}</div>`;
  }).join("");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Admin — Ticket Viewer", difficulty,
    bodyHtml: `<h1>All Tickets (admin view)</h1>${rows || '<p class="note">No tickets yet.</p>'}${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Stored XSS triggered in the admin context.</strong>\nFLAG: ${flag}</div>` : ""}`
  }));
});

// ======================================================= RACE CONDITIONS ===
router.get("/vuln/race-conditions", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "race-conditions", { balance: 50, redemptions: 0 });
  const suggestedN = difficulty === "easy" ? 3 : difficulty === "medium" ? 6 : 20;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Gift Card", difficulty,
    bodyHtml: `
      <h1>Redeem Gift Card ($20 per redemption)</h1>
      <p class="note">Current balance: <strong id="bal">$${st.balance}</strong> · Redemptions so far: <strong id="cnt">${st.redemptions}</strong></p>
      <label>Simultaneous requests to fire</label>
      <input type="text" id="n" value="${suggestedN}" />
      <button onclick="fireRace()">Fire simultaneously</button>
      <div class="result" id="out"></div>
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      <script>
        async function fireRace(){
          const n = parseInt(document.getElementById('n').value,10) || 1;
          const calls = Array.from({length:n}, () => fetch('/vuln/race-conditions/redeem?difficulty=${difficulty}', {method:'POST'}).then(r=>r.json()));
          const results = await Promise.all(calls);
          const succeeded = results.filter(r=>r.success).length;
          const last = results[results.length-1];
          document.getElementById('bal').textContent = '$' + last.balance;
          document.getElementById('cnt').textContent = last.redemptions;
          document.getElementById('out').textContent = succeeded + ' of ' + n + ' requests succeeded. Balance is now $' + last.balance + ' after ' + last.redemptions + ' total redemptions (started at $50, should allow at most 2 redemptions if handled safely).';
          const withFlag = results.find(r => r.flag);
          if (withFlag) {
            document.getElementById('flagBox').style.display = 'block';
            document.getElementById('flagBox').innerHTML = '<strong>🚩 Race condition confirmed — over-redeemed.</strong>\\nFLAG: ' + withFlag.flag;
          }
        }
      </script>
    `
  }));
});
router.post("/vuln/race-conditions/redeem", async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "race-conditions", { balance: 50, redemptions: 0 });
  const delay = difficulty === "hard" ? 120 : difficulty === "medium" ? 220 : 400;
  if (st.balance >= 20) {
    await new Promise((r) => setTimeout(r, delay)); // <- the check-then-act gap
    st.balance -= 20;
    st.redemptions += 1;
    const flag = st.redemptions > 2 ? C.getFlag(session, "race-conditions", difficulty) : null;
    return res.json({ success: true, balance: st.balance, redemptions: st.redemptions, flag });
  }
  res.json({ success: false, balance: st.balance, redemptions: st.redemptions });
});


// ============================================================================
// Consolidated from vulns-serverlogic-new.js during the Phase 1 architecture cleanup —
// same labs, same behavior, just no longer a separate "-new" module.
// ============================================================================
// =================================================== REMOTE FILE INCLUSION =
// Distinct from the existing LFI lab: LFI only ever resolves against the
// local VFS. Here, a URL-shaped value is treated as a remote include source
// — the vulnerability is TRUSTING that URL at all, never a real fetch.
const RFI_TRUSTED_HOST = "cdn.securecorp-demo.test";
function isUrlShaped(v) { return /^(https?:)?\/\//i.test(v); }
router.get("/vuln/rfi", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const tpl = req.query.tpl;
  const tplFallback = req.query.tpl_fallback;
  let output = "", flag = null;

  function simulateRemoteInclude(url) {
    return `[SIMULATED REMOTE INCLUDE] Fetched and executed template from ${url}\n` +
      `[SIMULATED RCE PROOF] uid=1000(trainee) gid=1000(trainee) — attacker-controlled remote content executed server-side`;
  }

  if (tpl !== undefined) {
    if (!isUrlShaped(tpl)) {
      output = C.VFS["/app/templates/" + tpl + ".txt"] || "[local template not found]";
    } else if (difficulty === "easy") {
      output = simulateRemoteInclude(tpl);
      flag = C.getFlag(session, "rfi", difficulty);
    } else if (difficulty === "medium") {
      // naive allowlist: just checks the substring is present ANYWHERE
      if (/^https?:\/\//i.test(tpl) && tpl.toLowerCase().includes("securecorp-demo.test")) {
        const hostname = (tpl.match(/^https?:\/\/([^/]+)/i) || [])[1] || "";
        const legit = hostname.toLowerCase() === RFI_TRUSTED_HOST;
        output = simulateRemoteInclude(tpl);
        if (!legit) flag = C.getFlag(session, "rfi", difficulty);
      } else {
        output = "❌ Blocked — URL must reference securecorp-demo.test.";
      }
    } else {
      // hard: tpl itself is properly anchored to the real CDN host now
      const hostname = (tpl.match(/^https:\/\/([^/]+)/i) || [])[1] || "";
      if (hostname === RFI_TRUSTED_HOST) {
        output = simulateRemoteInclude(tpl);
      } else {
        output = "❌ Blocked — tpl must be https://" + RFI_TRUSTED_HOST + "/...";
      }
    }
  } else if (tplFallback !== undefined && difficulty === "hard") {
    // hard: a forgotten fallback path used "when the primary CDN is
    // unreachable" — no validation at all.
    output = simulateRemoteInclude(tplFallback);
    flag = C.getFlag(session, "rfi", difficulty);
  }

  res.send(C.renderVulnPage({
    appName: "SecureCorp Template Importer", difficulty,
    bodyHtml: `
      <h1>Import an Email Template</h1>
      <p class="note">Legit use: import a template by local name (en, fr, es) or from the trusted CDN. ⚙️ Nothing here ever makes a real network request — remote fetches are simulated.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Template (name, or a URL)</label><input type="text" name="tpl" value="${(tpl || "").replace(/"/g, "&quot;")}" placeholder="en" />
        <button type="submit">Import</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Remote File Inclusion confirmed.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "easy" ? `<p class="note">Try: <code>http://attacker-controlled.evil/shell.txt</code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The URL must contain "securecorp-demo.test" — anywhere in the string. Try: <code>https://evil.test/?securecorp-demo.test</code> or <code>https://securecorp-demo.test.evil.test/shell.txt</code></p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The hostname is now properly anchored to the real CDN — that path is genuinely fixed. But there's a fallback template endpoint used "when the CDN is down":</p><form method="GET"><input type="hidden" name="difficulty" value="hard" /><label>tpl_fallback</label><input type="text" name="tpl_fallback" placeholder="http://attacker-controlled.evil/shell.txt" /><button type="submit">Import via fallback</button></form>` : ""}
    `
  }));
});

// ==================================================== CORS MISCONFIG =======
// Everything genuinely runs on one origin in this local sandbox, so we can't
// fully replicate a real cross-origin browser test. Instead we let you
// declare the Origin an attacker's page WOULD send (simOrigin) and the
// server issues the exact response headers that origin would really get —
// so what you observe here is the real, accurate server-side decision.
router.get("/vuln/cors-misconfig", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp API — Account Balance", difficulty,
    bodyHtml: `
      <h1>Cross-Origin API Tester</h1>
      <p class="note">This calls <code>/vuln/cors-misconfig/api</code>, declaring an Origin value the way an attacker-controlled page at that origin would. The server's real CORS response headers are shown below.</p>
      <label>Simulated Origin header</label><input type="text" id="origin" value="https://evil-attacker.test" />
      <button onclick="test()">Send credentialed request</button>
      <div class="result" id="out" style="display:none;"></div>
      <script>
        async function test(){
          const origin = document.getElementById('origin').value;
          const r = await fetch('/vuln/cors-misconfig/api?difficulty=${difficulty}&simOrigin=' + encodeURIComponent(origin), { credentials: 'include' });
          const headers = { 'access-control-allow-origin': r.headers.get('access-control-allow-origin'), 'access-control-allow-credentials': r.headers.get('access-control-allow-credentials') };
          const body = await r.json();
          const out = document.getElementById('out');
          out.style.display = 'block';
          out.textContent = 'Response headers:\\n' + JSON.stringify(headers, null, 2) + '\\n\\nBody (what an attacker page reading this cross-origin response would see):\\n' + JSON.stringify(body, null, 2);
        }
      </script>
      ${difficulty === "easy" ? `<p class="note">Any Origin is reflected, with credentials allowed.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">Only Origins containing "securecorp-demo.test" are reflected — try <code>https://securecorp-demo.test.evil-attacker.test</code></p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Origin is now matched with a real anchored check — except the value <code>null</code> (sent by sandboxed iframes / some redirect flows) is still trusted. Try setting the Origin field to exactly <code>null</code>.</p>` : ""}
    `
  }));
});
router.get("/vuln/cors-misconfig/api", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const simOrigin = req.query.simOrigin || "";
  const SELF = "https://securecorp-demo.test";
  let reflectedOrigin = null, allowCreds = false;

  if (difficulty === "easy") {
    reflectedOrigin = simOrigin || "*";
    allowCreds = true;
  } else if (difficulty === "medium") {
    if (simOrigin.toLowerCase().includes("securecorp-demo.test")) { reflectedOrigin = simOrigin; allowCreds = true; }
  } else {
    if (simOrigin === SELF || simOrigin === "null") { reflectedOrigin = simOrigin; allowCreds = true; }
  }

  if (reflectedOrigin) {
    res.setHeader("Access-Control-Allow-Origin", reflectedOrigin);
    if (allowCreds) res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  const untrusted = reflectedOrigin && reflectedOrigin !== SELF;
  const flag = untrusted && allowCreds ? C.getFlag(session, "cors-misconfig", difficulty) : undefined;
  res.json({ account: "amoore", balance: "$42,150.00 (fake demo data)", flag });
});

module.exports = { router };
