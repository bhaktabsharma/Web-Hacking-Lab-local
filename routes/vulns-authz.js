const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

const ADMIN_NOTE = {
  id: "n-admin-1",
  title: "Reminder to self",
  body: "Told IT (again) to stop leaving this discoverable. If support needs to double check user 100's account, /vuln/idor/profile still works the same as for everyone else. -A"
};

function ensureUser(session) {
  if (!session.canonicalId) {
    const pool = C.USERS[Math.floor(Math.random() * C.USERS.length)];
    session.canonicalId = pool.canonicalId;
    session.notes = [
      { id: "n1", title: "Welcome", body: "This is a demo note. Try editing me." },
      { id: "n2", title: "Groceries", body: "Milk, eggs, bread." }
    ];
  }
}

// ============================================================ IDOR =========
router.get("/vuln/idor", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  const myPublicId = C.encodeId(session.canonicalId, difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Portal",
    difficulty,
    bodyHtml: `
      <h1>My Profile</h1>
      <p class="note">You're logged in. Your id is <span class="pill">${myPublicId}</span> — check the address bar.</p>
      <p class="note">Try visiting <code>/vuln/idor/profile?id=${myPublicId}&difficulty=${difficulty}</code> and changing the id.</p>
      <a class="btn" href="/vuln/idor/profile?id=${myPublicId}&difficulty=${difficulty}">View My Profile →</a>
    `
  }));
});

router.get("/vuln/idor/profile", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  const canonicalId = C.decodeId(req.query.id, difficulty);
  const user = C.findUserByCanonicalId(canonicalId);

  if (!user) {
    return res.send(C.renderVulnPage({
      appName: "SecureCorp Portal", difficulty,
      bodyHtml: `<h1>Profile not found</h1><p class="note">No user matches id "${req.query.id || ""}".</p><a class="btn secondary" href="/vuln/idor?difficulty=${difficulty}">← Back</a>`
    }));
  }
  // Expert tier introduces a REAL ownership check for the first time (every
  // other tier here has none at all, by design — the encoding scheme is
  // the only thing that varies below expert). Blocked here, but the same
  // check was never applied to the batch export endpoint added below.
  if (difficulty === "expert" && canonicalId !== session.canonicalId) {
    return res.send(C.renderVulnPage({
      appName: "SecureCorp Portal", difficulty,
      bodyHtml: `<h1>Access denied</h1><p class="note">You can only view your own profile directly. (Try the Team Directory Export instead.)</p><a class="btn secondary" href="/vuln/idor?difficulty=expert">← Back</a>`
    }));
  }
  // No ownership check — this endpoint returns ANY profile by id. That's the bug.
  const exploited = canonicalId !== session.canonicalId;
  const flag = exploited ? C.getFlag(session, "idor", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Portal", difficulty,
    bodyHtml: `
      <h1>Profile: ${user.username}</h1>
      <table>
        <tr><th>Username</th><td>${user.username}</td></tr>
        <tr><th>Email</th><td>${user.email}</td></tr>
        <tr><th>id parameter</th><td>${req.query.id}</td></tr>
      </table>
      <p class="note">🔎 Open DevTools → view source / Network — the raw API response includes more than what's rendered here:</p>
      <div class="result">GET /api/viewUser?id=${req.query.id}&difficulty=${difficulty}
${JSON.stringify({ id: canonicalId, username: user.username, email: user.email, phone: user.phone, ...(user.password ? { password: user.password } : {}) }, null, 2)}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Exploit confirmed — you viewed a profile that isn't yours.</strong>\nFLAG: ${flag}</div>` : `<p class="note">(That's your own profile — try a different id to actually exploit this.)</p>`}
      ${difficulty === "expert" ? `<p class="note" style="margin-top:16px;">Direct profile access is now checked. Try the <a href="/vuln/idor/export?ids=${myIdPlaceholder(session, difficulty)}&difficulty=expert">Team Directory Export</a> instead — it accepts a batch of ids.</p>` : ""}
      <p style="margin-top:16px;"><a class="btn secondary" href="/vuln/idor?difficulty=${difficulty}">← Back to my profile</a></p>
    `
  }));
});

function myIdPlaceholder(session, difficulty) {
  return C.encodeId(session.canonicalId, difficulty) + ",2";
}

// Expert tier's actual bypass: a bulk "Team Directory Export" feature.
// Realistic, common real-world pattern — a single-record endpoint gets a
// real ownership check, but a LATER bulk/export feature is built against
// a different code path (batch-fetch by an array of ids) that the fix
// never touched. A very common, well-documented class of IDOR bug.
router.get("/vuln/idor/export", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  const idsRaw = String(req.query.ids || "");
  const ids = idsRaw.split(",").map((s) => s.trim()).filter(Boolean);
  const rows = ids.map((raw) => {
    const canonicalId = C.decodeId(raw, difficulty);
    const user = C.findUserByCanonicalId(canonicalId);
    return user ? { requestedId: raw, canonicalId, username: user.username, email: user.email, phone: user.phone } : { requestedId: raw, error: "not found" };
  });
  // No per-row ownership check at all — the bug.
  const leaked = rows.filter((r) => r.canonicalId !== undefined && r.canonicalId !== session.canonicalId);
  const flag = difficulty === "expert" && leaked.length ? C.getFlag(session, "idor", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Portal — Team Directory Export", difficulty,
    bodyHtml: `
      <h1>Team Directory Export</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Comma-separated ids</label><input type="text" name="ids" value="${idsRaw.replace(/"/g, "&quot;")}" />
        <button type="submit">Export</button>
      </form>
      <div class="result">${JSON.stringify(rows, null, 2)}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Bulk export leaked another user's record — the single-profile ownership check was never applied here.</strong>\nFLAG: ${flag}</div>` : ""}
      <p style="margin-top:16px;"><a class="btn secondary" href="/vuln/idor?difficulty=${difficulty}">← Back</a></p>
    `
  }));
});

// JSON API (kept for the Network-tab / raw-request teaching moment)
router.get("/api/viewUser", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  const canonicalId = C.decodeId(req.query.id, difficulty);
  if (Number.isNaN(canonicalId)) return res.status(400).json({ error: "Missing or malformed id parameter." });
  const user = C.findUserByCanonicalId(canonicalId);
  if (!user) return res.status(404).json({ error: "No such user." });
  if (difficulty === "expert" && canonicalId !== session.canonicalId) {
    return res.status(403).json({ error: "You may only view your own profile via this endpoint." });
  }
  res.json({
    id: canonicalId, username: user.username, email: user.email, phone: user.phone,
    ...(user.password ? { password: user.password } : {})
  });
});

// ================================================ BROKEN ACCESS CONTROL ====
function effectiveRole(req, difficulty) {
  if (difficulty === "easy") return "admin"; // no server check exists at all
  if (difficulty === "hard" && req.headers["x-debug-role"] === "admin") return "admin";
  const roleCookie = req.cookies.role;
  if (!roleCookie) return "viewer";
  if (difficulty === "hard") {
    try { return JSON.parse(Buffer.from(roleCookie, "base64").toString("utf8")).role || "viewer"; }
    catch (e) { return "viewer"; }
  }
  return roleCookie;
}

router.get("/vuln/access-control", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  if (difficulty === "hard") res.cookie("role", Buffer.from(JSON.stringify({ role: "viewer" })).toString("base64"));
  else res.cookie("role", "viewer");

  const notesHtml = session.notes.map((n) => `<div class="result">${n.title}\n${n.body}</div>`).join("");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Notes", difficulty,
    bodyHtml: `
      <h1>My Notes <span class="pill">read-only viewer</span></h1>
      ${notesHtml}
      <button disabled>+ Add Note</button>
      <button disabled class="secondary">Edit</button>
      <button disabled class="danger">Delete</button>
      <p class="note">These buttons are disabled in the UI. Is the server actually enforcing that?</p>
      <hr style="margin:20px 0;border:none;border-top:1px solid #eee;" />
      <h1 style="font-size:1rem;">Raw request console</h1>
      <label>Title</label><input type="text" id="t" value="Hacked note" />
      <label>Body</label><input type="text" id="b" value="pwned via broken access control" />
      ${difficulty === "hard" ? `<label>X-Debug-Role header (optional)</label><input type="text" id="dr" placeholder="admin" />` : ""}
      <button onclick="sendNote()">POST /api/notes</button>
      <div class="result" id="out" style="display:none;"></div>
      <script>
        async function sendNote(){
          const headers = {'Content-Type':'application/json'};
          const dr = document.getElementById('dr');
          if (dr && dr.value) headers['X-Debug-Role'] = dr.value;
          const res = await fetch('/api/notes?difficulty=${difficulty}', { method:'POST', headers, body: JSON.stringify({title:document.getElementById('t').value, body:document.getElementById('b').value}) });
          const data = await res.json();
          const out = document.getElementById('out');
          out.style.display = 'block';
          out.textContent = 'HTTP ' + res.status + '\\n' + JSON.stringify(data, null, 2);
        }
      </script>
      <p class="note" style="margin-top:14px;">Console shortcut: <code>document.querySelectorAll('[disabled]').forEach(el =&gt; el.removeAttribute('disabled'))</code></p>
    `
  }));
});

router.get("/api/notes", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  if (req.query.scope === "admin") {
    const difficulty = C.difficultyOf(req);
    if (effectiveRole(req, difficulty) !== "admin") return res.status(403).json({ error: "Admin notes require an admin role." });
    return res.json({ notes: [ADMIN_NOTE] });
  }
  res.json({ notes: session.notes });
});
router.post("/api/notes", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  const difficulty = C.difficultyOf(req);
  if (difficulty !== "easy" && effectiveRole(req, difficulty) !== "admin") return res.status(403).json({ error: "Read-only accounts cannot create notes." });
  const note = { id: "n" + C.randomHex(4), title: req.body.title || "Untitled", body: req.body.body || "" };
  session.notes.push(note);
  const flag = C.getFlag(session, "access-control", difficulty);
  res.json({ message: "✅ Note created — access control bypassed. FLAG: " + flag, note, flag });
});

// ============================================================ FINAL ========
router.get("/vuln/final", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  res.send(C.renderVulnPage({
    appName: "SecureCorp — Classified", difficulty,
    bodyHtml: `
      <h1>[REDACTED]</h1>
      <p class="note">Somewhere in this application, an admin note points to something. Follow the trail. Find user 100's password.</p>
      <p class="note">Tools you already have: <code>/vuln/access-control</code> (to read admin notes) and <code>/vuln/idor/profile?id=</code> (to read a profile).</p>
      <a class="btn secondary" href="/vuln/access-control?difficulty=${difficulty}">Open SecureCorp Notes →</a>
    `
  }));
});

router.post("/api/final-challenge", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const answer = (req.body.password || "").trim();
  if (answer && answer === C.ADMIN.password) {
    C.markSolved(session, "final", "hard");
    return res.json({ success: true, message: "Correct. Challenge complete." });
  }
  res.json({ success: false, message: "Incorrect password." });
});

// ============================================= VERTICAL PRIVILEGE ESCALATION
// Input context: hidden form field (and a secondary API for the hard tier).
router.get("/vuln/vertical-privesc", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "vertical-privesc", { role: "user", name: "Jordan Lee" });
  res.send(C.renderVulnPage({
    appName: "SecureCorp Profile Settings", difficulty,
    bodyHtml: `
      <h1>Edit Profile</h1>
      <p class="note">Current role: <span class="pill">${st.role}</span></p>
      <form method="GET" action="/vuln/vertical-privesc/update">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Display name</label><input type="text" name="name" value="${st.name}" />
        <input type="hidden" name="role" value="user" />
        <button type="submit">Save Profile</button>
      </form>
      <p class="note">🔎 View page source — a hidden "role" field is submitted alongside your name on every save.</p>
      <a class="btn secondary" href="/vuln/vertical-privesc/admin?difficulty=${difficulty}">Try the Admin Panel →</a>
      ${difficulty === "medium" ? `<h4 style="color:#5b6470;margin-top:20px;">Raw request console</h4><label>X-Role-Override header (internal debug feature)</label><input type="text" id="ov" placeholder="admin" /><button class="secondary" onclick="sendOverride()">POST profile update</button><div class="result" id="ovOut" style="display:none;"></div><script>async function sendOverride(){const r=await fetch('/vuln/vertical-privesc/update?difficulty=medium',{headers:{'X-Role-Override':document.getElementById('ov').value}});const t=await r.text();const o=document.getElementById('ovOut');o.style.display='block';o.textContent='Updated.';location.reload();}</script>` : ""}
      ${difficulty === "hard" ? `<p class="note">The role field and the debug header are both fixed on this endpoint — but check for other API endpoints that might do the same update differently (API enumeration pays off here).</p>` : ""}
    `
  }));
});
router.get("/vuln/vertical-privesc/update", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "vertical-privesc", { role: "user", name: "Jordan Lee" });
  st.name = req.query.name || st.name;
  if (difficulty === "easy") {
    if (req.query.role) st.role = req.query.role; // trusted directly, no check at all
  } else if (difficulty === "medium") {
    if (req.headers["x-role-override"]) st.role = req.headers["x-role-override"]; // leftover internal debug header, unconditionally trusted
  }
  // hard: this endpoint no longer honors the role field or the header at all
  res.redirect(`/vuln/vertical-privesc?difficulty=${difficulty}`);
});
router.get("/vuln/vertical-privesc/bulk-update", (req, res) => {
  const difficulty = C.difficultyOf(req);
  if (difficulty !== "hard") return res.status(404).send("Not found.");
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "vertical-privesc", { role: "user", name: "Jordan Lee" });
  if (req.query.role) st.role = req.query.role; // a secondary/legacy endpoint that still has the original bug
  res.redirect(`/vuln/vertical-privesc?difficulty=hard`);
});
router.get("/vuln/vertical-privesc/admin", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "vertical-privesc", { role: "user", name: "Jordan Lee" });
  let output, flag = null;
  if (st.role === "admin") {
    output = "✅ Welcome, admin! Full user management access granted.";
    flag = C.getFlag(session, "vertical-privesc", difficulty);
  } else {
    output = `Access denied — admin role required. Your role: ${st.role}`;
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Profile Settings", difficulty,
    bodyHtml: `<h1>Admin Panel</h1><div class="result">${output}</div>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Privilege escalation confirmed.</strong>\nFLAG: ${flag}</div>` : ""}<p style="margin-top:16px;"><a class="btn secondary" href="/vuln/vertical-privesc?difficulty=${difficulty}">← Back</a></p>`
  }));
});

// ============================================ MULTI-TENANT ISOLATION BYPASS
// Input context: API endpoint + URL parameter (tenant id), plus a cookie and
// a custom header at higher tiers.
const TENANTS = {
  "t-100": { name: "Acme Corp", invoices: ["INV-1001: $500 (fake demo data)"] },
  "t-200": { name: "Globex Inc", invoices: ["INV-2001: $1,200 (fake demo data)", "INV-2002: CONFIDENTIAL — merger terms (fake secret)"] }
};
router.get("/vuln/multi-tenant-isolation", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "multi-tenant-isolation", { tenantId: "t-100" });
  if (difficulty === "medium") res.cookie("tenantId", st.tenantId);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Admin Console", difficulty,
    bodyHtml: `
      <h1>My Organization: Acme Corp (${st.tenantId})</h1>
      <p class="note">Your session belongs to tenant <span class="pill">${st.tenantId}</span>. Another tenant, t-200 (Globex Inc), also exists.</p>
      <a class="btn" href="/vuln/multi-tenant-isolation/api?tenantId=${st.tenantId}&difficulty=${difficulty}">View My Invoices (API)</a>
      <p class="note">Try changing tenantId in the URL to view another organization's data.</p>
      ${difficulty === "medium" ? `<p class="note">A "tenantId" cookie now gates access — but it's a plain, client-editable cookie.</p>` : ""}
      ${difficulty === "hard" ? `<h4 style="color:#5b6470;margin-top:20px;">Raw request console</h4><label>tenantId</label><input type="text" id="tid" value="t-200" /><label>X-Tenant-Token header</label><input type="text" id="tok" placeholder="(reverse of tenantId)" /><button class="secondary" onclick="callApi()">Call API</button><div class="result" id="apiOut" style="display:none;"></div><script>async function callApi(){const tid=document.getElementById('tid').value;const tok=document.getElementById('tok').value;const r=await fetch('/vuln/multi-tenant-isolation/api?tenantId='+encodeURIComponent(tid)+'&difficulty=hard',{headers:{'X-Tenant-Token':tok}});const t=await r.text();const o=document.getElementById('apiOut');o.style.display='block';o.innerHTML=t;}</script><p class="note">Hint: the "token" here isn't real crypto — it's a weak, guessable transform of the tenantId.</p>` : ""}
    `
  }));
});
router.get("/vuln/multi-tenant-isolation/api", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "multi-tenant-isolation", { tenantId: "t-100" });
  const requestedTenant = req.query.tenantId;
  let allowed;
  if (difficulty === "easy") {
    allowed = true;
  } else if (difficulty === "medium") {
    allowed = req.cookies.tenantId === requestedTenant;
  } else {
    const expectedWeakToken = (requestedTenant || "").split("").reverse().join("");
    allowed = req.headers["x-tenant-token"] === expectedWeakToken;
  }
  const tenant = TENANTS[requestedTenant];
  let output, flag = null;
  if (!allowed) {
    output = "403 Forbidden.";
  } else if (!tenant) {
    output = "404 — no such tenant.";
  } else {
    output = `Tenant: ${tenant.name}\n\n${tenant.invoices.join("\n")}`;
    if (requestedTenant !== st.tenantId) flag = C.getFlag(session, "multi-tenant-isolation", difficulty);
  }
  const resultStyle = "background:#f4f5f7;border:1px solid #e2e5e9;border-radius:8px;padding:14px 16px;margin-top:16px;font-family:ui-monospace,Menlo,monospace;font-size:.85rem;white-space:pre-wrap;word-break:break-word;";
  res.send(`<div style="${resultStyle}">${output.replace(/</g, "&lt;")}</div>${flag ? `<div style="${resultStyle}border-color:#4ade80;"><strong>🚩 Cross-tenant data accessed.</strong>\nFLAG: ${flag}</div>` : ""}`);
});


// ============================================================================
// Consolidated from vulns-authz-new.js during the Phase 1 architecture cleanup —
// same labs, same behavior, just no longer a separate "-new" module.
// ============================================================================
// ==================================================== HTTP VERB TAMPERING ==
function requireAdminRole(req) {
  return req.cookies.vt_role === "admin";
}
router.get("/vuln/http-verb-tampering", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (!req.cookies.vt_role) res.cookie("vt_role", "viewer");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Admin Panel — User Management", difficulty,
    bodyHtml: `
      <h1>Delete User #4471</h1>
      <p class="note">You're logged in as a plain "viewer" (see the vt_role cookie) — the Delete button below is disabled for you.</p>
      <button class="btn danger" disabled>Delete User (POST — protected)</button>
      <p class="note" style="margin-top:16px;">Try calling the endpoint directly with different HTTP methods:</p>
      <div class="result">
        fetch('/vuln/http-verb-tampering/delete-user?difficulty=${difficulty}', {method:'POST'})  // protected, checks role
        fetch('/vuln/http-verb-tampering/delete-user?difficulty=${difficulty}', {method:'GET'})   // ?
        fetch('/vuln/http-verb-tampering/delete-user?difficulty=${difficulty}', {method:'PUT'})    // ?
        fetch('/vuln/http-verb-tampering/delete-user?difficulty=${difficulty}', {method:'DELETE'}) // ?
      </div>
      <button onclick="tryAll()">Try all four methods</button>
      <div class="result" id="out" style="display:none;"></div>
      <script>
        async function tryAll(){
          const out = document.getElementById('out');
          out.style.display = 'block';
          let log = '';
          for (const m of ['POST','GET','PUT','DELETE']) {
            const headers = {};
            if (m === 'POST' && ${difficulty === "hard"}) headers['X-HTTP-Method-Override'] = 'DELETE';
            const r = await fetch('/vuln/http-verb-tampering/delete-user?difficulty=${difficulty}', { method: m, headers });
            const d = await r.json().catch(()=>({}));
            log += m + (headers['X-HTTP-Method-Override'] ? ' (+override:'+headers['X-HTTP-Method-Override']+')' : '') + ': ' + JSON.stringify(d) + '\\n';
          }
          out.textContent = log;
        }
      </script>
      ${difficulty === "easy" ? `<p class="note">The DELETE action is reachable via both POST (role-checked) and GET (a separate, unprotected route registration).</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">GET is now also protected. Try PUT or DELETE — handled by a generic catch-all route added for "future REST support" that forgot the role check.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">POST/GET/PUT/DELETE are all protected now. But this app also honors an X-HTTP-Method-Override header (common for clients behind proxies) — sent WITH a plain POST, it's applied to the internal action dispatch AFTER the role check already ran for the original method.</p>` : ""}
    `
  }));
});
router.post("/vuln/http-verb-tampering/delete-user", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const isAdmin = requireAdminRole(req);
  const override = req.headers["x-http-method-override"];

  if (difficulty === "hard" && override === "DELETE") {
    // Trust-boundary bug: the role check above only validated the ORIGINAL
    // method (POST). The override is applied to the action dispatch below
    // without re-running that same check for the overridden verb.
    const flag = C.getFlag(session, "http-verb-tampering", difficulty);
    return res.json({ deleted: true, via: "POST+X-HTTP-Method-Override:DELETE (bypassed re-check)", flag });
  }
  if (!isAdmin) return res.status(403).json({ error: "Forbidden — admin role required." });
  res.json({ deleted: true, via: "POST (properly authorized)" });
});
router.get("/vuln/http-verb-tampering/delete-user", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (difficulty !== "easy") return res.status(403).json({ error: "Forbidden — GET is protected at this difficulty." });
  // easy: this route was registered as a separate, unprotected path — no role check exists here at all.
  const flag = C.getFlag(session, "http-verb-tampering", difficulty);
  res.json({ deleted: true, via: "GET (unprotected duplicate route)", flag });
});
function unprotectedCatchAll(req, res) {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (difficulty !== "medium") return res.status(404).json({ error: "Not found." });
  // medium: a generic "future REST support" catch-all forgot the role check entirely.
  const flag = C.getFlag(session, "http-verb-tampering", difficulty);
  res.json({ deleted: true, via: req.method + " (unprotected generic REST catch-all)", flag });
}
router.put("/vuln/http-verb-tampering/delete-user", unprotectedCatchAll);
router.delete("/vuln/http-verb-tampering/delete-user", unprotectedCatchAll);

module.exports = { router, effectiveRole, ensureUser, ADMIN_NOTE };
