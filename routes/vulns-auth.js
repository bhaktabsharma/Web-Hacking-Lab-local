const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const C = require("./vuln-common");

// ========================================================= 2FA BYPASS ======
router.get("/vuln/2fa-bypass", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Login", difficulty,
    bodyHtml: `
      <h1>Log In</h1>
      <form method="GET" action="/vuln/2fa-bypass/login">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" placeholder="alice" />
        <label>Password</label><input type="text" name="password" placeholder="(anything — demo)" />
        <button type="submit">Log In</button>
      </form>
    `
  }));
});
router.get("/vuln/2fa-bypass/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "2fa-bypass", { loggedIn: false, otpVerified: false, code: String(Math.floor(Math.random() * 100)).padStart(2, "0"), attempts: 0 });
  st.loggedIn = true;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Login", difficulty,
    bodyHtml: `
      <h1>Enter your 2FA code</h1>
      <p class="note">A 2-digit code was "texted" to you.</p>
      <form method="GET" action="/vuln/2fa-bypass/verify">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Code</label><input type="text" name="otp" maxlength="2" />
        <button type="submit">Verify</button>
      </form>
      ${difficulty === "easy" ? `<p class="note">Or just skip this — try going straight to <a href="/vuln/2fa-bypass/account?difficulty=${difficulty}">the account page</a>.</p>` : ""}
      ${difficulty === "hard" ? `<button class="secondary" onclick="bruteForce()">Try all 100 codes</button><div class="result" id="bf"></div>
        <script>
          async function bruteForce(){
            const out = document.getElementById('bf');
            for (let i=0;i<100;i++){
              const code = String(i).padStart(2,'0');
              const r = await fetch('/vuln/2fa-bypass/verify?difficulty=hard&otp='+code);
              const t = await r.text();
              if (t.includes('Verified')) { out.textContent = 'Found code: ' + code + ' after ' + (i+1) + ' attempts.'; return; }
            }
            out.textContent = 'No code worked (unexpected).';
          }
        </script>` : ""}
    `
  }));
});
router.get("/vuln/2fa-bypass/verify", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "2fa-bypass", { loggedIn: true, otpVerified: false, code: "00", attempts: 0 });
  const otp = req.query.otp || "";
  let message;
  if (difficulty === "easy") {
    st.otpVerified = true;
    message = "Verified (this difficulty doesn't check the code at all).";
  } else if (difficulty === "medium") {
    st.otpVerified = true; // any value is accepted
    message = "Verified — any 2-digit value is accepted here.";
  } else {
    st.attempts++;
    if (otp === st.code) { st.otpVerified = true; message = "Verified! Correct code."; }
    else message = `Incorrect code. (attempt ${st.attempts}, no lockout in place)`;
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Login", difficulty,
    bodyHtml: `<h1>${message}</h1><p style="margin-top:16px;"><a class="btn" href="/vuln/2fa-bypass/account?difficulty=${difficulty}">Continue to account →</a></p>`
  }));
});
router.get("/vuln/2fa-bypass/account", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "2fa-bypass", { loggedIn: false, otpVerified: false, code: "00", attempts: 0 });
  if (!st.loggedIn) {
    return res.send(C.renderVulnPage({ appName: "SecureCorp Account", difficulty, bodyHtml: `<h1>Not logged in</h1><p class="note"><a href="/vuln/2fa-bypass?difficulty=${difficulty}">Log in first</a>.</p>` }));
  }
  if (difficulty !== "easy" && !st.otpVerified) {
    return res.send(C.renderVulnPage({ appName: "SecureCorp Account", difficulty, bodyHtml: `<h1>🔒 Blocked</h1><p class="note">2FA verification required before viewing this page.</p>` }));
  }
  const flag = C.getFlag(session, "2fa-bypass", difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Account", difficulty,
    bodyHtml: `<h1>🎉 Full Account Access</h1><p class="note">Secret vault code: <span class="field-hidden-value">TR41N-9F2C</span></p>${difficulty === "easy" ? '<p class="note">Notice you never actually entered a correct 2FA code to get here.</p>' : ""}<div class="result" style="border-color:#4ade80;"><strong>🚩 2FA bypassed.</strong>\nFLAG: ${flag}</div>`
  }));
});

// ===================================================== WEAK PASSWORD =======
const ADMIN_PW = { easy: "admin123", medium: "Summer2024!", hard: "Tr41n1ng!2026" };
router.get("/vuln/weak-password", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "weak-password", { attempts: 0, lockedOut: false });
  res.send(C.renderVulnPage({
    appName: "SecureCorp Login", difficulty,
    bodyHtml: `
      <h1>Register</h1>
      <p class="note">No complexity or length requirements are enforced — any password is accepted.</p>
      <form method="GET" action="/vuln/weak-password/register">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>New username</label><input type="text" name="username" />
        <label>New password</label><input type="text" name="password" />
        <button type="submit">Register</button>
      </form>
      <hr style="margin:24px 0;border:none;border-top:1px solid #eee;" />
      <h1>Log In (try to brute-force "admin")</h1>
      ${st.lockedOut ? '<p class="note">🔒 Locked out for this session (5 failed attempts). Try clearing cookies for a fresh session.</p>' : ""}
      <label>Password guess</label><input type="text" id="guess" />
      <button onclick="tryOne()">Try</button>
      <button class="secondary" onclick="tryList()">Run built-in wordlist</button>
      <div class="result" id="out"></div>
      <script>
        async function tryOne(){
          const p = document.getElementById('guess').value;
          const r = await fetch('/vuln/weak-password/login?difficulty=${difficulty}&username=admin&password=' + encodeURIComponent(p));
          document.getElementById('out').textContent = await r.text();
        }
        async function tryList(){
          const words = ['123456','password','admin123','qwerty','letmein','Summer2024!','Winter2024!','Tr41n1ng!2026','welcome1'];
          const out = document.getElementById('out');
          for (const w of words){
            const r = await fetch('/vuln/weak-password/login?difficulty=${difficulty}&username=admin&password=' + encodeURIComponent(w));
            const t = await r.text();
            out.textContent = 'Tried: ' + w + ' → ' + t;
            if (t.includes('Success')) return;
          }
        }
      </script>
    `
  }));
});
router.get("/vuln/weak-password/register", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Login", difficulty,
    bodyHtml: `<h1>✅ Registered</h1><p class="note">Account "${(req.query.username || "").replace(/</g, "")}" created with password "${(req.query.password || "").replace(/</g, "")}" — no strength check was applied.</p>`
  }));
});
router.get("/vuln/weak-password/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "weak-password", { attempts: 0, lockedOut: false });
  if (difficulty === "hard" && st.lockedOut) return res.send("Locked out for this session.");
  const ok = req.query.password === ADMIN_PW[difficulty];
  if (!ok) {
    st.attempts++;
    if (difficulty === "hard" && st.attempts >= 5) st.lockedOut = true;
    return res.send(`Failure. (attempt ${st.attempts}${difficulty === "hard" ? ", locks after 5" : ""})`);
  }
  res.send(`Success! admin password is "${ADMIN_PW[difficulty]}". FLAG: ${C.getFlag(session, "weak-password", difficulty)}`);
});

// ==================================================== PASSWORD RESET =======
const HARD_LEAKED_TOKEN = crypto.randomBytes(6).toString("hex");
const HARD_TOKEN_OWNER = { [HARD_LEAKED_TOKEN]: "admin" };
router.get("/vuln/password-reset", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Password Reset", difficulty,
    bodyHtml: `
      <h1>Forgot your password?</h1>
      <form method="GET" action="/vuln/password-reset/request">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" placeholder="alice" />
        <button type="submit">Send reset link</button>
      </form>
      ${difficulty === "hard" ? `<div class="result">📧 Recently sent reset emails (debug log — shouldn't be exposed):\nadmin — token: ${HARD_LEAKED_TOKEN} (already used)</div>` : ""}
      <p class="note">Reset a password directly: <a href="/vuln/password-reset/reset-form?difficulty=${difficulty}">reset form →</a></p>
    `
  }));
});
router.get("/vuln/password-reset/request", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const username = req.query.username || "";
  let token;
  if (difficulty === "easy") token = Buffer.from(username).toString("base64");
  else if (difficulty === "medium") token = username.split("").reverse().join("") + "-2024";
  else { token = crypto.randomBytes(6).toString("hex"); HARD_TOKEN_OWNER[token] = username; }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Password Reset", difficulty,
    bodyHtml: `<h1>📧 Email sent (simulated)</h1><p class="note">Reset link: <code>/vuln/password-reset/reset?token=${token}</code></p>`
  }));
});
router.get("/vuln/password-reset/reset-form", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Password Reset", difficulty,
    bodyHtml: `
      <h1>Reset Password</h1>
      <form method="GET" action="/vuln/password-reset/reset">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Token</label><input type="text" name="token" />
        <label>New password</label><input type="text" name="newpassword" value="hacked123" />
        <button type="submit">Reset</button>
      </form>
    `
  }));
});
router.get("/vuln/password-reset/reset", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const token = req.query.token || "";
  const newpassword = req.query.newpassword || "";
  let username = null;
  if (difficulty === "easy") { try { username = Buffer.from(token, "base64").toString("utf8"); } catch (e) {} }
  else if (difficulty === "medium") { if (token.endsWith("-2024")) username = token.slice(0, -5).split("").reverse().join(""); }
  else { username = HARD_TOKEN_OWNER[token] || null; }

  if (!username) {
    return res.send(C.renderVulnPage({ appName: "SecureCorp Password Reset", difficulty, bodyHtml: `<h1>❌ Invalid token</h1>` }));
  }
  const flag = username === "admin" ? C.getFlag(session, "password-reset", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Password Reset", difficulty,
    bodyHtml: `<h1>✅ Password reset</h1><p class="note">The password for account "<strong>${username}</strong>" was changed to "${newpassword}" — without proving ownership of that account.</p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Admin account compromised.</strong>\nFLAG: ${flag}</div>` : `<p class="note">(Try targeting the "admin" account specifically to fully solve this lab.)</p>`}`
  }));
});

// ==================================================== OAUTH MISCONFIG ======
router.get("/vuln/oauth-misconfig", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp ID — OAuth", difficulty,
    bodyHtml: `
      <h1>Authorize "ThirdPartyApp"</h1>
      <p class="note">ThirdPartyApp wants to log in using your SecureCorp ID. Where should we send the authorization code?</p>
      <form method="GET" action="/vuln/oauth-misconfig/authorize">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>redirect_uri</label>
        <input type="text" name="redirect_uri" value="https://securecorp-demo.test/callback" />
        <button type="submit">Authorize</button>
      </form>
    `
  }));
});
router.get("/vuln/oauth-misconfig/authorize", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const redirectUri = req.query.redirect_uri || "";
  let blocked = false, reason = "";
  if (difficulty === "medium" && !redirectUri.includes("securecorp-demo.test")) { blocked = true; reason = "redirect_uri must reference securecorp-demo.test"; }
  if (difficulty === "hard" && !redirectUri.startsWith("https://securecorp-demo.test")) { blocked = true; reason = "redirect_uri must start with https://securecorp-demo.test"; }
  if (blocked) return res.send(C.renderVulnPage({ appName: "SecureCorp ID — OAuth", difficulty, bodyHtml: `<h1>Blocked</h1><p class="note">${reason}</p>` }));

  const fakeCode = "auth_code_" + C.randomHex(6);
  const finalUrl = redirectUri + (redirectUri.includes("?") ? "&" : "?") + "code=" + fakeCode;
  const looksOffDomain = !/^https:\/\/securecorp-demo\.test(\/|$|\?)/.test(redirectUri) || redirectUri.includes("/vuln/open-redirect");
  const flag = looksOffDomain ? C.getFlag(session, "oauth-misconfig", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp ID — OAuth", difficulty,
    bodyHtml: `<h1>Redirecting…</h1><div class="result">${finalUrl}</div>${looksOffDomain ? `<p class="note">🚩 That authorization code would be delivered off-domain.</p><div class="result" style="border-color:#4ade80;">FLAG: ${flag}</div>` : ""}`
  }));
});

// ======================================================== SAML =============
const SAMPLE_ASSERTION = Buffer.from(`<Assertion><Subject>guest</Subject><Attribute name="role">user</Attribute><Signature></Signature></Assertion>`).toString("base64");
router.get("/vuln/saml-vulns", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp SSO — SAML", difficulty,
    bodyHtml: `
      <h1>SAML Login</h1>
      <form method="GET" action="/vuln/saml-vulns/login">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>SAML Response (base64)</label>
        <textarea name="saml" style="min-height:120px;">${SAMPLE_ASSERTION}</textarea>
        <button type="submit">Log In</button>
      </form>
      <p class="note">Decoded sample: <code>&lt;Assertion&gt;&lt;Subject&gt;guest&lt;/Subject&gt;&lt;Attribute name="role"&gt;user&lt;/Attribute&gt;&lt;Signature&gt;&lt;/Signature&gt;&lt;/Assertion&gt;</code></p>
    `
  }));
});
router.get("/vuln/saml-vulns/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  let decoded = "";
  try { decoded = Buffer.from(req.query.saml || "", "base64").toString("utf8"); } catch (e) {}
  const subject = (decoded.match(/<Subject>(.*?)<\/Subject>/i) || [])[1];
  const role = (decoded.match(/<Attribute name="role">(.*?)<\/Attribute>/i) || [])[1];
  const signature = (decoded.match(/<Signature>([\s\S]*?)<\/Signature>/i) || [])[1];
  const notOnOrAfter = (decoded.match(/<NotOnOrAfter>(.*?)<\/NotOnOrAfter>/i) || [])[1];

  let blocked = false, reason = "";
  if (!subject) { blocked = true; reason = "Could not parse a Subject from the assertion."; }
  else if (difficulty !== "easy" && !signature) { blocked = true; reason = "Signature field missing."; }
  else if (difficulty === "hard") {
    if (!notOnOrAfter) { blocked = true; reason = "NotOnOrAfter missing."; }
    else if (new Date(notOnOrAfter).getTime() < Date.now()) { blocked = true; reason = "Assertion expired."; }
  }
  if (blocked) return res.send(C.renderVulnPage({ appName: "SecureCorp SSO — SAML", difficulty, bodyHtml: `<h1>❌ Rejected</h1><p class="note">${reason}</p>` }));
  const flag = subject === "admin" ? C.getFlag(session, "saml-vulns", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp SSO — SAML", difficulty,
    bodyHtml: `<h1>✅ Logged in as "${subject}"</h1><p class="note">Role: ${role || "user"}. Signature was ${difficulty === "easy" ? "never checked" : "checked for presence only — never cryptographically verified"}.</p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Forged into the admin account.</strong>\nFLAG: ${flag}</div>` : `<p class="note">(Forge the Subject to "admin" specifically to fully solve this lab.)</p>`}`
  }));
});

// ======================================================= BRUTE FORCE =======
const BF_USERS = { jsmith: { password: "Winter2025!" } };
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
router.get("/vuln/brute-force", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Staff Portal", difficulty,
    bodyHtml: `
      <h1>Staff Login</h1>
      <p class="note">Candidate usernames to investigate: admin, jsmith, test, svc_backup (only one is real).</p>
      <form method="GET" action="/vuln/brute-force/login">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" />
        <label>Password</label><input type="text" name="password" />
        <button type="submit">Log In</button>
      </form>
      ${difficulty === "easy" ? `<p class="note">The error message itself tells you whether the username exists.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The error message is now identical either way — but check the "serverProcessingMs" field in the response for a timing difference between valid and invalid usernames.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Message and timing are both identical now. Try several failed attempts against the SAME username — a lockout that only triggers for valid usernames is its own side-channel.</p>` : ""}
    `
  }));
});
router.get("/vuln/brute-force/login", async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "brute-force", { attempts: {} });
  const username = req.query.username || "";
  const password = req.query.password || "";
  const validUser = BF_USERS[username];

  if (difficulty === "easy") {
    if (!validUser) return res.json({ error: "No such user." });
    if (password !== validUser.password) return res.json({ error: "Incorrect password." });
  } else if (difficulty === "medium") {
    const delayMs = validUser ? 300 : 50;
    await sleep(delayMs);
    if (!validUser || password !== validUser.password) return res.json({ error: "Invalid username or password.", serverProcessingMs: delayMs });
  } else {
    st.attempts[username] = (st.attempts[username] || 0) + 1;
    await sleep(150);
    if (validUser && st.attempts[username] >= 5) {
      const flag = C.getFlag(session, "brute-force", difficulty);
      return res.json({ error: "Account temporarily locked due to repeated failed attempts.", enumerationFlag: flag, note: "Only valid usernames lock — this response itself confirms '" + username + "' is real." });
    }
    if (!validUser || password !== validUser.password) return res.json({ error: "Invalid username or password." });
  }
  const flag = C.getFlag(session, "brute-force", difficulty);
  res.json({ success: true, message: "Login successful.", flag });
});

// ===================================================== SESSION FIXATION ====
// Input context: cookie (and a URL param override at some tiers). This is a
// genuine 3-step attack chain: fix a session id → victim logs in reusing it
// → attacker reuses the same fixed id to inherit the authenticated session.
const FIXATION_SESSIONS = new Map();
router.get("/vuln/session-fixation", (req, res) => {
  const difficulty = C.difficultyOf(req);
  let sid = req.cookies.fix_sid || req.query.sessionid;
  if (!sid) sid = C.randomHex(6);
  if (!FIXATION_SESSIONS.has(sid)) FIXATION_SESSIONS.set(sid, { authenticated: false, username: null });
  res.cookie("fix_sid", sid);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Customer Portal", difficulty,
    bodyHtml: `
      <h1>Session Fixation — 3-Step Chain</h1>
      <p class="note">This simulates all three roles in one browser tab. Follow the steps in order.</p>
      <h4 style="color:#5b6470;margin-top:20px;">Step 1 — Attacker fixes a session id</h4>
      <p class="note">Your current session id (from a cookie, simulating a link an attacker sent): <span class="pill">${sid}</span></p>
      <a class="btn secondary" href="/vuln/session-fixation?difficulty=${difficulty}&sessionid=ATTACKERCHOSEN1">Use attacker-chosen id "ATTACKERCHOSEN1" instead →</a>
      <h4 style="color:#5b6470;margin-top:20px;">Step 2 — Victim logs in (keeping that same session id)</h4>
      <form method="GET" action="/vuln/session-fixation/login">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" value="victim_jsmith" />
        ${difficulty === "hard" ? `<label><input type="checkbox" name="keep" value="true" style="width:auto;display:inline-block;margin-right:6px;" /> "Keep me signed in" (SSO-style re-entry)</label>` : ""}
        <button type="submit">Log In</button>
      </form>
      <h4 style="color:#5b6470;margin-top:20px;">Step 3 — Attacker reuses the original fixed id</h4>
      <form method="GET" action="/vuln/session-fixation/check">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Session id to check</label><input type="text" name="sessionid" value="ATTACKERCHOSEN1" />
        <button type="submit">Check session</button>
      </form>
      ${difficulty === "medium" ? `<p class="note">Cookie-based session ids ARE now regenerated on login (fixed) — but the login endpoint also accepts a sessionid URL parameter that bypasses that fix.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both cookie and URL-param fixation are patched — except the "Keep me signed in" flow, which skips regeneration.</p>` : ""}
    `
  }));
});
router.get("/vuln/session-fixation/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const username = req.query.username || "victim";
  let effectiveSid;
  if (difficulty === "easy") {
    effectiveSid = req.cookies.fix_sid || C.randomHex(6);
  } else if (difficulty === "medium") {
    effectiveSid = req.query.sessionid ? req.query.sessionid : C.randomHex(6); // cookie path regenerates; URL param path doesn't
  } else {
    effectiveSid = req.query.keep === "true" ? (req.cookies.fix_sid || C.randomHex(6)) : C.randomHex(6);
  }
  FIXATION_SESSIONS.set(effectiveSid, { authenticated: true, username });
  res.cookie("fix_sid", effectiveSid);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Customer Portal", difficulty,
    bodyHtml: `<h1>✅ Logged in as ${username}</h1><p class="note">Session id in use: <span class="pill">${effectiveSid}</span></p><p style="margin-top:16px;"><a class="btn secondary" href="/vuln/session-fixation?difficulty=${difficulty}">← Back</a></p>`
  }));
});
router.get("/vuln/session-fixation/check", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const sid = req.query.sessionid;
  const st = FIXATION_SESSIONS.get(sid);
  let output, flag = null;
  if (st && st.authenticated) {
    output = `✅ Session "${sid}" is authenticated as "${st.username}" — the attacker's pre-chosen session id was inherited by the victim's login.`;
    flag = C.getFlag(session, "session-fixation", difficulty);
  } else {
    output = `Session "${sid}" is not authenticated.`;
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Customer Portal", difficulty,
    bodyHtml: `<h1>Session Check</h1><div class="result">${output}</div>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Session hijacked via fixation.</strong>\nFLAG: ${flag}</div>` : ""}<p style="margin-top:16px;"><a class="btn secondary" href="/vuln/session-fixation?difficulty=${difficulty}">← Back</a></p>`
  }));
});

// =================================================== JWT VULNERABILITIES ===
// Input context: Authorization header (Bearer token). Uses real HMAC-SHA256
// (Node crypto server-side, Web Crypto client-side) — genuine signature
// verification, not a simulated shortcut.
function b64url(buf) { return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function b64urlDecode(str) { str = str.replace(/-/g, "+").replace(/_/g, "/"); while (str.length % 4) str += "="; return Buffer.from(str, "base64"); }
const JWT_REAL_SECRET = "Tr41n1ng_JWT_S3cr3t_2026_xyz789";
const JWT_WEAK_SECRET = "secret123";
const JWT_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqDEMOFAKEPUBLICKEYDONOTUSE0523\n-----END PUBLIC KEY-----";
const JWT_KEY_STORE = { "key-2024-a": JWT_REAL_SECRET }; // the one legitimate, current signing key
function resolveJwtKey(kid) {
  if (!kid) return JWT_KEY_STORE["key-2024-a"];
  if (JWT_KEY_STORE[kid]) return JWT_KEY_STORE[kid];
  // Expert tier's actual bug: an unrecognized kid falls through to being
  // treated as a raw path into the same simulated filesystem the path-
  // traversal/LFI labs already use (src/services/fake-filesystem.js) —
  // whatever content is "read" there gets used AS the HMAC signing key.
  // This is a real, well-documented JWT attack class (CVE reports of
  // "kid": "../../../../dev/null" being used to force an empty/known
  // signing key are common) — genuinely different from hard tier's
  // algorithm-confusion bug, not a harder version of it.
  if (C.VFS[kid]) return C.VFS[kid];
  return null;
}
function hmacSign(headerB64, payloadB64, secret) { return b64url(crypto.createHmac("sha256", secret).update(headerB64 + "." + payloadB64).digest()); }
function issueJwt(payload) {
  const headerB64 = b64url(Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const payloadB64 = b64url(Buffer.from(JSON.stringify(payload)));
  return `${headerB64}.${payloadB64}.${hmacSign(headerB64, payloadB64, JWT_REAL_SECRET)}`;
}
function verifyJwt(token, difficulty) {
  const parts = (token || "").split(".");
  if (parts.length !== 3) return { valid: false, reason: "malformed token" };
  let header, payload;
  try { header = JSON.parse(b64urlDecode(parts[0])); payload = JSON.parse(b64urlDecode(parts[1])); } catch (e) { return { valid: false, reason: "malformed header/payload" }; }
  if (difficulty === "easy") {
    if (header.alg === "none") return parts[2] === "" ? { valid: true, payload } : { valid: false, reason: "signature present for alg:none" };
    return { valid: hmacSign(parts[0], parts[1], JWT_REAL_SECRET) === parts[2], payload, reason: "signature mismatch" };
  }
  if (difficulty === "medium") {
    if (header.alg === "none") return { valid: false, reason: "alg:none is blocked" };
    return { valid: hmacSign(parts[0], parts[1], JWT_WEAK_SECRET) === parts[2], payload, reason: "signature mismatch" };
  }
  // hard: alg confusion — an HS256 token is (buggily) verified using the public RS256 key as the HMAC secret
  if (difficulty === "hard") {
    if (header.alg === "none") return { valid: false, reason: "alg:none is blocked" };
    if (header.alg === "HS256") return { valid: hmacSign(parts[0], parts[1], JWT_PUBLIC_KEY) === parts[2], payload, reason: "signature mismatch" };
    return { valid: false, reason: "only HS256 accepted by this simulation" };
  }
  // expert: alg confusion is fully closed (only the real registered key
  // resolves for a normal request) — but key resolution now happens by
  // `kid` header lookup, and an unrecognized kid falls through to reading
  // an arbitrary path from the same fake filesystem other labs use.
  if (header.alg === "none") return { valid: false, reason: "alg:none is blocked" };
  if (header.alg !== "HS256") return { valid: false, reason: "only HS256 accepted by this simulation" };
  const key = resolveJwtKey(header.kid);
  if (!key) return { valid: false, reason: `no key found for kid "${header.kid || "(none)"}"` };
  return { valid: hmacSign(parts[0], parts[1], key) === parts[2], payload, reason: "signature mismatch" };
}
router.get("/vuln/jwt-vulnerabilities", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const legitToken = issueJwt({ user: "guest", role: "user" });
  res.send(C.renderVulnPage({
    appName: "SecureCorp API — JWT Auth", difficulty,
    bodyHtml: `
      <h1>JWT-Protected API</h1>
      <p class="note">You've been issued a guest token (real HMAC-SHA256, signed server-side). Forge a token below and call the admin endpoint.</p>
      <div class="result">${legitToken}</div>
      ${difficulty === "hard" ? `<p class="note">Public verification key (published for RS256 API clients):</p><div class="result">${JWT_PUBLIC_KEY}</div>` : ""}
      <h4 style="color:#5b6470;margin-top:20px;">Token Forge Helper (real Web Crypto HMAC-SHA256)</h4>
      <label>alg</label><input type="text" id="alg" value="HS256" />
      ${difficulty === "expert" ? `<label>kid (key id header)</label><input type="text" id="kid" value="/app/templates/en.txt" />` : ""}
      <label>Payload JSON</label><textarea id="payload">{"user":"admin","role":"admin"}</textarea>
      <label>Secret to sign with (leave blank only if alg is "none")</label><input type="text" id="secret" value="${difficulty === "medium" ? JWT_WEAK_SECRET : difficulty === "hard" ? JWT_PUBLIC_KEY : difficulty === "expert" ? "Welcome to SecureCorp Demo!" : ""}" />
      <button type="button" onclick="forge()">Forge Token</button>
      <div class="result" id="forged" style="display:none;"></div>
      <form method="GET" action="/vuln/jwt-vulnerabilities/admin" style="margin-top:16px;">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Token to send as Authorization: Bearer</label>
        <textarea name="token" id="tokenField">${legitToken}</textarea>
        <button type="submit">Call /admin</button>
      </form>
      <script>
        function b64urlBuf(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); }
        function b64urlStr(str){ return btoa(unescape(encodeURIComponent(str))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); }
        async function forge(){
          const alg = document.getElementById('alg').value;
          const kidEl = document.getElementById('kid');
          const payloadText = document.getElementById('payload').value;
          const secret = document.getElementById('secret').value;
          const header = {alg, typ:'JWT'};
          if (kidEl && kidEl.value) header.kid = kidEl.value;
          const headerB64 = b64urlStr(JSON.stringify(header));
          const payloadB64 = b64urlStr(payloadText);
          let sig = '';
          if (alg !== 'none' && secret) {
            const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
            const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(headerB64+'.'+payloadB64));
            sig = b64urlBuf(sigBuf);
          }
          const token = headerB64 + '.' + payloadB64 + '.' + sig;
          document.getElementById('forged').style.display = 'block';
          document.getElementById('forged').textContent = token;
          document.getElementById('tokenField').value = token;
        }
      </script>
      ${difficulty === "medium" ? `<p class="note">alg:none is now rejected — but the real signing secret is weak/guessable.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The secret is strong, but an algorithm-confusion bug lets an HS256 token get verified using the published RS256 public key as the HMAC secret.</p>` : ""}
      ${difficulty === "expert" ? `<p class="note">Algorithm confusion is fixed — only the one real key (kid: "key-2024-a") verifies normally. Keys are looked up by the "kid" header you control, though — an unrecognized kid falls through to being read as a raw path from this app's internal file store. The forge helper above is already set to kid "/app/templates/en.txt" with that file's exact content as the signing secret — forge and send.</p>` : ""}
    `
  }));
});
router.get("/vuln/jwt-vulnerabilities/admin", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const result = verifyJwt(req.query.token, difficulty);
  let output, flag = null;
  if (!result.valid) {
    output = `❌ Rejected: ${result.reason}`;
  } else if (!result.payload || result.payload.role !== "admin") {
    output = `Valid token, but role="${result.payload && result.payload.role}" — not an admin.`;
  } else {
    output = "✅ Welcome, admin! Here is the internal flag vault.";
    flag = C.getFlag(session, "jwt-vulnerabilities", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp API — JWT Auth", difficulty,
    bodyHtml: `<h1>/admin result</h1><div class="result">${output}</div>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Forged admin token accepted.</strong>\nFLAG: ${flag}</div>` : ""}<p style="margin-top:16px;"><a class="btn secondary" href="/vuln/jwt-vulnerabilities?difficulty=${difficulty}">← Back</a></p>`
  }));
});


// ============================================================================
// Consolidated from vulns-auth-new.js during the Phase 1 architecture cleanup —
// same labs, same behavior, just no longer a separate "-new" module.
// ============================================================================
// ========================================================= CAPTCHA BYPASS =
router.get("/vuln/captcha-bypass", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "captcha-bypass", { a: 3, b: 4, attemptsWithoutFreshCaptcha: 0, usedChallenge: null });
  if (difficulty === "hard") { st.a = Math.floor(Math.random() * 8) + 1; st.b = Math.floor(Math.random() * 8) + 1; st.usedChallenge = null; }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Staff Login", difficulty,
    bodyHtml: `
      <h1>Log In</h1>
      <p class="note">CAPTCHA: what is ${st.a} + ${st.b}?</p>
      <form method="GET" action="/vuln/captcha-bypass/login" id="f">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        ${difficulty !== "easy" ? `<input type="hidden" name="a" value="${st.a}" /><input type="hidden" name="b" value="${st.b}" />` : ""}
        <label>Username</label><input type="text" name="username" value="admin" />
        <label>Password guess</label><input type="text" name="password" value="wrongpass" />
        <label>CAPTCHA answer</label><input type="text" name="captcha" id="captchaInput" />
        <button type="button" onclick="submitChecked()">Log In</button>
      </form>
      <div class="result" id="out" style="display:none;"></div>
      <button class="secondary" onclick="automate()">Run 5 automated login attempts</button>
      <div class="result" id="autoOut" style="display:none;"></div>
      <p class="note">${difficulty === "easy" ? "The CAPTCHA is only checked in this page's JavaScript, before the request is even sent." : difficulty === "medium" ? "The CAPTCHA is checked server-side now — but the same challenge (3+4) is never invalidated, so one correct answer can be replayed forever." : "The CAPTCHA rotates every request and is checked server-side, single-use. There is, however, an internal QA testing bypass header some deployments forget to remove."}</p>
      <script>
        const correctClientSide = ${st.a} + ${st.b};
        function submitChecked(){
          const val = Number(document.getElementById('captchaInput').value);
          if (${difficulty === "easy" ? "true" : "false"} && val !== correctClientSide) { alert('Wrong CAPTCHA (client-side check)'); return; }
          document.getElementById('f').submit();
        }
        async function automate(){
          const out = document.getElementById('autoOut');
          out.style.display = 'block';
          let log = '';
          for (let i=0;i<5;i++){
            const url = '/vuln/captcha-bypass/login?difficulty=${difficulty}&username=admin&password=guess' + i +
              ${difficulty !== "easy" ? `'&a=${st.a}&b=${st.b}&captcha=${st.a + st.b}'` : "'&captcha=999999'"} +
              (${difficulty === "hard"} ? '&skipCaptcha=true' : '');
            const r = await fetch(url, ${difficulty === "hard" ? "{ headers: { 'X-QA-Bypass': 'true' } }" : "{}"});
            const t = await r.text();
            log += 'Attempt ' + (i+1) + ': ' + (t.includes('FLAG') ? 'FLAG FOUND' : t.includes('Success') || t.includes('automated') ? 'accepted without solving a fresh CAPTCHA' : 'rejected') + '\\n';
            out.textContent = log;
            if (t.includes('FLAG')) { out.innerHTML = log.replace(/\\n/g,'<br>') + '<br><br>' + t.match(/FLAG\\{[^}]+\\}/); return; }
          }
        }
      </script>
    `
  }));
});
router.get("/vuln/captcha-bypass/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "captcha-bypass", { a: 3, b: 4, attemptsWithoutFreshCaptcha: 0, usedChallenge: null });
  const skipCaptcha = req.query.skipCaptcha === "true" && req.headers["x-qa-bypass"] === "true";
  let captchaOk = false, freshlySolved = false;

  if (difficulty === "easy") {
    captchaOk = true; // never actually checked server-side
    freshlySolved = false;
  } else if (difficulty === "medium") {
    const a = Number(req.query.a), b = Number(req.query.b), answer = Number(req.query.captcha);
    captchaOk = answer === a + b;
    freshlySolved = false; // same challenge can be replayed indefinitely — never rotates or expires
  } else {
    if (skipCaptcha) { captchaOk = true; freshlySolved = false; }
    else {
      const a = Number(req.query.a), b = Number(req.query.b), answer = Number(req.query.captcha);
      const matchesCurrent = a === st.a && b === st.b;
      captchaOk = matchesCurrent && answer === a + b;
      if (captchaOk) { st.a = Math.floor(Math.random() * 8) + 1; st.b = Math.floor(Math.random() * 8) + 1; freshlySolved = true; } // single-use: rotates immediately
    }
  }

  if (!captchaOk) return res.send("Incorrect CAPTCHA or credentials.");
  if (!freshlySolved) st.attemptsWithoutFreshCaptcha++;
  let flag;
  if (st.attemptsWithoutFreshCaptcha >= 3) flag = C.getFlag(session, "captcha-bypass", difficulty);
  res.send(`Login attempt processed (automated, no CAPTCHA freshly solved this time). attemptsWithoutFreshCaptcha=${st.attemptsWithoutFreshCaptcha}` + (flag ? `\nFLAG: ${flag}` : ""));
});

// ================================================ INSECURE COOKIE FLAGS ====
// Focused entirely on HttpOnly — the one flag genuinely, fully testable via
// real browser cookie behavior in a local sandbox (Secure/SameSite can't be
// honestly demonstrated without a real second origin/TLS listener).
router.get("/vuln/insecure-cookie-flags", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session, sid } = C.getOrInitSession(req, res);
  if (difficulty === "easy") res.cookie("authToken_ick", "tok_" + C.randomHex(6), { httpOnly: false });
  else res.cookie("authToken_ick", "tok_" + C.randomHex(6), { httpOnly: true });
  const proofToken = C.issueClientProofToken(session, "insecure-cookie-flags", difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Account Session", difficulty,
    bodyHtml: `
      <h1>Account Session</h1>
      <p class="note">Logged in. An authToken cookie was just set for this session.</p>
      <button onclick="readCookie()">Simulate malicious script: read document.cookie</button>
      <div class="result" id="out" style="display:none;"></div>
      ${difficulty !== "easy" ? `<p class="note" style="margin-top:16px;">The main login flow's cookie is HttpOnly now. But there's also a <a href="/vuln/insecure-cookie-flags/${difficulty === "medium" ? "remember-me" : "reset-confirm"}?difficulty=${difficulty}">${difficulty === "medium" ? "\"Remember Me\" persistent-login endpoint" : "password-reset confirmation flow"}</a> — try visiting that, then re-run the read above.</p>` : ""}
      <script>
        const PROOF_TOKEN = ${JSON.stringify(proofToken)};
        const ICK_DIFFICULTY = ${JSON.stringify(difficulty)};
        async function readCookie(){
          const out = document.getElementById('out');
          out.style.display = 'block';
          if (document.cookie.includes('authToken_ick')) {
            const r = await fetch('/api/confirm-client-exploit', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({labId:'insecure-cookie-flags', difficulty:ICK_DIFFICULTY, token:PROOF_TOKEN}) });
            const d = await r.json();
            out.innerHTML = '<strong>🚩 Cookie readable via JavaScript — HttpOnly is missing.</strong>\\nRaw: ' + document.cookie + (d.success ? '\\nFLAG: ' + d.flag : '');
            out.style.borderColor = '#4ade80';
          } else {
            out.textContent = 'document.cookie does not include authToken_ick — HttpOnly is protecting it here.';
          }
        }
      </script>
    `
  }));
});
router.get("/vuln/insecure-cookie-flags/remember-me", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.cookie("authToken_ick", "tok_remember_" + C.randomHex(6), { httpOnly: false }); // forgotten secondary code path
  res.redirect(`/vuln/insecure-cookie-flags?difficulty=${difficulty}`);
});
router.get("/vuln/insecure-cookie-flags/reset-confirm", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  if (difficulty === "hard") res.cookie("authToken_ick", "tok_resetconfirm_" + C.randomHex(6), { httpOnly: false }); // third forgotten path
  res.redirect(`/vuln/insecure-cookie-flags?difficulty=${difficulty}`);
});

// =================================================== SESSION ID IN URL =====
const SIU_STORE = new Map();
SIU_STORE.set("victim-tok-9f21", { username: "admin", role: "admin" });
router.get("/vuln/session-id-in-url", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Legacy Customer Portal", difficulty,
    bodyHtml: `
      <h1>Log In</h1>
      <p class="note">This legacy portal tracks sessions entirely via a URL parameter — no cookie at all.</p>
      <form method="GET" action="/vuln/session-id-in-url/login">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" value="guest" />
        <button type="submit">Log In</button>
      </form>
      <p class="note">An admin session was pre-recorded earlier today (for this lab, its token is "victim-tok-9f21" — normally you'd have to find it, not be told it directly).</p>
      <p class="note"><a href="/vuln/session-id-in-url/access-log?difficulty=${difficulty}">Recent access log →</a></p>
    `
  }));
});
router.get("/vuln/session-id-in-url/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const username = req.query.username || "guest";
  const token = C.randomHex(6);
  SIU_STORE.set(token, { username, role: "user" });
  res.redirect(`/vuln/session-id-in-url/dashboard?difficulty=${difficulty}&sessionid=${token}`);
});
router.get("/vuln/session-id-in-url/dashboard", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const token = req.query.sessionid;
  const acct = SIU_STORE.get(token);
  if (!acct) return res.send(C.renderVulnPage({ appName: "SecureCorp Legacy Customer Portal", difficulty, bodyHtml: `<h1>❌ Invalid or expired session id</h1>` }));
  const flag = acct.role === "admin" ? C.getFlag(session, "session-id-in-url", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Legacy Customer Portal", difficulty,
    bodyHtml: `<h1>Welcome, ${acct.username}</h1><p class="note">Session id in URL: <span class="pill">${token}</span></p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Hijacked an admin session via a URL-embedded token.</strong>\nFLAG: ${flag}</div>` : ""}`
  }));
});
router.get("/vuln/session-id-in-url/access-log", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const roleCookie = req.cookies.siu_role;
  const simReferer = req.query.simReferer || "";
  let allowed;
  if (difficulty === "easy") allowed = true;
  else if (difficulty === "medium") allowed = simReferer.includes("/vuln/session-id-in-url/dashboard"); // spoofable "referer check as access control"
  else allowed = roleCookie === "admin"; // requires a real (still just a plain cookie, but at least a deliberate step) admin flag
  if (!allowed) {
    return res.send(C.renderVulnPage({
      appName: "SecureCorp Legacy Customer Portal", difficulty,
      bodyHtml: `<h1>🔒 Access log restricted</h1>${difficulty === "hard" ? `<p class="note">Even with access, the dashboard now sends <code>Referrer-Policy: no-referrer</code>, so this vector alone won't leak anything further at this difficulty. But session identifiers belonging in URLs at all is still the root problem — see the shared-link scenario below.</p><p class="note"><a href="/vuln/session-id-in-url/shared-link?difficulty=hard">📋 A colleague pasted a dashboard link into a support ticket →</a></p>` : `<p class="note">${difficulty === "medium" ? 'Try requesting this page with a simReferer param claiming to come from the dashboard: <code>?simReferer=/vuln/session-id-in-url/dashboard</code>' : ''}</p>`}`
    }));
  }
  res.setHeader("Referrer-Policy", difficulty === "hard" ? "no-referrer" : "no-referrer-when-downgrade");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Legacy Customer Portal", difficulty,
    bodyHtml: `
      <h1>Recent Access Log</h1>
      <div class="result">10:02:14 GET /dashboard?sessionid=a91fbe (guest)\n10:03:41 GET /dashboard?sessionid=victim-tok-9f21 (admin — pre-recorded earlier today)\n10:04:02 GET /dashboard?sessionid=2c88de (guest)</div>
      <p class="note">Full request URLs — including session tokens — are always captured in server access logs, regardless of any header policy. That's a structural property of putting secrets in URLs, not a fixable misconfiguration.</p>
      <p style="margin-top:16px;"><a class="btn secondary" href="/vuln/session-id-in-url/dashboard?difficulty=${difficulty}&sessionid=victim-tok-9f21">Reuse the admin token from this log →</a></p>
    `
  }));
});
router.get("/vuln/session-id-in-url/shared-link", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Legacy Customer Portal", difficulty,
    bodyHtml: `<h1>📋 Support Ticket #8842</h1><p class="note">"...here's the link to my dashboard, having trouble finding the invoice:"</p><p style="margin-top:16px;"><a class="btn" href="/vuln/session-id-in-url/dashboard?difficulty=${difficulty}&sessionid=victim-tok-9f21">/vuln/session-id-in-url/dashboard?sessionid=victim-tok-9f21</a></p>`
  }));
});

// =================================================== WEAK SESSION TOKEN ====
const WST_STORE = new Map();
WST_STORE.set("1", { username: "admin", role: "admin" });
let wstCounter = 1000;
router.get("/vuln/weak-session-token", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const adminLoginTs = Math.floor(Date.now() / 1000) - 4; // "recorded" ~4s ago, shown in a plausible status panel
  if (difficulty === "medium") WST_STORE.set(String(adminLoginTs * 1000), { username: "admin", role: "admin" });
  res.send(C.renderVulnPage({
    appName: "SecureCorp Kiosk Login", difficulty,
    bodyHtml: `
      <h1>Guest Kiosk Login</h1>
      <form method="GET" action="/vuln/weak-session-token/login">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Guest name</label><input type="text" name="name" value="visitor" />
        <button type="submit">Log In</button>
      </form>
      ${difficulty === "medium" ? `<p class="note">System status: last admin login recorded at unix ts ${adminLoginTs} (±a few seconds).</p>` : ""}
      ${difficulty === "hard" ? `<p class="note"><a href="/vuln/weak-session-token/debug-sessions?difficulty=hard">🔧 /debug-sessions (leftover internal QA endpoint)</a></p>` : ""}
    `
  }));
});
router.get("/vuln/weak-session-token/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  let token;
  if (difficulty === "easy") { token = String(wstCounter++); }
  else if (difficulty === "medium") { token = String(Date.now()); }
  else { token = crypto.randomBytes(16).toString("hex"); }
  WST_STORE.set(token, { username: req.query.name || "guest", role: "guest" });
  res.send(C.renderVulnPage({
    appName: "SecureCorp Kiosk Login", difficulty,
    bodyHtml: `<h1>✅ Logged in</h1><p class="note">Your session token: <span class="pill">${token}</span></p><form method="GET" action="/vuln/weak-session-token/account" style="margin-top:16px;"><input type="hidden" name="difficulty" value="${difficulty}" /><label>Session token to check</label><input type="text" name="token" value="${token}" /><button type="submit">View account</button></form>`
  }));
});
router.get("/vuln/weak-session-token/account", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const acct = WST_STORE.get(req.query.token);
  if (!acct) return res.send(C.renderVulnPage({ appName: "SecureCorp Kiosk Login", difficulty, bodyHtml: `<h1>❌ Invalid token</h1>` }));
  const flag = acct.role === "admin" ? C.getFlag(session, "weak-session-token", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Kiosk Login", difficulty,
    bodyHtml: `<h1>Account: ${acct.username} (${acct.role})</h1>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Hijacked an admin session by guessing its token.</strong>\nFLAG: ${flag}</div>` : ""}`
  }));
});
router.get("/vuln/weak-session-token/debug-sessions", (req, res) => {
  const difficulty = C.difficultyOf(req);
  if (difficulty !== "hard") return res.status(404).send("Not found.");
  const rows = [...WST_STORE.entries()].slice(-5).map(([tok, acct]) => `${tok} — ${acct.username} (${acct.role})`).join("\n");
  res.send(C.renderVulnPage({ appName: "SecureCorp Kiosk Login", difficulty, bodyHtml: `<h1>🔧 Debug: Recent Sessions</h1><div class="result">${rows}\n1 — admin (admin)</div><p class="note">Leftover internal QA endpoint — was never meant to ship.</p>` }));
});

// ====================================================== BROKEN LOGOUT ======
const BL_TOKENS = new Map();
const BL_REMEMBER = new Map();
router.get("/vuln/broken-logout", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Employee Portal", difficulty,
    bodyHtml: `
      <h1>Log In</h1>
      <form method="GET" action="/vuln/broken-logout/login">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" value="jsmith" />
        <button type="submit">Log In</button>
      </form>
    `
  }));
});
router.get("/vuln/broken-logout/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const tok = C.randomHex(8);
  BL_TOKENS.set(tok, { username: req.query.username || "jsmith", valid: true });
  let rememberTok;
  if (difficulty === "medium" || difficulty === "hard") {
    rememberTok = C.randomHex(8);
    BL_REMEMBER.set(rememberTok, { username: req.query.username || "jsmith", valid: true });
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Employee Portal", difficulty,
    bodyHtml: `
      <h1>✅ Logged in</h1>
      <p class="note">Session token: <span class="pill">${tok}</span></p>
      ${rememberTok ? `<p class="note">"Remember me" token (separate, longer-lived): <span class="pill">${rememberTok}</span></p>` : ""}
      <p style="margin-top:16px;"><a class="btn" href="/vuln/broken-logout/account?difficulty=${difficulty}&token=${tok}">View account →</a></p>
      <p><a class="btn secondary" href="/vuln/broken-logout/logout?difficulty=${difficulty}&token=${tok}${rememberTok ? "&rememberToken=" + rememberTok : ""}">Log Out</a></p>
    `
  }));
});
router.get("/vuln/broken-logout/logout", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { token, rememberToken } = req.query;
  if (difficulty === "easy") {
    // does nothing server-side — purely cosmetic
  } else if (difficulty === "medium") {
    BL_TOKENS.delete(token); // primary invalidated; "remember me" forgotten
  } else {
    // hard: both invalidated, but the primary token's removal happens
    // asynchronously (simulating a real message-queue-based session
    // cleanup job) — a genuine ~300ms race window.
    if (rememberToken) BL_REMEMBER.delete(rememberToken);
    setTimeout(() => BL_TOKENS.delete(token), 300);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Employee Portal", difficulty,
    bodyHtml: `<h1>👋 Logged out</h1><p class="note">Token used: ${token}</p><p style="margin-top:16px;"><a class="btn secondary" href="/vuln/broken-logout/account?difficulty=${difficulty}&token=${token}">Try the account page again with the same token →</a></p>${rememberToken ? `<p><a class="btn secondary" href="/vuln/broken-logout/account?difficulty=${difficulty}&rememberToken=${rememberToken}">Try the "remember me" token →</a></p>` : ""}`
  }));
});
router.get("/vuln/broken-logout/account", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const { token, rememberToken } = req.query;
  const primary = token && BL_TOKENS.get(token);
  const remembered = rememberToken && BL_REMEMBER.get(rememberToken);
  const acct = primary || remembered;
  if (!acct) return res.send(C.renderVulnPage({ appName: "SecureCorp Employee Portal", difficulty, bodyHtml: `<h1>🔒 Session invalid — please log in again</h1>` }));
  const flag = C.getFlag(session, "broken-logout", difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Employee Portal", difficulty,
    bodyHtml: `<h1>Account: ${acct.username}</h1><div class="result" style="border-color:#4ade80;"><strong>🚩 A token from before logout is still valid.</strong>\nFLAG: ${flag}</div>`
  }));
});

module.exports = { router };
