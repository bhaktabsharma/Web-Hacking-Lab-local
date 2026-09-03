/**
 * routes/vulns-chains.js
 *
 * NEW CATEGORY — "Attack Chains" (Phase 3c, Section 16 of the upgrade
 * spec). Each lab here requires combining 3-4 genuinely distinct
 * techniques in sequence — the same idea as the existing "final"
 * challenge, generalized. Marked `locked: true` in labs-data.js like
 * final, with an explicit `prerequisites` list per chain (see app.js's
 * generalized unlock check) rather than final's "solve literally
 * everything else" rule, since each chain only actually depends on a
 * handful of specific techniques.
 */
const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

// =============================================================================
// CHAIN 1 — Support Portal Takeover
// Info disclosure (leaked backup file) -> weak/default credentials -> IDOR
// on another user's support ticket.
// =============================================================================
const CH1_TICKETS = {
  1: { owner: "support_temp", subject: "Printer on 3rd floor is out of toner", body: "Please order more toner, thanks." },
  2: { owner: "cwalsh_finance", subject: "Q1 invoice reconciliation — CONFIDENTIAL", body: "See attached wire details for the Meridian Corp settlement. Reference code needed to authorize: " }
};
function ch1FlagTicketId(difficulty) { return 2; } // the "confidential" ticket, not your own
function ch1EncodeTicketRef(id, difficulty) {
  if (difficulty === "easy") return String(id);
  if (difficulty === "medium") return String(id + 4817); // offset — enumerate nearby values from a visible one
  return Buffer.from(String(id)).toString("base64"); // hard: base64-encoded reference
}
function ch1DecodeTicketRef(ref, difficulty) {
  if (difficulty === "easy") { const n = parseInt(ref, 10); return Number.isFinite(n) ? n : null; }
  if (difficulty === "medium") { const n = parseInt(ref, 10); return Number.isFinite(n) ? n - 4817 : null; }
  try { const n = parseInt(Buffer.from(ref, "base64").toString("utf8"), 10); return Number.isFinite(n) ? n : null; } catch (e) { return null; }
}

router.get("/vuln/chain-support-takeover", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  C.advanceChainState(session, "chain-support-takeover", "STARTED");
  const myTicketRef = ch1EncodeTicketRef(1, difficulty);
  const backupPath = difficulty === "easy" ? "/vuln/chain-support-takeover/backup/config.js.bak"
    : difficulty === "medium" ? "/vuln/chain-support-takeover/backup/support-portal.js.bak"
    : "/vuln/chain-support-takeover/.git-config";
  res.send(C.renderVulnPage({
    appName: "SecureCorp Support Portal", difficulty,
    bodyHtml: `
      <h1>Support Portal</h1>
      <p class="note">A newly-launched internal support portal. Somewhere in here is ticket "${difficulty === "medium" ? "around " + myTicketRef : difficulty === "hard" ? "(reference encoded)" : "#2"}" — a finance ticket that shouldn't be readable by a support agent.</p>
      ${difficulty === "easy" ? `<p class="note"><a href="${backupPath}">A leftover backup file</a> is linked right on the deploy status page.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">Deploy artifacts sometimes get left behind with a predictable ".bak" suffix on the app's own filename. (Try: ${backupPath})</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Check for a leftover VCS config file at the site root — a very common leftover from automated deploys. (Try: ${backupPath})</p>` : ""}
      <p class="note">Once you have credentials:</p>
      <form method="POST" action="/vuln/chain-support-takeover/login" onsubmit="return false;" id="loginForm">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" id="u" />
        <label>Password</label><input type="text" id="p" />
        <button onclick="login()">Log In</button>
      </form>
      <div class="result" id="out" style="display:none;"></div>
      <div id="ticketArea"></div>
      <script>
        let sessionCookieSet = false;
        async function login(){
          const r = await fetch('/vuln/chain-support-takeover/login?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
          const d = await r.json();
          show(d);
          if (d.success) {
            document.getElementById('ticketArea').innerHTML = '<label>Ticket reference</label><input type="text" id="ref" value="" placeholder="e.g. ${myTicketRef}" /><button onclick="viewTicket()">View Ticket</button>';
          }
        }
        async function viewTicket(){
          const ref = document.getElementById('ref').value;
          const r = await fetch('/vuln/chain-support-takeover/tickets/' + encodeURIComponent(ref) + '?difficulty=${difficulty}');
          show(await r.json());
        }
        function show(d){ const out = document.getElementById('out'); out.style.display='block'; out.textContent = JSON.stringify(d, null, 2); }
      </script>
    `
  }));
});
router.get("/vuln/chain-support-takeover/backup/config.js.bak", (req, res) => {
  if (C.difficultyOf(req) !== "easy") return res.status(404).send("Not found.");
  const { session } = C.getOrInitSession(req, res);
  C.advanceChainState(session, "chain-support-takeover", "CREDENTIAL_LEAK_FOUND");
  res.type("text/plain").send("// SecureCorp support portal config\n// TODO: change default cred before real launch\nmodule.exports = { defaultUser: 'support_temp', defaultPass: 'Supp0rt_Temp_2026!' };\n");
});
router.get("/vuln/chain-support-takeover/backup/support-portal.js.bak", (req, res) => {
  if (C.difficultyOf(req) !== "medium") return res.status(404).send("Not found.");
  const { session } = C.getOrInitSession(req, res);
  C.advanceChainState(session, "chain-support-takeover", "CREDENTIAL_LEAK_FOUND");
  res.type("text/plain").send("// SecureCorp support portal config\n// TODO: change default cred before real launch\nmodule.exports = { defaultUser: 'support_temp', defaultPass: 'Supp0rt_Temp_2026!' };\n");
});
router.get("/vuln/chain-support-takeover/.git-config", (req, res) => {
  if (C.difficultyOf(req) !== "hard") return res.status(404).send("Not found.");
  const { session } = C.getOrInitSession(req, res);
  C.advanceChainState(session, "chain-support-takeover", "CREDENTIAL_LEAK_FOUND");
  res.type("text/plain").send("[remote \"origin\"]\n  url = git@git.securecorp-demo.test:internal/support-portal.git\n[user]\n  # rotate before launch\n  default-login = support_temp / Supp0rt_Temp_2026!\n");
});
router.post("/vuln/chain-support-takeover/login", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "chain-support-takeover", { loggedIn: false });
  if ((req.body.username || "") === "support_temp" && (req.body.password || "") === "Supp0rt_Temp_2026!") {
    st.loggedIn = true;
    C.advanceChainState(session, "chain-support-takeover", "AUTHENTICATED");
    return res.json({ success: true, message: "Logged in as support_temp (role: support)." });
  }
  res.json({ success: false });
});
router.get("/vuln/chain-support-takeover/tickets/:ref", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "chain-support-takeover", { loggedIn: false });
  if (!st.loggedIn) return res.status(403).json({ error: "Log in first." });
  const id = ch1DecodeTicketRef(req.params.ref, difficulty);
  const ticket = id !== null ? CH1_TICKETS[id] : null;
  if (!ticket) return res.status(404).json({ error: "Ticket not found." });
  C.advanceChainState(session, "chain-support-takeover", "TICKET_ACCESS_CONFIRMED");
  let body = ticket.body;
  const isFlagTicket = id === ch1FlagTicketId(difficulty);
  if (isFlagTicket) C.advanceChainState(session, "chain-support-takeover", "EXPLOIT_VERIFIED");
  const flag = isFlagTicket ? C.getFlag(session, "chain-support-takeover", difficulty) : undefined;
  if (flag) {
    body += flag;
    C.advanceChainState(session, "chain-support-takeover", "FLAG_ISSUED");
  }
  res.json({ subject: ticket.subject, owner: ticket.owner, body, flag });
});

// =============================================================================
// CHAIN 2 — Internal Network Pivot
// SSRF via a "link preview" feature -> reach an internal-only admin API ->
// use a leaked internal API key against a real (chain-local) admin endpoint.
// =============================================================================
function ch2IsInternalTarget(url, difficulty) {
  if (difficulty === "easy") return /internal-admin\.local/i.test(url);
  // medium: the literal hostname from easy is now blocked — only raw
  // internal IPs/localhost forms are recognized as internal at this tier.
  if (difficulty === "medium") return /(^|\/\/)(169\.254\.169\.254|127\.0\.0\.1|localhost)([:/]|$)/i.test(url);
  // hard: literal internal hostnames/IPs are blocked; only reachable via the "trusted" internal redirector
  return /safe-redirector\.securecorp-demo\.test\/go\?to=internal-admin\.local/i.test(url);
}
router.get("/vuln/chain-internal-pivot", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  C.advanceChainState(session, "chain-internal-pivot", "STARTED");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Chat — Link Preview", difficulty,
    bodyHtml: `
      <h1>Link Preview Bot</h1>
      <p class="note">Paste a URL and the bot fetches a preview (simulated — no real outbound request is ever made).</p>
      <input type="text" id="url" value="https://example.com" style="width:100%;" />
      <button onclick="preview()">Fetch Preview</button>
      <div class="result" id="out" style="display:none;"></div>
      <div id="adminArea"></div>
      ${difficulty === "easy" ? `<p class="note">Try: http://internal-admin.local/creds</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">Literal internal-admin.local is blocked now — try a well-known internal/metadata address instead: 169.254.169.254 or 127.0.0.1.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Direct internal addresses are blocked. Requests routed through the "trusted" internal redirector aren't re-checked: https://safe-redirector.securecorp-demo.test/go?to=internal-admin.local</p>` : ""}
      <script>
        async function preview(){
          const r = await fetch('/vuln/chain-internal-pivot/preview?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:document.getElementById('url').value})});
          const d = await r.json();
          const out = document.getElementById('out'); out.style.display='block'; out.textContent = JSON.stringify(d, null, 2);
          if (d.internalKey) document.getElementById('adminArea').innerHTML = '<label>Internal API key</label><input type="text" id="key" value="' + d.internalKey + '" /><button onclick="callAdmin()">Call admin API</button>';
        }
        async function callAdmin(){
          const r = await fetch('/vuln/chain-internal-pivot/admin-api/flag?difficulty=${difficulty}', {headers:{'X-Internal-Key': document.getElementById('key').value}});
          const d = await r.json();
          const out = document.getElementById('out'); out.textContent = JSON.stringify(d, null, 2);
        }
      </script>
    `
  }));
});
router.post("/vuln/chain-internal-pivot/preview", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const url = String(req.body.url || "");
  if (!ch2IsInternalTarget(url, difficulty)) {
    return res.json({ title: "Example Domain", description: "This domain is for use in illustrative examples." });
  }
  const st = C.labState(session, "chain-internal-pivot", { key: "sc_internal_" + C.randomHex(8) });
  C.advanceChainState(session, "chain-internal-pivot", "SSRF_KEY_OBTAINED");
  res.json({ title: "Internal Admin Metadata Service", description: "[SIMULATED SSRF] Reached an internal-only service.", internalKey: st.key });
});
router.get("/vuln/chain-internal-pivot/admin-api/flag", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "chain-internal-pivot", { key: "sc_internal_" + C.randomHex(8) });
  const provided = req.headers["x-internal-key"];
  if (provided && provided === st.key) {
    C.advanceChainState(session, "chain-internal-pivot", "EXPLOIT_VERIFIED");
    const flag = C.getFlag(session, "chain-internal-pivot", difficulty);
    C.advanceChainState(session, "chain-internal-pivot", "FLAG_ISSUED");
    return res.json({ access: "granted", flag });
  }
  res.status(403).json({ access: "denied" });
});

// =============================================================================
// CHAIN 3 — Stored XSS to Admin Wire Approval
// Stored XSS in a support ticket -> an admin "reviews the queue" (server-
// side simulation of the admin opening it) -> the injected script silently
// approves a pending wire transfer via the admin's session.
// =============================================================================
function ch3Sanitize(msg, difficulty) {
  if (difficulty === "easy") return msg;
  if (difficulty === "medium") return String(msg).replace(/<script/gi, "");
  return String(msg).replace(/<script/gi, "").replace(/onerror\s*=/gi, "").replace(/onload\s*=/gi, "");
}
router.get("/vuln/chain-xss-to-admin-action", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "chain-xss-to-admin-action", { ticketMessage: "", pendingApproved: false });
  C.advanceChainState(session, "chain-xss-to-admin-action", "STARTED");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Support — New Ticket", difficulty,
    bodyHtml: `
      <h1>Submit a Support Ticket</h1>
      <p class="note">A pending wire transfer (#9931, $18,400.00) is awaiting admin approval elsewhere in the system. An admin periodically reviews new tickets — anything rendered in front of them runs in THEIR session.</p>
      <label>Message</label>
      <textarea id="msg" style="min-height:90px;"></textarea>
      <button onclick="submitTicket()">Submit Ticket</button>
      <button onclick="simulateAdmin()" style="margin-left:8px;">Simulate admin reviewing the queue</button>
      <div class="result" id="out" style="display:none;"></div>
      ${difficulty === "easy" ? `<p class="note">Try: &lt;img src=x onerror="fetch('/vuln/chain-xss-to-admin-action/admin-approve?difficulty=easy',{method:'POST'})"&gt;</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">"&lt;script" is stripped now — use an event-handler payload like the one above instead.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">"&lt;script", onerror=, and onload= are all stripped now. Try an unblocked event handler: &lt;svg onbegin="fetch('/vuln/chain-xss-to-admin-action/admin-approve?difficulty=hard',{method:'POST'})"&gt;</p>` : ""}
      <script>
        async function submitTicket(){
          const message = document.getElementById('msg').value;
          const r = await fetch('/vuln/chain-xss-to-admin-action/submit?difficulty=${difficulty}', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message})});
          show(await r.json());
        }
        async function simulateAdmin(){
          const r = await fetch('/vuln/chain-xss-to-admin-action/simulate-admin-review?difficulty=${difficulty}', {method:'POST'});
          show(await r.json());
        }
        function show(d){ const out = document.getElementById('out'); out.style.display='block'; out.textContent = JSON.stringify(d, null, 2); }
      </script>
    `
  }));
});
router.post("/vuln/chain-xss-to-admin-action/submit", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "chain-xss-to-admin-action", { ticketMessage: "", pendingApproved: false });
  st.ticketMessage = ch3Sanitize(req.body.message || "", difficulty);
  const looksLiveOnSubmit = /<script/i.test(st.ticketMessage) || /on\w+\s*=/i.test(st.ticketMessage);
  if (looksLiveOnSubmit) C.advanceChainState(session, "chain-xss-to-admin-action", "PAYLOAD_STORED");
  res.json({ stored: true, renderedAs: st.ticketMessage });
});
router.post("/vuln/chain-xss-to-admin-action/simulate-admin-review", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "chain-xss-to-admin-action", { ticketMessage: "", pendingApproved: false });
  // The "admin" renders whatever HTML is stored. We detect a genuinely live
  // executable pattern (not just any tag) surviving the sanitizer, exactly
  // like the header-xss lab's detection logic — a partially-stripped
  // payload (e.g. onerror= removed from an <img>) is inert, not a real find.
  const looksLive = /<script/i.test(st.ticketMessage) || /on\w+\s*=/i.test(st.ticketMessage);
  if (looksLive) C.advanceChainState(session, "chain-xss-to-admin-action", "ADMIN_EXECUTION_CONFIRMED");
  res.json({ adminReviewed: true, note: looksLive ? "The admin's browser just ran your script." : "The admin saw plain text — nothing executed." });
});
router.post("/vuln/chain-xss-to-admin-action/admin-approve", (req, res) => {
  // This endpoint represents an action taken FROM WITHIN the admin's
  // hijacked session (the injected script calls it) — reachable only in
  // the sense that a real attack would trigger it via the admin's browser;
  // here it's called directly by the PoC payload for the same effect.
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "chain-xss-to-admin-action", { ticketMessage: "", pendingApproved: false });
  const looksLive = /<script/i.test(st.ticketMessage) || /on\w+\s*=/i.test(st.ticketMessage);
  if (!looksLive) return res.status(403).json({ error: "No hijacked admin session to act through — submit and trigger the payload first." });
  st.pendingApproved = true;
  C.advanceChainState(session, "chain-xss-to-admin-action", "EXPLOIT_VERIFIED");
  const flag = C.getFlag(session, "chain-xss-to-admin-action", difficulty);
  C.advanceChainState(session, "chain-xss-to-admin-action", "FLAG_ISSUED");
  res.json({ transferApproved: true, amount: 18400.0, flag });
});

module.exports = { router };
