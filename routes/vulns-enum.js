const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

// =============================================== FILES & DIRECTORIES =======
function hiddenPaths(difficulty) {
  if (difficulty === "easy") return { "/backup.zip": "SecureCorp full site backup (fake archive)." };
  if (difficulty === "medium") return { "/old_admin_2019/": "Legacy admin panel (decommissioned, still reachable)." };
  return { "/config.php.bak": "<?php\ndefine('DB_PASS','Tr41n1ng_DB_2026!');\n// backup file left behind by an editor — not executed, served as plain text" };
}
router.get("/vuln/enum-files", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const path = req.query.path;
  const paths = hiddenPaths(difficulty);
  let output = "", flag = null;
  if (path !== undefined) {
    if (paths[path]) {
      output = `200 OK\n\n${paths[path]}`;
      flag = C.getFlag(session, "enum-files", difficulty);
    } else {
      output = "404 Not Found";
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Web Server", difficulty,
    bodyHtml: `
      <h1>Path Prober</h1>
      <p class="note">This site has no visible links to some real, sensitive files. Try probing common paths — a real attacker would use a wordlist tool (gobuster/ffuf/dirb).</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Path</label><input type="text" name="path" placeholder="/backup.zip" value="${(path || "").replace(/"/g, "&quot;")}" />
        <button type="submit">Probe</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Hidden file discovered.</strong>\nFLAG: ${flag}</div>` : ""}
      <button class="secondary" onclick="runWordlist()">Run built-in wordlist</button>
      <div class="result" id="wlOut" style="display:none;"></div>
      <script>
        async function runWordlist(){
          const words = ['/backup.zip','/backup.tar.gz','/old_admin_2019/','/admin_old/','/config.php.bak','/config.bak','/.env.bak','/site-backup/'];
          const out = document.getElementById('wlOut');
          out.style.display = 'block';
          for (const w of words){
            const r = await fetch('/vuln/enum-files?difficulty=${difficulty}&path=' + encodeURIComponent(w));
            const t = await r.text();
            const found = t.includes('200 OK');
            out.textContent = 'Tried: ' + w + ' -> ' + (found ? 'FOUND (reload to see it)' : '404');
            if (found) { location.href = '/vuln/enum-files?difficulty=${difficulty}&path=' + encodeURIComponent(w); return; }
            await new Promise(r=>setTimeout(r,150));
          }
        }
      </script>
    `
  }));
});

// ==================================================== VIRTUAL HOSTS ========
function hiddenVhosts(difficulty) {
  if (difficulty === "easy") return { "admin.securecorp-demo.test": "Internal Admin Console (should not be reachable by this Host header)." };
  if (difficulty === "medium") return { "staging-internal.securecorp-demo.test": "Staging environment — pre-release build, internal only." };
  return { "Internal-API.securecorp-demo.test": "Internal API gateway (note: exact case required — this check is case-sensitive)." };
}
router.get("/vuln/virtual-hosts", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const vhost = req.query.vhost;
  const hidden = hiddenVhosts(difficulty);
  let output = "", flag = null;
  if (vhost !== undefined) {
    // easy/medium: case-insensitive match (server normalizes Host header casing).
    // hard: case-sensitive match (no normalization) — the wordlist entry uses mixed case on purpose.
    const matchedKey = difficulty === "hard"
      ? (hidden[vhost] ? vhost : null)
      : Object.keys(hidden).find((k) => k.toLowerCase() === (vhost || "").toLowerCase());
    if (matchedKey) {
      output = `200 OK (served by matching Host header: ${vhost})\n\n${hidden[matchedKey]}`;
      flag = C.getFlag(session, "virtual-hosts", difficulty);
    } else {
      output = `404 (default site served — "${vhost}" doesn't match any configured vhost)`;
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Virtual Host Prober", difficulty,
    bodyHtml: `
      <h1>Host Header Prober</h1>
      <p class="note">This server hosts multiple sites on the same IP, distinguished by the Host header — including some never linked publicly. This tool simulates sending a request with a custom Host header value.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Host header value</label><input type="text" name="vhost" placeholder="admin.securecorp-demo.test" value="${(vhost || "").replace(/"/g, "&quot;")}" />
        <button type="submit">Send</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Hidden virtual host discovered.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "hard" ? `<p class="note">This tier's check is case-sensitive — try variations in capitalization, e.g. Internal-API.securecorp-demo.test.</p>` : ""}
    `
  }));
});

// ============================================ FUZZING & HTTP PARAMETERS ====
router.get("/vuln/fuzz-params", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  let unlocked = false;
  if (difficulty === "easy") {
    unlocked = req.query.debug === "true";
  } else if (difficulty === "medium") {
    unlocked = req.query.internal === "1";
  } else {
    // hard: requires bracket-notation nested parameter, not a flat name
    unlocked = req.query.filter && req.query.filter.status === "admin";
  }
  const flag = unlocked ? C.getFlag(session, "fuzz-params", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Dashboard", difficulty,
    bodyHtml: `
      <h1>Dashboard</h1>
      <p class="note">This page has an undocumented parameter that unlocks hidden functionality — the kind of thing parameter-fuzzing tools (ffuf, Arjun, x8) are built to find.</p>
      ${unlocked
        ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Hidden functionality unlocked.</strong>\nFLAG: ${flag}</div>`
        : `<div class="result">Standard dashboard — nothing special here. Try adding query parameters.</div>`}
      ${difficulty === "medium" ? `<p class="note">Try a parameter other than "debug" — something meaning roughly the same thing.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">A flat parameter name isn't enough here — try a nested/bracket-style parameter, e.g. <code>?filter[status]=admin</code>.</p>` : ""}
    `
  }));
});

// =================================================== DNS ZONE TRANSFER =====
const ZONE_RECORDS = [
  "www.securecorp-demo.test.        IN A     93.184.216.34",
  "api.securecorp-demo.test.        IN A     93.184.216.35",
  "mail.securecorp-demo.test.       IN MX    10 mail.securecorp-demo.test.",
  "internal-vpn.securecorp-demo.test. IN A   10.0.0.4",
  "backup-db.securecorp-demo.test.  IN A     10.0.0.7",
  "ns1.securecorp-demo.test.        IN A     93.184.216.10"
];
const ZONE_KEY = "tsig-" + C.randomHex(3);
router.get("/vuln/dns-zone-transfer", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const server = req.query.server;
  const key = req.query.key;
  let output = "", flag = null, allowed = false;

  if (server !== undefined) {
    if (difficulty === "easy") {
      allowed = true;
    } else if (difficulty === "medium") {
      allowed = server === "ns1.securecorp-demo.test"; // trivially spoofable claimed identity, no real auth
    } else {
      allowed = server === "ns1.securecorp-demo.test" && key === ZONE_KEY;
    }
    if (allowed) {
      output = "Zone transfer (AXFR) succeeded:\n\n" + ZONE_RECORDS.join("\n");
      flag = C.getFlag(session, "dns-zone-transfer", difficulty);
    } else {
      output = "Zone transfer refused — server did not authorize this request.";
    }
  }

  res.send(C.renderVulnPage({
    appName: "SecureCorp DNS Zone Transfer Tool", difficulty,
    bodyHtml: `
      <h1>Request a Zone Transfer (AXFR)</h1>
      <p class="note">A properly configured DNS server only allows zone transfers from specific trusted secondary servers. This one might not.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Requesting server identity</label><input type="text" name="server" placeholder="ns1.securecorp-demo.test" />
        ${difficulty === "hard" ? `<label>Zone transfer key</label><input type="text" name="key" placeholder="tsig-..." />` : ""}
        <button type="submit">Request AXFR</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Full zone disclosed.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "hard" ? `<p class="note">Need the key? Check the <a href="/vuln/dns-zone-transfer/changelog?difficulty=${difficulty}">ops changelog</a> — sometimes internal notes leak more than intended.</p>` : ""}
    `
  }));
});
router.get("/vuln/dns-zone-transfer/changelog", (req, res) => {
  const difficulty = C.difficultyOf(req);
  if (difficulty !== "hard") return res.status(404).send("Not found.");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Ops Changelog", difficulty,
    bodyHtml: `<h1>Ops Changelog (internal)</h1><div class="result">2026-05-02 — rotated zone transfer key to ${ZONE_KEY} for ns1↔ns2 sync. Reminder: this page shouldn't be public.</div>`
  }));
});

module.exports = { router };
