/**
 * routes/vulns-api.js
 *
 * NEW CATEGORY — "API Security" (Phase 3a, Section 8 of the upgrade spec).
 * GraphQL uses real graphql-js (the actual reference implementation used by
 * real-world GraphQL APIs — not a hand-rolled toy parser), so introspection,
 * validation errors, and "Did you mean" suggestions all behave exactly like
 * a genuine target would. WebSockets use the standard `ws` package,
 * attached to the same underlying HTTP server Express already listens on
 * (see attachWebSocketServer, called once from server.js).
 */
const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const C = require("./vuln-common");
const { parse, validate, execute, specifiedRules, NoSchemaIntrospectionCustomRule, buildSchema, GraphQLError } = require("graphql");
const WebSocket = require("ws");

// =============================================================================
// Shared fake dataset — isolated from vuln-common's USERS (different fields,
// different purpose: this one exists specifically to hold API-sensitive
// data like SSNs/API keys for the API-security labs).
// =============================================================================
const API_USERS = [
  { id: 1, username: "amoore", email: "a.moore@securecorp-demo.test", bio: "Sales lead.", role: "user", ssn: "412-19-2291", passwordHash: "5f4dcc3b5aa765d61d8327deb882cf99", apiKey: "sk_live_a1f02x9c", internalDebugNotes: "flagged for KYC re-verification 2026-02" },
  { id: 2, username: "bkline", email: "b.kline@securecorp-demo.test", bio: "Support engineer.", role: "user", ssn: "558-73-1140", passwordHash: "5f4dcc3b5aa765d61d8327deb882cf99", apiKey: "sk_live_b298zqe1", internalDebugNotes: "none" },
  { id: 3, username: "cwalsh", email: "c.walsh@securecorp-demo.test", bio: "Finance.", role: "user", ssn: "203-88-4471", passwordHash: "5f4dcc3b5aa765d61d8327deb882cf99", apiKey: "sk_live_c344lpz7", internalDebugNotes: "none" },
  { id: 100, username: "admin", email: "admin@securecorp-demo.test", bio: "System administrator.", role: "admin", ssn: "000-00-0000", passwordHash: "e19d5cd5af0378da05f63f891c7467af", apiKey: "sk_live_ADMIN_9f21xk", internalDebugNotes: "rotate quarterly — last rotated 2026-01-05" }
];
function ensureApiUser(session) {
  if (!session.apiUserId) {
    const pool = API_USERS.filter((u) => u.role !== "admin");
    session.apiUserId = pool[Math.floor(Math.random() * pool.length)].id;
  }
  return session.apiUserId;
}

// =============================================================================
// GRAPHQL — three labs (introspection, BOLA, excessive data exposure) share
// this one real endpoint, exactly as a real deployment would. Difficulty
// controls the overall hardening posture of the whole endpoint, matching
// every other lab's ?difficulty= convention.
// =============================================================================
const GQL_SCHEMA = buildSchema(`
  type User {
    id: Int
    username: String
    email: String
    bio: String
    role: String
    ssn: String
    passwordHash: String
    apiKey: String
    internalDebugNotes: String
  }
  type Query {
    me: User
    user(id: Int): User
    userProfile(id: Int): User
    node(id: Int): User
    users(search: String): [User]
    search(text: String): [User]
  }
`);

const SENSITIVE_FIELDS = ["ssn", "passwordHash", "apiKey", "internalDebugNotes"];

function buildGqlRoot(session, difficulty) {
  const myId = ensureApiUser(session);
  const byId = (id) => API_USERS.find((u) => u.id === id) || null;

  function ownedLookup(id) {
    if (difficulty === "easy") return byId(id); // BOLA: no ownership check at all
    if (difficulty === "expert") return byId(id); // centralized pre-execution check instead — see expertFieldAuthzViolation
    return id === myId ? byId(id) : null; // medium/hard: correctly checked here, per-resolver
  }
  function legacyLookup(id) {
    // "userProfile" — an older duplicate field the migration forgot to
    // deprecate. Still unchecked at easy AND medium; fixed only at hard
    // (and, differently, at expert — see below).
    if (difficulty === "hard") return id === myId ? byId(id) : null;
    if (difficulty === "expert") return byId(id);
    return byId(id);
  }
  function genericNodeLookup(id) {
    // Relay-style generic object lookup. Real, common GraphQL pattern where
    // type-specific authorization is easy to forget to re-apply — stays
    // unchecked at easy/medium/hard, on purpose, as the hard-tier finding.
    // At expert, it's covered too (by the same centralized check as the
    // other two) — closing this hole is what makes expert's OWN, different
    // gap worth finding instead of just reusing this one.
    return byId(id);
  }
  function listLookup() {
    return API_USERS;
  }

  return {
    me: () => byId(myId),
    user: ({ id }) => ownedLookup(id),
    userProfile: ({ id }) => legacyLookup(id),
    node: ({ id }) => genericNodeLookup(id),
    users: () => listLookup(),
    search: () => listLookup()
  };
}

// A deliberately naive, regex/substring-based "security middleware" — the
// kind real teams sometimes bolt on in front of a GraphQL endpoint without
// actually parsing the query. Both the introspection-substring check and
// the sensitive-field-substring check below are this exact anti-pattern.
function naiveIntrospectionBlocked(rawQuery, difficulty) {
  if (difficulty === "easy") return false;
  if (difficulty === "medium") return /__schema/.test(rawQuery); // "__type" isn't checked
  return false; // hard applies the REAL validation rule instead, see below
}
function naiveFieldFilterBlocks(rawQuery, difficulty) {
  if (difficulty !== "medium") return false;
  // Only scans the text immediately inside users(...)/search(...)'s OWN
  // selection braces — misses fields pulled in via a named fragment spread
  // defined elsewhere in the document.
  const m = rawQuery.match(/(?:users|search)\s*(?:\([^)]*\))?\s*\{([^}]*)\}/);
  if (!m) return false;
  return SENSITIVE_FIELDS.some((f) => m[1].includes(f));
}
function realFieldAuthzViolation(document, difficulty) {
  // hard: a REAL (AST-based, not regex) check — walks every selection in
  // the document for users()/search() specifically, rejecting sensitive
  // fields there. node() is deliberately NOT covered (matches the same
  // "generic lookup forgot type-specific rules" finding as the BOLA lab).
  // Applies at hard AND expert — the real AST-based sensitive-field check
  // stays fully in force at expert too (expert's own gap is object-level,
  // not field-level; see expertFieldAuthzViolation).
  if (difficulty !== "hard" && difficulty !== "expert") return false;
  let violated = false;
  const guardedRootFields = ["users", "search"];
  for (const def of document.definitions) {
    if (!def.selectionSet) continue;
    for (const sel of def.selectionSet.selections) {
      if (sel.kind === "Field" && guardedRootFields.includes(sel.name.value) && sel.selectionSet) {
        const scan = (set) => {
          for (const s of set.selections) {
            if (s.kind === "Field") {
              if (SENSITIVE_FIELDS.includes(s.name.value)) violated = true;
            } else if (s.kind === "FragmentSpread") {
              const frag = document.definitions.find((d) => d.kind === "FragmentDefinition" && d.name.value === s.name.value);
              if (frag) scan(frag.selectionSet);
            }
          }
        };
        scan(sel.selectionSet);
      }
    }
  }
  return violated;
}
// Expert tier's distinct gap (a genuinely different bug class than hard's
// "the generic lookup was never covered"): ownership enforcement is
// centralized as ONE pre-execution check covering user()/userProfile()/
// node() together (closing all 3 of hard tier's holes — every resolver
// above just does a plain lookup at expert, trusting this gate entirely)
// — but the check only inspects the FIRST guarded field selection in the
// whole document and assumes every other instance shares the same id.
// A second, differently-ALIASED occurrence of a guarded field with a
// different id sails straight through — a real, well-documented GraphQL
// batching/aliasing authorization bypass class.
function expertFieldAuthzViolation(document, myId) {
  const guardedFields = ["user", "userProfile", "node"];
  for (const def of document.definitions) {
    if (!def.selectionSet) continue;
    for (const sel of def.selectionSet.selections) {
      if (sel.kind === "Field" && guardedFields.includes(sel.name.value)) {
        const idArg = (sel.arguments || []).find((a) => a.name.value === "id");
        const requestedId = idArg && idArg.value && idArg.value.kind === "IntValue" ? parseInt(idArg.value.value, 10) : null;
        return requestedId !== myId; // only the FIRST occurrence is ever checked
      }
    }
  }
  return false; // no guarded field present at all in this document
}

router.post("/graphql", express.json(), async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const rawQuery = String(req.body.query || "");

  let document;
  try {
    document = parse(rawQuery);
  } catch (e) {
    return res.status(400).json({ errors: [{ message: "Syntax error: " + e.message }] });
  }

  if (naiveIntrospectionBlocked(rawQuery, difficulty)) {
    return res.json({ errors: [{ message: "Introspection is disabled." }] });
  }

  // Real introspection-blocking validation rule applies at both hard AND
  // expert (expert closes every hard-tier hole, including this one — its
  // own gap is elsewhere; see expertFieldAuthzViolation above).
  const rules = (difficulty === "hard" || difficulty === "expert") ? [...specifiedRules, NoSchemaIntrospectionCustomRule] : specifiedRules;
  const validationErrors = validate(GQL_SCHEMA, document, rules);
  if (validationErrors.length) {
    const messages = validationErrors.map((e) => e.message);
    // Schema-extraction-via-error-messages still counts as a real
    // introspection leak even though the query never executes — a "Did
    // you mean" suggestion on a hidden field name IS the finding.
    let extensions;
    if (messages.some((m) => /Did you mean.*internalDebugNotes/i.test(m))) {
      extensions = { flags: { "graphql-introspection": C.getFlag(session, "graphql-introspection", difficulty) } };
    }
    return res.json({ errors: messages.map((message) => ({ message })), extensions });
  }

  if (naiveFieldFilterBlocks(rawQuery, difficulty)) {
    return res.json({ errors: [{ message: "Query rejected: sensitive field requested directly." }] });
  }
  if (realFieldAuthzViolation(document, difficulty)) {
    return res.json({ errors: [{ message: "Field-level authorization: sensitive fields are not permitted on this query." }] });
  }
  if (difficulty === "expert") {
    const myIdForCheck = ensureApiUser(session);
    if (expertFieldAuthzViolation(document, myIdForCheck)) {
      return res.json({ errors: [{ message: "Object-level authorization: you may only request your own id." }] });
    }
  }

  const result = await execute({ schema: GQL_SCHEMA, document, rootValue: buildGqlRoot(session, difficulty), variableValues: req.body.variables });
  const responseText = JSON.stringify(result);

  // --- flag conditions, independent per underlying vulnerability class ---
  // Note: only C.getFlag() is called here (reveals the flag in the
  // response, same as every other server-round-trip lab) — NOT
  // markSolved(). Marking solved happens exclusively via the Report tab's
  // POST /api/validate-lab, same flow as every other lab in the app, so
  // GraphQL labs don't get a shortcut around "prove you can reproduce it."
  const myId = ensureApiUser(session);
  const flags = {};
  if ((/__schema|__type/.test(rawQuery) && responseText.includes("internalDebugNotes")) ||
      (result.errors || []).some((e) => /Did you mean.*internalDebugNotes/i.test(e.message))) {
    flags["graphql-introspection"] = C.getFlag(session, "graphql-introspection", difficulty);
  }
  const othersSsn = API_USERS.filter((u) => u.id !== myId).map((u) => u.ssn);
  if (othersSsn.some((ssn) => responseText.includes(ssn))) {
    flags["graphql-authz-bypass"] = C.getFlag(session, "graphql-authz-bypass", difficulty);
  }
  const otherUser = API_USERS.find((u) => u.id !== myId);
  if (SENSITIVE_FIELDS.slice(1).some((f) => responseText.includes(otherUser[f]))) {
    flags["graphql-excessive-exposure"] = C.getFlag(session, "graphql-excessive-exposure", difficulty);
  }

  if (Object.keys(flags).length) result.extensions = Object.assign({}, result.extensions, { flags });
  res.json(result);
});

function gqlPageHtml(labId, difficulty, title, blurb, examples) {
  return C.renderVulnPage({
    appName: "SecureCorp API — GraphQL", difficulty,
    bodyHtml: `
      <h1>${title}</h1>
      <p class="note">${blurb}</p>
      <label>Query</label>
      <textarea id="q" style="min-height:110px;font-family:monospace;">${examples[0]}</textarea>
      <button onclick="runQuery()">Run Query</button>
      <div class="result" id="out" style="white-space:pre-wrap;"></div>
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      <p class="note">Try also:</p>
      <div class="result">${examples.slice(1).join("\n\n")}</div>
      <script>
        async function runQuery(){
          const query = document.getElementById('q').value;
          const r = await fetch('/graphql?difficulty=${difficulty}', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({query}) });
          const d = await r.json();
          document.getElementById('out').textContent = JSON.stringify(d, null, 2);
          const flag = d.extensions && d.extensions.flags && d.extensions.flags['${labId}'];
          if (flag) {
            const box = document.getElementById('flagBox');
            box.style.display = 'block';
            box.innerHTML = '<strong>🚩 Confirmed.</strong>\\nFLAG: ' + flag;
          }
        }
      </script>
    `
  });
}

router.get("/vuln/graphql-introspection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const examples = difficulty === "easy"
    ? ["{ __schema { types { name fields { name } } } }", "{ __type(name: \"User\") { fields { name } } }"]
    : difficulty === "medium"
    ? ["{ __type(name: \"User\") { fields { name } } }", "# __schema is now blocked (naive substring check) — __type isn't"]
    : ["{ user(id: 1) { internalDebugNote } }", "# Both __schema and __type are properly disabled now.\n# Misspell a field name on purpose and read the suggestion error."];
  res.send(gqlPageHtml("graphql-introspection", difficulty, "GraphQL Schema Introspection", "This is a real GraphQL endpoint (graphql-js). Use introspection to map out fields the app's own UI never shows you.", examples));
});
router.get("/vuln/graphql-authz-bypass", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const examples = difficulty === "easy"
    ? ["{ user(id: 1) { username ssn } }", "{ user(id: 2) { username ssn } }"]
    : difficulty === "medium"
    ? ["{ user(id: 1) { username ssn } }\n# user() is now ownership-checked — try userProfile() instead:", "{ userProfile(id: 1) { username ssn } }"]
    : ["{ user(id: 1) { username ssn } }\n# user() and userProfile() are both fixed now.\n# There's a generic object-lookup field too:", "{ node(id: 1) { username ssn } }"];
  res.send(gqlPageHtml("graphql-authz-bypass", difficulty, "GraphQL Object-Level Authorization (BOLA)", "Query another user's record by id — the same IDOR concept, applied to GraphQL. Your own id isn't shown on purpose; that's the point.", examples));
});
router.get("/vuln/graphql-excessive-exposure", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const examples = difficulty === "easy"
    ? ["{ users { username ssn passwordHash apiKey } }"]
    : difficulty === "medium"
    ? ["{ users { username ssn } }\n# Direct field selection is now blocked — try a fragment instead:", "fragment F on User { ssn passwordHash apiKey }\n{ users { username ...F } }"]
    : ["{ users { username ssn } }\n# users/search are properly field-authorized now (real AST check).\n# The generic node() lookup was never covered by that check:", "{ node(id: 1) { username ssn passwordHash apiKey } }"];
  res.send(gqlPageHtml("graphql-excessive-exposure", difficulty, "GraphQL Excessive Data Exposure", "The user directory search is meant to show public info only. See what the schema actually lets you pull for EVERY user in one request.", examples));
});

// =============================================================================
// WEBSOCKETS — two labs, attached to the SAME underlying http.Server Express
// already listens on (see attachWebSocketServer, called once from server.js
// after app.listen()). Uses the standard `ws` package.
// =============================================================================
const PORT = process.env.PORT || 3000;

function parseCookies(header) {
  const out = {};
  (header || "").split(";").forEach((p) => {
    const idx = p.indexOf("=");
    if (idx === -1) return;
    out[p.slice(0, idx).trim()] = p.slice(idx + 1).trim();
  });
  return out;
}
function sessionFromRequest(req) {
  const sid = parseCookies(req.headers.cookie).sid;
  if (!sid || !C.SESSIONS.has(sid)) return null;
  return C.SESSIONS.get(sid);
}
function queryParam(req, name) {
  try { return new URL(req.url, "http://x").searchParams.get(name); } catch (e) { return null; }
}

// --- /ws/notifications (websocket-no-auth) ----------------------------------
const notificationSockets = new Set();
function handleNotificationsWs(ws, req, difficulty) {
  const session = sessionFromRequest(req);
  if (difficulty !== "easy" && !session) { ws.close(4001, "Authentication required"); return; }
  const myId = session ? ensureApiUser(session) : null;
  notificationSockets.add(ws);
  ws.on("close", () => notificationSockets.delete(ws));
  ws.on("message", (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    if (msg.type === "subscribe") {
      const targetId = Number(msg.targetUserId);
      const allowed = difficulty === "hard" ? targetId === myId : true; // easy/medium: no ownership check on the subscribe target at all
      if (!allowed) { ws.send(JSON.stringify({ type: "error", message: "Not authorized to subscribe to that user." })); return; }
      const target = API_USERS.find((u) => u.id === targetId) || API_USERS[0];
      const feed = ["Password changed from a new device (Lagos, Nigeria)", "New login: Chrome on Windows, IP 41.203.x.x", `Account balance updated: $${(Math.random() * 20000).toFixed(2)}`];
      feed.forEach((n, i) => setTimeout(() => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "notification", forUser: target.username, message: n })); }, i * 150));
      if (targetId !== myId && session) {
        setTimeout(() => ws.send(JSON.stringify({ type: "flag", flag: C.getFlag(session, "websocket-no-auth", difficulty) })), feed.length * 150 + 50);
      }
    }

    if (msg.type === "admin-broadcast") {
      // hard tier: connection-level auth is correct now, but THIS message
      // TYPE was never separately checked for role — a real, distinct gap.
      if (difficulty === "hard") {
        const payload = JSON.stringify({ type: "system-alert", message: String(msg.message || "").slice(0, 200) });
        notificationSockets.forEach((s) => { if (s.readyState === WebSocket.OPEN) s.send(payload); });
        if (session) ws.send(JSON.stringify({ type: "flag", flag: C.getFlag(session, "websocket-no-auth", difficulty) }));
      }
    }
  });
}

// --- /ws/chat (websocket-chat-hijack) ---------------------------------
// A live support-chat widget — the third distinct realistic WebSocket use
// case in this app (notifications feed, wire-transfer terminal, now a
// multi-party chat room), matching upgrade-spec Section 23's own named
// examples ("chat... support... collaboration") rather than being another
// variant of the same "subscribe to a feed" shape as websocket-no-auth.
// The bug here is specifically about ROOM ISOLATION: can a connection
// join and read/write another customer's private support conversation
// just by producing that room's id, with no server-side check that this
// connection actually owns it?
const CHAT_VICTIM_ROOM_IDS = { easy: "4821", medium: "7734", hard: C.randomHex(16) };
const CHAT_ROOMS = {}; // "<difficulty>:<roomId>" -> { messages: [{from, text}] } — namespaced per
// difficulty so practice rooms created while testing one tier never leak
// into another tier's room list (this matters specifically for the hard
// tier's claim-agent-access response, which lists every active room id —
// that list should only ever contain hard-tier rooms).
function chatRoomKey(difficulty, roomId) { return difficulty + ":" + roomId; }
function seedVictimRoom(difficulty) {
  const roomId = CHAT_VICTIM_ROOM_IDS[difficulty];
  const key = chatRoomKey(difficulty, roomId);
  if (!CHAT_ROOMS[key]) {
    CHAT_ROOMS[key] = {
      messages: [
        { from: "agent", text: "Hi! Thanks for reaching out to SecureCorp Support. Can you confirm the last 4 digits of the card on file?" },
        { from: "customer", text: "Sure, it's 4477." },
        { from: "agent", text: "Great, I've located your account (Order #8842). What can I help with today?" },
      ],
    };
  }
  return roomId;
}
function handleChatWs(ws, req, difficulty) {
  const session = sessionFromRequest(req);
  seedVictimRoom(difficulty);
  let joinedRoomId = null;

  ws.on("message", (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    if (msg.type === "join") {
      const roomId = String(msg.roomId || "");
      const key = chatRoomKey(difficulty, roomId);
      if (!CHAT_ROOMS[key]) {
        // Joining a brand-new (not-yet-used) id is treated as starting a
        // fresh conversation — completely normal, expected behavior, not
        // itself a vulnerability. The bug is specifically that THIS check
        // never asks "does the connecting session actually own this
        // room?" for ids that already exist.
        CHAT_ROOMS[key] = { messages: [] };
      }
      joinedRoomId = roomId;
      ws.send(JSON.stringify({ type: "history", roomId, messages: CHAT_ROOMS[key].messages }));
      if (roomId === CHAT_VICTIM_ROOM_IDS[difficulty] && session) {
        ws.send(JSON.stringify({ type: "flag", flag: C.getFlag(session, "websocket-chat-hijack", difficulty) }));
      }
    }

    if (msg.type === "send" && joinedRoomId) {
      const room = CHAT_ROOMS[chatRoomKey(difficulty, joinedRoomId)];
      const text = String(msg.text || "").slice(0, 300);
      room.messages.push({ from: "customer", text });
      ws.send(JSON.stringify({ type: "message", from: "customer", text }));
      setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN) {
          const reply = "Got it, let me take a look and get back to you.";
          room.messages.push({ from: "agent", text: reply });
          ws.send(JSON.stringify({ type: "message", from: "agent", text: reply }));
        }
      }, 250);
    }

    // hard tier's distinct flaw (not "harder to guess", a DIFFERENT gap):
    // the room id itself is genuinely unguessable, but this message type
    // grants an "agent" capability — listing every active room id (for
    // THIS difficulty's namespace only), which then lets the same 'join'
    // handler above reach the victim room anyway. Deliberately never
    // gated by anything: no role check, no session check, nothing.
    if (msg.type === "claim-agent-access" && difficulty === "hard") {
      const prefix = difficulty + ":";
      const roomIds = Object.keys(CHAT_ROOMS).filter((k) => k.startsWith(prefix)).map((k) => k.slice(prefix.length));
      ws.send(JSON.stringify({ type: "agent-access-granted", activeRoomIds: roomIds }));
    }
  });
}

// --- /ws/transfer + /ws/transfer-legacy (websocket-origin-validation) -------
function isRealTrustedOrigin(origin) { return origin === `http://localhost:${PORT}`; }
function originCheckPasses(origin, difficulty) {
  if (difficulty === "easy") return true;
  if (difficulty === "medium") return (origin || "").includes("securecorp-demo.test") || isRealTrustedOrigin(origin);
  return isRealTrustedOrigin(origin);
}
function handleTransferWs(ws, req, difficulty, isLegacyPath) {
  const origin = req.headers.origin || "";
  const passesCheck = isLegacyPath ? true : originCheckPasses(origin, difficulty); // legacy path never checks origin, at any difficulty
  if (!passesCheck) { ws.close(4003, "Origin not allowed: " + origin); return; }
  const session = sessionFromRequest(req);
  const exploitedVector = isLegacyPath || !isRealTrustedOrigin(origin);
  ws.on("message", (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }
    if (msg.action !== "transfer") return;
    const amount = Number(msg.amount) || 0;
    const response = { status: "completed", amount, to: String(msg.to || "").slice(0, 60), newBalance: (12000 - amount).toFixed(2) };
    if (exploitedVector && session) response.flag = C.getFlag(session, "websocket-origin-validation", difficulty);
    ws.send(JSON.stringify(response));
  });
}

function attachWebSocketServer(httpServer) {
  const wss = new WebSocket.Server({ noServer: true });
  httpServer.on("upgrade", (req, socket, head) => {
    let pathname;
    try { pathname = new URL(req.url, "http://x").pathname; } catch (e) { socket.destroy(); return; }
    if (!pathname.startsWith("/ws/")) return; // not ours — let other upgrade handlers (none currently) or default behavior apply
    wss.handleUpgrade(req, socket, head, (ws) => {
      const difficulty = queryParam(req, "difficulty") === "medium" || queryParam(req, "difficulty") === "hard" ? queryParam(req, "difficulty") : "easy";
      if (pathname === "/ws/notifications") handleNotificationsWs(ws, req, difficulty);
      else if (pathname === "/ws/chat") handleChatWs(ws, req, difficulty);
      else if (pathname === "/ws/transfer") handleTransferWs(ws, req, difficulty, false);
      else if (pathname === "/ws/transfer-legacy") handleTransferWs(ws, req, difficulty, true);
      else ws.close(4004, "Unknown endpoint");
    });
  });
}

// Server-side probe used by the websocket-origin-validation lab page: real
// browsers can't set a custom Origin header on a WebSocket handshake (it's
// always the page's genuine origin, non-spoofable — same restriction as
// fetch/XHR). This lets the lab page test "what would happen from a
// different origin" honestly, using a real `ws` client with a real custom
// header — exactly what a researcher would do with a small script, just
// wired up for convenience. The check being exercised is 100% real and
// unmodified: only the "attacker" side is simulated.
router.post("/vuln/websocket-origin-validation/probe", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { sid } = C.getOrInitSession(req, res);
  const simOrigin = String(req.body.simOrigin || "");
  const wsPath = req.body.legacy ? "/ws/transfer-legacy" : "/ws/transfer";
  const client = new WebSocket(`ws://localhost:${PORT}${wsPath}?difficulty=${difficulty}`, { headers: { Origin: simOrigin, Cookie: `sid=${sid}` } });
  let responded = false;
  const finish = (result) => { if (responded) return; responded = true; try { client.close(); } catch (e) {} res.json(result); };
  client.on("open", () => client.send(JSON.stringify({ action: "transfer", amount: 500, to: "attacker-account-9f21" })));
  client.on("message", (raw) => { let msg; try { msg = JSON.parse(raw); } catch (e) { msg = null; } finish({ accepted: true, response: msg }); });
  client.on("unexpected-response", (_req2, res2) => finish({ accepted: false, status: res2.statusCode }));
  client.on("error", () => finish({ accepted: false, status: "rejected" }));
  setTimeout(() => finish({ accepted: false, status: "timeout" }), 3000);
});

router.get("/vuln/websocket-no-auth", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Live Notifications", difficulty,
    bodyHtml: `
      <h1>Live Notifications Feed</h1>
      <p class="note">Connects to a WebSocket endpoint and subscribes to a user's real-time account activity feed.</p>
      <label>Target user id to subscribe to</label>
      <input type="number" id="targetId" value="2" />
      <button onclick="connect()">Connect & Subscribe</button>
      ${difficulty === "hard" ? `<button onclick="sendBroadcast()" style="margin-left:8px;">Send admin-broadcast message</button>` : ""}
      <div class="result" id="out" style="white-space:pre-wrap;min-height:60px;"></div>
      ${difficulty === "easy" ? `<p class="note">No authentication at all is required on this connection — try any target id.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">A valid session cookie is now required to connect — but the subscribe target isn't checked against who you actually are. Try subscribing to an id that isn't yours.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The subscribe target is checked now — try subscribing to your own id first, then try the admin-broadcast button, which isn't gated by role at all.</p>` : ""}
      <script>
        let ws;
        function log(s){ document.getElementById('out').textContent += s + '\\n'; }
        function connect(){
          ws = new WebSocket((location.protocol==='https:'?'wss://':'ws://') + location.host + '/ws/notifications?difficulty=${difficulty}');
          ws.onmessage = (e) => {
            const d = JSON.parse(e.data);
            if (d.type === 'flag') log('🚩 FLAG: ' + d.flag);
            else log(JSON.stringify(d));
          };
          ws.onopen = () => { log('[connected]'); ws.send(JSON.stringify({type:'subscribe', targetUserId: Number(document.getElementById('targetId').value)})); };
          ws.onclose = (e) => log('[closed] ' + e.code + ' ' + e.reason);
        }
        function sendBroadcast(){ if (ws) ws.send(JSON.stringify({type:'admin-broadcast', message:'Unauthorized system-wide alert from a non-admin connection'})); }
      </script>
    `
  }));
});

router.get("/vuln/websocket-chat-hijack", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  let hint;
  if (difficulty === "easy") hint = `Room ids are plain sequential numbers — try nearby values like <code>4820</code>, <code>4821</code>, <code>4822</code>.`;
  else if (difficulty === "medium") hint = `Room ids are 4-digit codes now, not sequential — but that's still a small enough space to try a handful of guesses.`;
  else hint = `Room ids are long random tokens now — realistically not guessable. But nothing checks who's allowed to send a <code>claim-agent-access</code> message...`;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Live Support Chat", difficulty,
    bodyHtml: `
      <h1>Live Support Chat</h1>
      <p class="note">A normal chat widget — starts a fresh conversation automatically. There's also a "resume a previous chat" field for reconnecting to a session you had earlier.</p>
      <div class="result" id="log" style="min-height:100px;white-space:pre-wrap;"></div>
      <label>Message</label>
      <input type="text" id="msgInput" placeholder="Type a message..." />
      <button onclick="send()">Send</button>
      <label style="margin-top:16px;">Resume a previous chat (room id)</label>
      <input type="text" id="roomInput" placeholder="e.g. 4821" />
      <button class="secondary" onclick="resume()">Resume</button>
      <p class="note">${hint}</p>
      ${difficulty === "hard" ? `<button class="secondary" onclick="claimAgent()" style="margin-top:8px;">Debug: claim-agent-access</button>` : ""}
      <script>
        let ws, myRoomId = crypto.randomUUID ? crypto.randomUUID() : String(Math.random());
        function log(s){ document.getElementById('log').textContent += s + '\\n'; }
        function connect(roomId){
          ws = new WebSocket((location.protocol==='https:'?'wss://':'ws://') + location.host + '/ws/chat?difficulty=${difficulty}');
          ws.onopen = () => ws.send(JSON.stringify({type:'join', roomId}));
          ws.onmessage = (e) => {
            const d = JSON.parse(e.data);
            if (d.type === 'flag') log('🚩 FLAG: ' + d.flag);
            else if (d.type === 'history') { log('[joined room ' + d.roomId + ']'); d.messages.forEach(m => log(m.from + ': ' + m.text)); }
            else if (d.type === 'message') log(d.from + ': ' + d.text);
            else if (d.type === 'agent-access-granted') log('[agent access granted] active rooms: ' + d.activeRoomIds.join(', '));
            else log(JSON.stringify(d));
          };
        }
        connect(myRoomId);
        function send(){ const t = document.getElementById('msgInput').value; if (ws && t) ws.send(JSON.stringify({type:'send', text:t})); document.getElementById('msgInput').value=''; }
        function resume(){ const r = document.getElementById('roomInput').value; if (r) connect(r); }
        function claimAgent(){ if (ws) ws.send(JSON.stringify({type:'claim-agent-access'})); }
      </script>
    `
  }));
});

router.get("/vuln/websocket-origin-validation", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Wire Transfer Terminal", difficulty,
    bodyHtml: `
      <h1>Wire Transfer Terminal (WebSocket)</h1>
      <p class="note">This terminal authenticates purely via the ambient session cookie sent automatically during the WebSocket handshake — the same way a browser sends cookies on any same-origin request. That's exactly what makes Cross-Site WebSocket Hijacking possible when the <code>Origin</code> header isn't validated: cookies aren't opt-in for WebSocket like they are for fetch/CORS.</p>
      <p class="note">Real browsers can't forge the Origin header — genuine testing needs a raw client (a small script, wscat, Burp). Use the probe below to test it honestly, exactly the same way.</p>
      <label>Simulated attacker-page Origin</label>
      <input type="text" id="simOrigin" value="https://evil-attacker.test" />
      <div style="margin-top:8px;">
        <button onclick="probe(false)">Probe /ws/transfer</button>
        ${difficulty === "hard" ? `<button onclick="probe(true)" style="margin-left:8px;">Probe /ws/transfer-legacy</button>` : ""}
      </div>
      <div class="result" id="out" style="white-space:pre-wrap;"></div>
      ${difficulty === "easy" ? `<p class="note">No Origin check at all — the probe should succeed immediately.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">Origin must contain "securecorp-demo.test" — try an Origin like <code>https://securecorp-demo.test.evil-attacker.test</code></p>` : ""}
      ${difficulty === "hard" ? `<p class="note">/ws/transfer now validates Origin exactly and correctly. There's also a legacy alias path kept for backwards compatibility — probe that one instead.</p>` : ""}
      <script>
        async function probe(legacy){
          const simOrigin = document.getElementById('simOrigin').value;
          const r = await fetch('/vuln/websocket-origin-validation/probe?difficulty=${difficulty}', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({simOrigin, legacy}) });
          const d = await r.json();
          document.getElementById('out').textContent = JSON.stringify(d, null, 2);
        }
      </script>
    `
  }));
});

// =============================================================================
// REST MASS ASSIGNMENT — a classic, extremely common real-world API bug:
// an update endpoint blindly applies whatever fields the client sends,
// including ones no UI form ever exposes.
// =============================================================================
const MA_ACCOUNTS = new Map(); // sid -> profile record, isolated per session
function maAccount(sid) {
  if (!MA_ACCOUNTS.has(sid)) MA_ACCOUNTS.set(sid, { name: "Jordan Ellis", email: "jordan@example.com", bio: "", role: "user" });
  return MA_ACCOUNTS.get(sid);
}
router.get("/vuln/api-mass-assignment", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { sid } = C.getOrInitSession(req, res);
  const acct = maAccount(sid);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Account API", difficulty,
    bodyHtml: `
      <h1>My Profile</h1>
      <div class="result">${JSON.stringify(acct, null, 2)}</div>
      <p class="note">The UI form only ever submits name/email/bio — inspect what the API actually accepts.</p>
      <div class="result">fetch('/vuln/api-mass-assignment/profile?difficulty=${difficulty}', {method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({role:'admin'})})</div>
      <button onclick="tryIt()">Try the request above</button>
      <div class="result" id="out" style="display:none;"></div>
      ${difficulty === "medium" ? `<p class="note">Top-level fields are now allowlisted (name/email/bio only). There's also a separate bulk-import endpoint for CSV-based profile imports that reuses the same underlying update logic — try <code>POST /vuln/api-mass-assignment/import</code> instead.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both endpoints allowlist correctly now — but the check is case-sensitive ("role") while the field actually gets applied case-insensitively downstream. Try the field name with different casing, e.g. <code>"Role"</code>.</p>` : ""}
      <script>
        async function tryIt(){
          const r = await fetch('/vuln/api-mass-assignment/profile?difficulty=${difficulty}', {method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({role:'admin'})});
          const d = await r.json();
          const out = document.getElementById('out'); out.style.display='block'; out.textContent = JSON.stringify(d, null, 2);
        }
      </script>
    `
  }));
});
function applyMassAssignmentUpdate(acct, body, difficulty, allowNested) {
  if (difficulty === "easy") {
    Object.assign(acct, body); // zero restriction
    return;
  }
  const allowlist = ["name", "email", "bio"];
  if (difficulty === "medium" && !allowNested) {
    allowlist.forEach((k) => { if (body[k] !== undefined) acct[k] = body[k]; });
    return; // properly restricted on THIS endpoint
  }
  if (difficulty === "medium" && allowNested) {
    Object.assign(acct, body); // the forgotten bulk-import path: no allowlist at all
    return;
  }
  // hard: a real denylist explicitly blocks the exact string "role" from
  // ever being applied — but the block only checks that EXACT string; the
  // downstream update logic still recognizes any differently-cased key as
  // the same real field (a genuine, subtle validate/persist case mismatch).
  const denylist = ["role"];
  Object.keys(body).forEach((k) => {
    if (denylist.includes(k)) return; // exact "role" is explicitly, correctly blocked
    if (allowlist.includes(k)) { acct[k] = body[k]; return; }
    if (k.toLowerCase() === "role") acct.role = body[k]; // a differently-cased submission slips past the denylist above but still resolves to the same real column downstream
  });
}
router.patch("/vuln/api-mass-assignment/profile", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session, sid } = C.getOrInitSession(req, res);
  const acct = maAccount(sid);
  applyMassAssignmentUpdate(acct, req.body || {}, difficulty, false);
  const flag = acct.role === "admin" ? C.getFlag(session, "api-mass-assignment", difficulty) : undefined;
  res.json({ profile: acct, flag });
});
router.post("/vuln/api-mass-assignment/import", express.json(), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session, sid } = C.getOrInitSession(req, res);
  const acct = maAccount(sid);
  applyMassAssignmentUpdate(acct, req.body || {}, difficulty, true);
  const flag = acct.role === "admin" ? C.getFlag(session, "api-mass-assignment", difficulty) : undefined;
  res.json({ profile: acct, flag, note: "Bulk import endpoint — intended for CSV-based profile imports." });
});

module.exports = { router, attachWebSocketServer };
