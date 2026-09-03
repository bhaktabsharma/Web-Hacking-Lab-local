/**
 * tests/websocket-chat-hijack.test.js — Phase 3 addition (upgrade-spec
 * Section 23: realistic WebSocket use cases — "chat... support...
 * collaboration"). Covers routes/vulns-api.js's handleChatWs across all 3
 * difficulty tiers, using a real `ws` client against the live server —
 * the same honest-testing approach as the pre-existing WebSocket labs.
 *
 * Uses a persistent-message-collector pattern (attach one listener, wait,
 * then inspect everything received) rather than sequential attach/detach
 * `once()` calls — the latter has a real race condition when a server
 * sends two messages back-to-back synchronously (as this lab's join
 * handler does: history then flag), where a listener removed after the
 * first match can miss the second message entirely. Documented here
 * because it's exactly the bug this test suite's own first draft had.
 */
const http = require("http");
const WebSocket = require("ws");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function getSessionCookie(difficulty) {
  return new Promise((resolve) => {
    http.get(`http://localhost:3000/vuln/websocket-chat-hijack?difficulty=${difficulty}`, (res) => {
      res.resume();
      const setCookie = res.headers["set-cookie"] || [];
      const line = setCookie.find((c) => c.startsWith("sid="));
      resolve(line ? line.split(";")[0] : null);
    });
  });
}
function connect(difficulty, cookie) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:3000/ws/chat?difficulty=${difficulty}`, cookie ? { headers: { Cookie: cookie } } : undefined);
    const received = [];
    ws.on("message", (raw) => { try { received.push(JSON.parse(raw)); } catch (e) {} });
    ws.once("open", () => resolve({ ws, received }));
    ws.once("error", reject);
  });
}
function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function testGuessableTier(difficulty, victimRoomId) {
  const cookie = await getSessionCookie(difficulty);
  check(`[${difficulty}] a session cookie was issued`, !!cookie);

  // --- joining a brand-new room is normal, no flag --------------------
  const { ws: wsFresh, received: rFresh } = await connect(difficulty, cookie);
  wsFresh.send(JSON.stringify({ type: "join", roomId: `fresh-${difficulty}-${Date.now()}` }));
  await wait(400);
  const histFresh = rFresh.find((m) => m.type === "history");
  check(`[${difficulty}] joining a brand-new room returns empty history`, !!histFresh && histFresh.messages.length === 0);
  check(`[${difficulty}] joining a brand-new room issues no flag`, !rFresh.find((m) => m.type === "flag"));
  wsFresh.close();

  // --- the actual vulnerability: guess/produce the victim's room id ---
  const { ws, received } = await connect(difficulty, cookie);
  ws.send(JSON.stringify({ type: "join", roomId: victimRoomId }));
  await wait(400);
  const hist = received.find((m) => m.type === "history");
  check(`[${difficulty}] joining the victim's room returns their real conversation history`, !!hist && hist.messages.length === 3, hist);
  check(`[${difficulty}] the leaked history contains the seeded PII (last-4 digits)`, hist.messages.some((m) => m.text.includes("4477")));
  const flag = received.find((m) => m.type === "flag");
  check(`[${difficulty}] a real flag is issued once the victim room is reached`, !!flag && new RegExp(`^FLAG\\{websocket-chat-hijack-${difficulty}-`).test(flag.flag), JSON.stringify(flag));
  ws.close();
}

async function testHardTier() {
  const difficulty = "hard";
  const cookie = await getSessionCookie(difficulty);
  check(`[${difficulty}] a session cookie was issued`, !!cookie);

  const { ws: wsFresh, received: rFresh } = await connect(difficulty, cookie);
  wsFresh.send(JSON.stringify({ type: "join", roomId: `fresh-${difficulty}-${Date.now()}` }));
  await wait(400);
  check(`[${difficulty}] joining a brand-new room returns empty history`, (rFresh.find((m) => m.type === "history") || {}).messages && rFresh.find((m) => m.type === "history").messages.length === 0);
  wsFresh.close();

  // Direct guessing must fail — the id is unguessable.
  const { ws, received } = await connect(difficulty, cookie);
  ws.send(JSON.stringify({ type: "join", roomId: "4821" })); // easy tier's id — deliberately wrong here
  await wait(400);
  check(`[${difficulty}] guessing an unrelated/wrong room id issues no flag`, !received.find((m) => m.type === "flag"));

  // The real hard-tier flaw: unauthenticated role escalation leaks the
  // actual (otherwise unguessable) victim room id.
  ws.send(JSON.stringify({ type: "claim-agent-access" }));
  await wait(400);
  const leak = received.find((m) => m.type === "agent-access-granted");
  check(`[${difficulty}] claim-agent-access is accepted with no auth/role check at all`, !!leak);
  const victimRoomId = leak && leak.activeRoomIds.find((id) => id.length > 20 && id !== "4821");
  check(`[${difficulty}] the leaked list includes a genuinely long, unguessable room id (the real victim room)`, !!victimRoomId, leak);

  ws.send(JSON.stringify({ type: "join", roomId: victimRoomId }));
  await wait(400);
  const hist = received.filter((m) => m.type === "history").pop();
  check(`[${difficulty}] joining the leaked id returns the victim's real conversation`, !!hist && hist.messages.length === 3);
  const flag = received.find((m) => m.type === "flag");
  check(`[${difficulty}] using the leaked id to join yields a real flag`, !!flag && new RegExp(`^FLAG\\{websocket-chat-hijack-${difficulty}-`).test(flag.flag), JSON.stringify(flag));
  ws.close();

  // claim-agent-access must NOT work at easy/medium (different flaw shape,
  // deliberately scoped to hard tier only).
  const cookieEasy = await getSessionCookie("easy");
  const { ws: wsEasy, received: rEasy } = await connect("easy", cookieEasy);
  wsEasy.send(JSON.stringify({ type: "claim-agent-access" }));
  await wait(300);
  check("claim-agent-access at EASY tier is a no-op (that flaw is hard-tier-specific)", !rEasy.find((m) => m.type === "agent-access-granted"));
  wsEasy.close();
}

async function testRoomNamespacingAndChat() {
  // Rooms are namespaced per-difficulty internally — sending a chat
  // message and getting a simulated agent reply should work independent
  // of any of the above.
  const cookie = await getSessionCookie("easy");
  const { ws, received } = await connect("easy", cookie);
  const roomId = "chat-flow-" + Date.now();
  ws.send(JSON.stringify({ type: "join", roomId }));
  await wait(150);
  ws.send(JSON.stringify({ type: "send", text: "Hello, I need help." }));
  await wait(500);
  const echoed = received.find((m) => m.type === "message" && m.from === "customer");
  const agentReply = received.find((m) => m.type === "message" && m.from === "agent");
  check("sending a chat message echoes back to the sender", !!echoed && echoed.text === "Hello, I need help.");
  check("a simulated agent reply follows shortly after", !!agentReply);
  ws.close();
}

async function run() {
  await testGuessableTier("easy", "4821");
  await testGuessableTier("medium", "7734");
  await testHardTier();
  await testRoomNamespacingAndChat();

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
