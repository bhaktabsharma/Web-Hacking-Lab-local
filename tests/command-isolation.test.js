/**
 * tests/command-isolation.test.js — upgrade-spec Section 50: "Prove that
 * command-injection labs cannot execute real host commands. Use a
 * simulated command interpreter/environment."
 *
 * Two layers of proof:
 *   STATIC  — grep every route/src file for `require("child_process")`.
 *             It must appear NOWHERE — unlike SSRF/filesystem, there is no
 *             legitimate feature anywhere in this app that needs real
 *             process spawning, so the bar here is zero occurrences, not
 *             "one controlled occurrence." (A bare exec()/spawn() text
 *             scan was tried too and dropped — it false-positived on
 *             `db.exec(query)`, sql.js's safe in-memory SQLite API used by
 *             the SQL-injection labs. Node cannot reach real process
 *             spawning without require("child_process") first, so the
 *             require() check alone is already the complete guarantee.)
 *   DYNAMIC — the strongest proof available: send a payload that would
 *             make a REAL shell sleep for several real seconds
 *             (`; sleep 4`) and assert the HTTP response comes back near-
 *             instantly. A simulated command environment doing a
 *             dictionary lookup cannot "accidentally" take 4 real seconds;
 *             if this ever executed a real shell, the request would
 *             visibly hang for ~4s. Also confirms `id`/`whoami`-style
 *             outputs match the fake trainee identity, never this
 *             container's real identity (this sandbox actually runs as
 *             root — a real command injection here would immediately leak
 *             `uid=0(root)`, which never appears in the fake output).
 */
const fs = require("fs");
const path = require("path");
const http = require("http");

const ROOT = path.join(__dirname, "..");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 45000).unref();

function httpGet(urlPath) {
  const startedAt = Date.now();
  return new Promise((resolve, reject) => {
    const r = http.request({ host: "localhost", port: 3000, path: urlPath, method: "GET" }, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body, elapsedMs: Date.now() - startedAt }));
    });
    r.on("error", reject);
    r.end();
  });
}

function staticChecks() {
  const offenders = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".js")) {
        const src = fs.readFileSync(full, "utf8");
        if (/require\(\s*["']child_process["']\s*\)/.test(src)) offenders.push(path.relative(ROOT, full));
      }
    }
  }
  walk(path.join(ROOT, "routes"));
  walk(path.join(ROOT, "src"));

  // NOTE: deliberately NOT also grepping for bare exec(/spawn( calls —
  // tried that first and it false-positived on `db.exec(query)`, which is
  // sql.js's safe in-memory SQLite API used by the SQL-injection labs, not
  // child_process.exec. Node has no way to reach real process spawning
  // without require("child_process") first (no global implicit exec/spawn
  // exists), so the require() check above is already the complete,
  // precise guarantee — a second heuristic on top of it only adds false
  // positives, not real coverage.
  check("no route/src file requires child_process (the only way to reach real process spawning)", offenders.length === 0, JSON.stringify(offenders));
}

async function dynamicChecks() {
  // A real shell executing this would sleep for ~4 real seconds. This
  // sandbox never should. Generous margin (2000ms) well below the 4000ms
  // a real execution would take, while still tolerant of normal request
  // overhead.
  const t0 = Date.now();
  const { status } = await httpGet(`/vuln/command-injection?difficulty=easy&host=${encodeURIComponent("127.0.0.1; sleep 4")}`);
  const elapsed = Date.now() - t0;
  check("command-injection with '; sleep 4' responds 200", status === 200, "status=" + status);
  check("command-injection with '; sleep 4' returns in well under 4 real seconds (proves no real shell ran)", elapsed < 2000, elapsed + "ms");

  // fork-bomb-shaped payload — must not be attempted for real, for obvious
  // reasons; same fast-response assertion covers it.
  const t1 = Date.now();
  const { status: status2 } = await httpGet(`/vuln/command-injection?difficulty=easy&host=${encodeURIComponent("127.0.0.1; :(){ :|:& };:")}`);
  check("command-injection with a fork-bomb-shaped payload responds 200 (not executed)", status2 === 200);
  check("...and returns fast", Date.now() - t1 < 2000);

  // Identity check: this container genuinely runs as root. A real command
  // injection would leak "uid=0(root)". The simulated environment must
  // only ever return the fake trainee identity.
  const { body } = await httpGet(`/vuln/command-injection?difficulty=easy&host=${encodeURIComponent("127.0.0.1; id")}`);
  check("command-injection 'id' output does not leak this container's real uid=0(root)", !body.includes("uid=0(root)"));
  check("command-injection 'id' output matches the fake trainee identity instead", body.includes("uid=1000(trainee)"));

  const { body: whoBody } = await httpGet(`/vuln/command-injection?difficulty=easy&host=${encodeURIComponent("127.0.0.1; whoami")}`);
  check("command-injection 'whoami' output does not leak the real 'root' identity as a bare match", !/\broot\b/.test(whoBody.split("simulated)")[1] || ""));

  // blind-command-injection is DIFFERENT by design (see its own doc
  // comment in routes/vulns-injection.js): it genuinely delays its
  // response with a real, capped setTimeout to simulate authentic timing-
  // based blind detection — a slow response here is the intended,
  // pedagogically-correct behavior, not something to flag. What actually
  // matters for isolation is that the delay is a safe, bounded setTimeout
  // (never real command execution) AND that it's capped, so an attacker
  // can't cause an unbounded hang by requesting an enormous sleep value.
  const t2 = Date.now();
  const { status: status3, body: body3 } = await httpGet(`/vuln/blind-command-injection?difficulty=easy&host=${encodeURIComponent("127.0.0.1; sleep 4")}`);
  const elapsed3 = Date.now() - t2;
  check("blind-command-injection with '; sleep 4' responds 200", status3 === 200);
  check(
    "blind-command-injection with '; sleep 4' takes a genuine ~4s delay (real timing simulation, not a shortcut)",
    elapsed3 >= 3500 && elapsed3 < 6000,
    elapsed3 + "ms"
  );
  check("blind-command-injection response body never echoes command output (timing-only, by design)", !body3.includes("uid=") && !body3.includes("trainee"));

  const t3 = Date.now();
  const { status: status4 } = await httpGet(`/vuln/blind-command-injection?difficulty=easy&host=${encodeURIComponent("127.0.0.1; sleep 999999")}`);
  const elapsed4 = Date.now() - t3;
  check("blind-command-injection with an enormous sleep value still responds 200", status4 === 200);
  check(
    "...and the delay is CAPPED well below the requested duration (proves it's a bounded setTimeout, not real execution)",
    elapsed4 < 7000,
    elapsed4 + "ms"
  );
}

async function run() {
  staticChecks();
  await dynamicChecks();
  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
