/**
 * tests/route-collisions.test.js — Route Collision Test (upgrade-spec Section 51)
 *
 * Fails if the same HTTP method + path is registered more than once across
 * routes/*.js. This is pure static analysis (no live server needed), so it
 * also catches collisions that would otherwise only silently shadow one
 * another at runtime (Express doesn't error on duplicate GET registrations
 * across two `router.use()`'d routers — it just lets the first-mounted one
 * win, which is a real bug class, not just cosmetic duplication).
 *
 * Only files actually required by server.js are "authoritative" — a
 * leftover, unwired file (e.g. an old *-new.js draft) sitting in routes/
 * but never require()'d is dead code, not a collision. This test enforces
 * that distinction by cross-checking against server.js's require() list
 * rather than just globbing every *.js file in routes/.
 */
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const ROUTES_DIR = path.join(ROOT, "routes");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }

function requiredRouteFiles() {
  const serverSrc = fs.readFileSync(path.join(ROOT, "server.js"), "utf8");
  const re = /require\(\s*["']\.\/routes\/([^"']+)["']\s*\)/g;
  const files = [];
  let m;
  while ((m = re.exec(serverSrc))) {
    let f = m[1];
    if (!f.endsWith(".js")) f += ".js";
    files.push(f);
  }
  return files;
}

function run() {
  const wired = requiredRouteFiles();
  check("server.js wires up at least one route file", wired.length > 0, JSON.stringify(wired));

  // Every file server.js requires must actually exist on disk.
  for (const f of wired) {
    check(`wired route file exists: ${f}`, fs.existsSync(path.join(ROUTES_DIR, f)));
  }

  // Any *.js file sitting in routes/ that is NOT required by server.js is
  // dead code. That's not itself a failure (it might be a work-in-progress
  // file), but it must not be silently double-counted as "live" anywhere —
  // this just surfaces it for visibility.
  const onDisk = fs.readdirSync(ROUTES_DIR).filter((f) => f.endsWith(".js"));
  const unwired = onDisk.filter((f) => !wired.includes(f));
  if (unwired.length) {
    console.log("NOTE: unwired route files present (not part of the live app):", unwired.join(", "));
  }

  const routeRe = /router\.(get|post|put|delete|patch|all)\(\s*["`]([^"`]+)["`]/g;
  const registrations = [];
  for (const f of wired) {
    const src = fs.readFileSync(path.join(ROUTES_DIR, f), "utf8");
    let m;
    while ((m = routeRe.exec(src))) {
      registrations.push({ file: f, method: m[1].toUpperCase(), path: m[2] });
    }
  }
  check("at least one route registration found across wired files", registrations.length > 0, registrations.length);

  const seen = new Map();
  for (const r of registrations) {
    const key = r.method + " " + r.path;
    if (!seen.has(key)) seen.set(key, []);
    seen.get(key).push(r.file);
  }

  let collisions = 0;
  for (const [key, files] of seen.entries()) {
    if (files.length > 1) {
      collisions++;
      console.log("COLLISION:", key, "registered in:", files.join(", "));
    }
  }
  check(`no method+path is registered more than once (${registrations.length} registrations checked)`, collisions === 0, `${collisions} collision(s) found`);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run();
