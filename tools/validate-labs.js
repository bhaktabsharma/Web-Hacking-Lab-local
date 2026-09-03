#!/usr/bin/env node
/**
 * tools/validate-labs.js — Lab Registry Validator
 *
 * Walks every lab in public/js/labs-data.js and verifies it against the
 * REAL running application (not just the metadata file in isolation).
 * This is the "lab-registry validator" from the upgrade spec's Section 3,
 * scoped to what this app's actual architecture supports:
 *
 *   ✓ unique id                  — no two labs share an id
 *   ✓ valid category             — category exists in the categories list
 *   ✓ metadata completeness      — title, blurb, inputContext, goal.mission,
 *                                   why, fix, answerPlaceholder all present
 *   ✓ difficulty coverage        — difficultyNotes/reportSummary/reportImpact/
 *                                   solutionSteps all define easy/medium/hard
 *                                   (or the lab is explicitly flagged as a
 *                                   locked/chained special case, e.g. "final")
 *   ✓ route exists & responds    — a live GET /vuln/<id> returns 200 or 302
 *                                   against the actual running server
 *   ✓ flag generation exists     — the route source actually calls
 *                                   C.getFlag(session, "<id>", ...) — this
 *                                   catches id/route mismatches a metadata
 *                                   file alone can never catch
 *   ✓ reset is structurally sound — reset is centralized (routes/reset-and-
 *                                   validate.js works for any labId via
 *                                   C.resetLabState), so this checks that
 *                                   IF the lab keeps session state via
 *                                   C.labState(...), it does so under the
 *                                   SAME id used everywhere else — a state
 *                                   key mismatch would silently break reset.
 *
 * Usage:
 *   node server.js &          (server must already be running on :3000)
 *   node tools/validate-labs.js
 *
 * Exits 0 if every lab passes, 1 otherwise — safe to wire into CI or a
 * pre-commit hook later.
 */
const fs = require("fs");
const path = require("path");
const http = require("http");

const ROOT = path.join(__dirname, "..");
const LABS_DATA = require(path.join(ROOT, "public/js/labs-data.js"));
const ROUTES_DIR = path.join(ROOT, "routes");

// Concatenate all route source once, so per-lab checks are simple substring
// tests against the real source of truth rather than re-reading files.
const ALL_ROUTE_SOURCE = fs
  .readdirSync(ROUTES_DIR)
  .filter((f) => f.endsWith(".js"))
  .map((f) => fs.readFileSync(path.join(ROUTES_DIR, f), "utf8"))
  .join("\n// ---- next file ----\n");

function httpGet(urlPath) {
  return new Promise((resolve) => {
    const req = http.request({ host: "localhost", port: 3000, path: urlPath, method: "GET" }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.setTimeout(3000, () => { req.destroy(); resolve("TIMEOUT"); });
    req.on("error", () => resolve("CONN_ERROR"));
    req.end();
  });
}

const results = []; // { id, ok, problems: [] }

async function validateLab(lab, categoryIds) {
  const problems = [];

  // --- category ---
  if (!categoryIds.has(lab.category)) problems.push(`category "${lab.category}" is not in the registered categories list`);

  // --- metadata completeness ---
  const requiredStringFields = ["id", "category", "title", "blurb", "inputContext", "why", "fix", "answerPlaceholder"];
  for (const f of requiredStringFields) {
    if (!lab[f] || typeof lab[f] !== "string" || !lab[f].trim()) problems.push(`missing/empty required field "${f}"`);
  }
  if (!lab.goal || !Array.isArray(lab.goal.mission) || lab.goal.mission.length === 0) {
    problems.push(`goal.mission must be a non-empty array (the lab has no stated objective)`);
  }
  if (!lab.goal || !lab.goal.explain) problems.push(`goal.explain is missing`);

  // --- difficulty coverage ---
  // "final" and any lab explicitly marked `locked: true` are allowed to use
  // a different shape (chained scenario, single non-tiered answer) rather
  // than the standard easy/medium/hard triplet.
  if (!lab.locked) {
    const tieredFields = ["difficultyNotes", "reportSummary", "reportImpact", "solutionSteps"];
    for (const f of tieredFields) {
      const obj = lab[f];
      if (!obj || typeof obj !== "object") { problems.push(`"${f}" is missing entirely`); continue; }
      for (const tier of ["easy", "medium", "hard"]) {
        const v = obj[tier];
        const empty = Array.isArray(v) ? v.length === 0 : !v || !String(v).trim();
        if (empty) problems.push(`"${f}.${tier}" is missing/empty`);
      }
    }
  }

  // --- live route check ---
  const status = await httpGet("/vuln/" + lab.id);
  if (status !== 200 && status !== 302) problems.push(`GET /vuln/${lab.id} returned ${status} (expected 200 or 302) — is the server running on :3000?`);

  // --- flag generation exists in source, under the SAME id ---
  // Direct issuance: C.getFlag(session, "<id>", ...). Client-proof pattern
  // (Phase 2): C.issueClientProofToken(session, "<id>", ...) followed by
  // C.confirmClientProof(...) — used by labs whose exploit is entirely
  // client-side, where the flag is only ever handed out via
  // POST /api/confirm-client-exploit rather than embedded at page load.
  const directFlagPattern = new RegExp(`getFlag\\(\\s*session\\s*,\\s*["']${lab.id}["']`);
  const clientProofPattern = new RegExp(`issueClientProofToken\\(\\s*session\\s*,\\s*["']${lab.id}["']`);
  const hasFlagCall = directFlagPattern.test(ALL_ROUTE_SOURCE) || clientProofPattern.test(ALL_ROUTE_SOURCE);
  if (!hasFlagCall && !lab.locked) {
    problems.push(`no "C.getFlag(session, "${lab.id}", ...)" or "C.issueClientProofToken(session, "${lab.id}", ...)" call found in routes/ — this lab may never actually issue a flag`);
  }

  // --- reset consistency: if the lab keeps state via C.labState(session, id, ...), the id used must match lab.id exactly ---
  const labStatePattern = new RegExp(`labState\\(\\s*session\\s*,\\s*["']([a-z0-9-]+)["']`, "g");
  let m, usesLabStateUnderWrongId = false;
  // Only meaningful within this lab's own "section" of source is hard without
  // AST parsing; as a practical proxy we confirm that WHEREVER this lab's id
  // is used as a labState key, it's spelled identically (case/hyphenation)
  // everywhere flag/labState calls reference it — catches the most common
  // real mistake (a typo'd id that silently creates a second, unreset-able
  // state bucket).
  while ((m = labStatePattern.exec(ALL_ROUTE_SOURCE))) {
    const key = m[1];
    if (key.toLowerCase() === lab.id.toLowerCase() && key !== lab.id) usesLabStateUnderWrongId = true;
  }
  if (usesLabStateUnderWrongId) problems.push(`found a labState(...) call using a differently-cased/hyphenated variant of id "${lab.id}" — reset would not clear it correctly`);

  results.push({ id: lab.id, ok: problems.length === 0, problems });
}

async function main() {
  const categoryIds = new Set(LABS_DATA.categories.map((c) => c.id));

  // duplicate id check across the whole registry, up front
  const ids = LABS_DATA.labs.map((l) => l.id);
  const dupes = [...new Set(ids.filter((id, i) => ids.indexOf(id) !== i))];

  for (const lab of LABS_DATA.labs) await validateLab(lab, categoryIds);

  const failed = results.filter((r) => !r.ok);
  console.log(`\nLab Registry Validation — ${LABS_DATA.labs.length} labs checked\n${"=".repeat(60)}`);
  if (dupes.length) console.log(`❌ DUPLICATE IDS: ${dupes.join(", ")}\n`);

  for (const r of results) {
    if (!r.ok) {
      console.log(`❌ ${r.id}`);
      r.problems.forEach((p) => console.log(`   - ${p}`));
    }
  }

  console.log(`${"=".repeat(60)}`);
  console.log(`${results.length - failed.length}/${results.length} labs passed validation.`);
  if (dupes.length || failed.length) {
    console.log(`FAILED — fix the issues above before shipping.`);
    process.exit(1);
  } else {
    console.log(`ALL LABS VALID.`);
    process.exit(0);
  }
}

main().catch((e) => { console.error("VALIDATOR CRASHED:", e); process.exit(1); });
