#!/usr/bin/env node
/**
 * tools/generate-manifest.js — Existing-Lab Compatibility Manifest generator
 *
 * Produces data/existing-labs-manifest.json: a machine-readable snapshot of
 * every lab currently in the registry (public/js/labs-data.js), cross-
 * referenced against the actual route source in routes/*.js.
 *
 * WHY THIS EXISTS (upgrade-spec Section 4):
 *   Every future upgrade must be checked against this file. If a lab that
 *   was "preserved" in the manifest is missing afterwards, the regression
 *   test in tests/existing-labs-regression.test.js fails the build. This is
 *   how "never remove an existing lab" gets enforced mechanically instead
 *   of relying on memory or code review catching it.
 *
 * ADAPTATION NOTE: the spec's example schema has a single "difficulty"
 * field per lab record. This app's actual architecture (confirmed by
 * auditing routes/ and public/js/labs-data.js) has ONE lab entry serving
 * MULTIPLE difficulty tiers via a shared route + ?difficulty= param/cookie
 * (see difficultyOf() in routes/vuln-common.js), not one registry row per
 * tier. So this manifest records a "difficulties" array per lab (which
 * tiers actually exist and are covered by difficultyNotes/reportSummary/
 * reportImpact/solutionSteps) rather than forcing a single value — that
 * keeps the manifest an accurate reflection of the real registry instead
 * of a fictionalized one.
 *
 * Usage:
 *   node tools/generate-manifest.js            (writes data/existing-labs-manifest.json)
 *   node tools/generate-manifest.js --check    (exits 1 if regenerating would change the file)
 */
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const LABS_DATA = require(path.join(ROOT, "public/js/labs-data.js"));
const ROUTES_DIR = path.join(ROOT, "routes");
const OUT_PATH = path.join(ROOT, "data", "existing-labs-manifest.json");

const DIFFICULTY_TIERS = ["easy", "medium", "hard", "expert"];

// Route files that are actually wired into server.js. Anything else in
// routes/ (e.g. a leftover *-new.js) is NOT authoritative and must not be
// treated as evidence a route exists.
const AUTHORITATIVE_FILES = fs
  .readdirSync(ROUTES_DIR)
  .filter((f) => f.endsWith(".js") && !/-new\.js$/.test(f));

function loadRouteSource() {
  return AUTHORITATIVE_FILES.map((f) => ({
    file: f,
    src: fs.readFileSync(path.join(ROUTES_DIR, f), "utf8"),
  }));
}

function findRoutesForLab(labId, files) {
  // Matches router.<method>("/vuln/<labId>"...) and any nested sub-route
  // like /vuln/<labId>/profile, /vuln/<labId>/login, etc.
  const re = new RegExp(
    `router\\.(get|post|put|delete|patch|all)\\(\\s*["\`](\\/vuln\\/${labId}(?:\\/[^"\`]*)?)["\`]`,
    "g"
  );
  const found = [];
  for (const { file, src } of files) {
    let m;
    while ((m = re.exec(src))) {
      found.push({ method: m[1].toUpperCase(), path: m[2], file });
    }
  }
  return found;
}

function difficultyCoverage(lab) {
  const covered = {};
  for (const tier of DIFFICULTY_TIERS) {
    const inNotes = lab.difficultyNotes && Object.prototype.hasOwnProperty.call(lab.difficultyNotes, tier);
    const inSummary = lab.reportSummary && Object.prototype.hasOwnProperty.call(lab.reportSummary, tier);
    const inImpact = lab.reportImpact && Object.prototype.hasOwnProperty.call(lab.reportImpact, tier);
    const inSteps = lab.solutionSteps && Object.prototype.hasOwnProperty.call(lab.solutionSteps, tier);
    if (inNotes || inSummary || inImpact || inSteps) covered[tier] = true;
  }
  return Object.keys(covered);
}

function build() {
  const files = loadRouteSource();
  const manifest = {
    generatedAt: new Date().toISOString(),
    schemaNote:
      "Adapted from upgrade-spec Section 4: 'difficulty' is a 'difficulties' array because one lab entry serves multiple tiers via a shared route, not one row per tier.",
    totalLabs: LABS_DATA.labs.length,
    totalCategories: LABS_DATA.categories.length,
    categories: LABS_DATA.categories,
    labs: [],
  };

  for (const lab of LABS_DATA.labs) {
    const routes = findRoutesForLab(lab.id, files);
    // Prefer the bare GET /vuln/<id> entry point as "primary" (that's the
    // one a learner actually lands on, and the one tools/validate-labs.js
    // already checks). Fall back to any GET route, then to whatever's
    // first, rather than blindly taking routes[0] — a POST-only sub-route
    // (e.g. an AJAX probe endpoint) is not a valid GET entry point even if
    // it happens to appear earlier in the source file.
    const bareGet = routes.find((r) => r.method === "GET" && r.path === `/vuln/${lab.id}`);
    const anyGet = routes.find((r) => r.method === "GET");
    const primary = bareGet || anyGet || routes[0] || null;

    manifest.labs.push({
      id: lab.id,
      slug: lab.id,
      category: lab.category,
      title: lab.title,
      demoApp: lab.demoApp || null,
      difficulties: difficultyCoverage(lab),
      routes: routes.map((r) => ({ method: r.method, path: r.path })),
      primaryRoute: primary ? primary.path : null,
      primaryMethod: primary ? primary.method : null,
      routeFile: primary ? primary.file : null,
      hasWorkingRoute: routes.length > 0,
      status: "preserved",
    });
  }

  return manifest;
}

function main() {
  const checkOnly = process.argv.includes("--check");
  const manifest = build();
  const json = JSON.stringify(manifest, null, 2) + "\n";

  if (checkOnly) {
    if (!fs.existsSync(OUT_PATH)) {
      console.error("❌ No manifest exists yet at data/existing-labs-manifest.json — run without --check first.");
      process.exit(1);
    }
    const existing = fs.readFileSync(OUT_PATH, "utf8");
    // Ignore the generatedAt timestamp when diffing for --check.
    const strip = (s) => s.replace(/"generatedAt": ".*?",\n/, "");
    if (strip(existing) !== strip(json)) {
      console.error("❌ Manifest is out of date. Run: node tools/generate-manifest.js");
      process.exit(1);
    }
    console.log("✅ Manifest matches current registry (" + manifest.totalLabs + " labs).");
    process.exit(0);
  }

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, json);

  const withoutRoutes = manifest.labs.filter((l) => !l.hasWorkingRoute);
  console.log(`Manifest written: ${OUT_PATH}`);
  console.log(`  Total labs recorded: ${manifest.totalLabs}`);
  console.log(`  Categories: ${manifest.totalCategories}`);
  if (withoutRoutes.length) {
    console.log(`  ⚠️  ${withoutRoutes.length} lab(s) with NO route match found (needs manual check):`);
    withoutRoutes.forEach((l) => console.log("     - " + l.id));
  } else {
    console.log("  ✅ Every lab resolved to at least one live route.");
  }
}

main();
