/**
 * tests/lab-metadata.test.js — centralized lab-model metadata (upgrade-spec
 * Section 13). Covers the two fields added in the Phase 1 migration
 * (tools/enrich-lab-metadata.js) plus a referential-integrity check on the
 * pre-existing `locked`/`prerequisites` chain-gating field — the exact
 * kind of check that would have caught the duplicate-key bug found and
 * fixed during that migration's own verification pass (see
 * docs/UPGRADE-LOG.md) before it ever reached this file.
 */
const path = require("path");
const data = require(path.join(__dirname, "..", "public", "js", "labs-data.js"));

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }

function run() {
  const idSet = new Set(data.labs.map((l) => l.id));

  for (const lab of data.labs) {
    check(`[${lab.id}] has a tags array`, Array.isArray(lab.tags) && lab.tags.length > 0);
    check(`[${lab.id}] tags includes its own id`, Array.isArray(lab.tags) && lab.tags.includes(lab.id));
    check(`[${lab.id}] tags includes its category`, Array.isArray(lab.tags) && lab.tags.includes(lab.category));
    check(`[${lab.id}] has a non-empty successCondition string`, typeof lab.successCondition === "string" && lab.successCondition.length > 10);
  }

  // Referential integrity on the pre-existing chain-lock mechanism: every
  // id a "locked" lab lists as a prerequisite must actually exist in the
  // registry. This is what would have caught a stale/invented prerequisite
  // id immediately instead of silently shipping one.
  //
  // NOTE: "locked" labs come in two flavors, both intentional (confirmed
  // against public/js/app.js line ~90):
  //   - the 3 attack-chain labs list an explicit `prerequisites` array
  //   - the "final" lab is `locked: true` with NO `prerequisites` array on
  //     purpose — app.js falls back to "every non-locked lab must be
  //     solved first" when prerequisites is absent (a genuine "solve
  //     everything" gate, not a missing field). See the comment above the
  //     chain labs in labs-data.js.
  const lockedLabs = data.labs.filter((l) => l.locked);
  check("at least one lab uses the locked gate (sanity check on the test itself)", lockedLabs.length > 0, lockedLabs.length);

  const explicitPrereqLabs = lockedLabs.filter((l) => l.id !== "final");
  for (const lab of explicitPrereqLabs) {
    check(`[${lab.id}] locked lab has a non-empty prerequisites array`, Array.isArray(lab.prerequisites) && lab.prerequisites.length > 0);
    if (Array.isArray(lab.prerequisites)) {
      for (const prereqId of lab.prerequisites) {
        check(`[${lab.id}] prerequisite "${prereqId}" exists in the registry`, idSet.has(prereqId));
      }
    }
  }

  const finalLab = data.labs.find((l) => l.id === "final");
  check("'final' lab exists and is locked", !!finalLab && !!finalLab.locked);
  check("'final' lab intentionally has no explicit prerequisites (uses the solve-everything fallback in app.js)", !finalLab.prerequisites);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run();
