#!/usr/bin/env node
/**
 * tools/enrich-lab-metadata.js — ONE-TIME migration (upgrade-spec Section
 * 13: centralized lab-model metadata).
 *
 * Adds two fields to every lab entry in public/js/labs-data.js:
 *   tags              — derived mechanically from category + id tokens (+
 *                        "attack-chain"/"client-side-proof" where
 *                        applicable), not hand-invented, so it can't
 *                        silently drift from what a lab actually is.
 *   successCondition  — one of two fixed strings depending on whether the
 *                        lab uses the ordinary server-verified-flag flow
 *                        or the client-proof-token flow (grepped from
 *                        routes/*.js for issueClientProofToken() calls,
 *                        not guessed).
 *
 * CORRECTION (found during this migration's own verification pass, before
 * it shipped): an earlier version of this script also added a `chainId`
 * and a fresh `prerequisites` array per lab. For the 3 "chains"-category
 * labs, that collided with a `locked: true, prerequisites: [...]` field
 * that ALREADY exists later in each of those same lab objects (added in
 * an earlier session — see labs-data.js). JS object literals silently let
 * the later duplicate key win, so the app's actual behavior was never
 * wrong, but the source would have carried two conflicting
 * `prerequisites:` fields in one object, which is exactly the kind of
 * duplication the upgrade spec's Section 5/60 says not to create. Fixed
 * by dropping this script's own chainId/prerequisites entirely — the
 * existing locked/prerequisites mechanism already covers that need, and
 * is more precise than this script's guesses were (it names the exact
 * standalone labs each chain step reuses, e.g. "source-map-leak" +
 * "weak-password" for chain-support-takeover's credential-leak step,
 * not just a generic "info-disclosure"). Richer chain-state metadata is
 * Phase 4's job (upgrade-spec Sections 32-33), building on the existing
 * locked/prerequisites field rather than a second parallel one.
 *
 * This is a SOURCE-TEXT migration, not a JSON.stringify rewrite — it finds
 * each lab's unique `id: "...", category: "...",` header line and inserts
 * one new line directly after it, byte-for-byte preserving every other
 * character in the file (all the hand-authored goal/blurb/reportSummary/
 * solutionSteps content, comments, spacing, and the existing
 * locked/prerequisites field on chain labs). Run once; re-running is safe
 * (it's idempotent — skips any lab that already has a `tags:` field) but
 * this is not part of the regular build like generate-manifest.js is.
 *
 * Usage: node tools/enrich-lab-metadata.js
 */
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const DATA_PATH = path.join(ROOT, "public/js/labs-data.js");
const ROUTES_DIR = path.join(ROOT, "routes");

// Labs whose exploit is entirely client-side and therefore use the
// client-proof-token flow (grepped from routes/*.js — see flag-engine's
// doc comment for the full rationale).
const CLIENT_PROOF_LAB_IDS = new Set([
  "insecure-cookie-flags",
  "cstl",
  "postmessage",
  "prototype-pollution",
  "dom-xss",
  "web-storage-secrets",
]);

const SUCCESS_CONDITION = {
  serverFlag:
    "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
  clientProof:
    "Client-proof token: the client-side exploit must genuinely execute and POST a single-use proof token back to the server, which then issues the real flag.",
};

function buildTags(lab) {
  const tokens = new Set();
  tokens.add(lab.category);
  // The full compound id as one tag (matches how `prerequisites` references
  // other labs, e.g. ["info-disclosure", "idor"] — so a prerequisite id and
  // a tag mean the same string and can cross-reference directly), PLUS its
  // individual hyphen-split tokens (so a keyword search for just "sql" or
  // "privesc" still finds it without requiring the exact compound id).
  tokens.add(lab.id);
  lab.id.split("-").forEach((t) => t && tokens.add(t));
  if (lab.category === "chains") tokens.add("attack-chain");
  if (CLIENT_PROOF_LAB_IDS.has(lab.id)) tokens.add("client-side-proof");
  return Array.from(tokens);
}

function jsArrayLiteral(arr) {
  return "[" + arr.map((s) => JSON.stringify(s)).join(", ") + "]";
}

function main() {
  const LABS_DATA = require(DATA_PATH);
  let src = fs.readFileSync(DATA_PATH, "utf8");

  if (/\n\s*tags:\s*\[/.test(src)) {
    console.log("labs-data.js already has tags: fields — nothing to do (idempotent skip).");
    return;
  }

  let inserted = 0;
  for (const lab of LABS_DATA.labs) {
    const idLit = JSON.stringify(lab.id);
    const catLit = JSON.stringify(lab.category);
    const headerNeedle = `id: ${idLit}, category: ${catLit},`;
    const idx = src.indexOf(headerNeedle);
    if (idx === -1) {
      console.error(`⚠️  Could not find header line for lab "${lab.id}" — skipping (leaving it unenriched).`);
      continue;
    }
    // Find the end of that header LINE (it continues with title/shortTitle
    // on the same physical line), then insert a new line right after it.
    const lineEnd = src.indexOf("\n", idx);
    if (lineEnd === -1) {
      console.error(`⚠️  Unexpected EOF right after header for lab "${lab.id}" — skipping.`);
      continue;
    }

    const tags = buildTags(lab);
    const successCondition = CLIENT_PROOF_LAB_IDS.has(lab.id) ? SUCCESS_CONDITION.clientProof : SUCCESS_CONDITION.serverFlag;

    const newLine = `\n        tags: ${jsArrayLiteral(tags)},\n        successCondition: ${JSON.stringify(successCondition)},`;

    src = src.slice(0, lineEnd) + newLine + src.slice(lineEnd);
    inserted++;
  }

  fs.writeFileSync(DATA_PATH, src);
  console.log(`Inserted centralized metadata (tags/successCondition) into ${inserted}/${LABS_DATA.labs.length} labs.`);
}

main();
