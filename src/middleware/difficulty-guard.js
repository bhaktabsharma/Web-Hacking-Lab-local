/**
 * src/middleware/difficulty-guard.js — Express middleware enforcing
 * upgrade-spec Section 15: "Do not silently convert invalid difficulty to
 * Easy. Return a proper error."
 *
 * FOUND DURING A PHASE 7 ACCEPANCE-CRITERIA AUDIT: before this fix, ANY
 * unrecognized difficulty value silently fell back to "easy" inside
 * src/utils/difficulty.js's difficultyOf() — including "expert" (not
 * implemented anywhere in this build) and genuine typos/garbage values.
 * That's a direct, confirmed violation of Section 15's explicit
 * requirement, not a hypothetical one.
 *
 * ADAPTATION: rather than changing difficultyOf()'s contract — every one
 * of the 89 labs' route handlers calls it expecting a working tier string
 * to branch their actual logic on; changing that return contract would
 * mean touching every route file — this is a separate guard applied only
 * to /vuln/* requests, BEFORE those handlers run. It inspects the same
 * three sources difficultyOf() reads from (query, body, cookie), in the
 * same priority order, and short-circuits with a proper error response
 * for anything invalid. "expert" gets a distinct, honest 501 (a real,
 * named tier that's genuinely just not implemented yet) rather than being
 * lumped in with malformed input (400, e.g. ?difficulty=banana).
 * difficultyOf() itself is UNCHANGED, and still has a sane default for
 * the case where no difficulty was specified at all — an absent
 * parameter is a normal default, not the "invalid value" Section 15
 * means.
 *
 * Scope note: this covers the /vuln/* HTTP surface (what the spec's own
 * examples and most explicit language is about), PLUS /graphql
 * specifically — added when graphql-authz-bypass got real expert-tier
 * logic, because all 3 GraphQL labs share ONE execution endpoint
 * (POST /graphql) separate from their individual /vuln/graphql-* landing
 * pages. Without this, ?difficulty=expert would correctly reach the
 * graphql-authz-bypass landing PAGE but then get wrongly 501'd on the
 * actual query execution request, since /graphql doesn't match /vuln/*.
 * The 3 WebSocket labs' ?difficulty= on the initial upgrade request is
 * still not covered — WS upgrades bypass Express's middleware pipeline
 * entirely (see routes/vulns-api.js's attachWebSocketServer), and none of
 * them currently have expert content, so there's nothing yet to let
 * through there.
 */
const VALID_TIERS = ["easy", "medium", "hard"];
const KNOWN_UNIMPLEMENTED_TIERS = ["expert"];

// Labs with genuine, working Expert-tier logic (see docs/UPGRADE-LOG.md's
// Phase 7 entries for which ones and why). Every other lab still gets the
// honest 501 below for ?difficulty=expert — this list is the single
// source of truth for "does this lab actually have expert content",
// checked directly against the request path rather than duplicated
// per-lab difficulty-of logic.
const EXPERT_SUPPORTED_LAB_IDS = ["ssrf", "jwt-vulnerabilities", "sql-injection", "xxe", "graphql-authz-bypass", "idor"];

// GraphQL labs share one execution endpoint (POST /graphql) instead of
// each having their own /vuln/<id> route for the actual query — this maps
// that shared endpoint to whichever GraphQL lab ids currently have expert
// content, since the guard's normal per-path labId lookup can't apply here.
const GRAPHQL_SHARED_ENDPOINT = "/graphql";
const GRAPHQL_LAB_IDS_WITH_EXPERT = EXPERT_SUPPORTED_LAB_IDS.filter((id) => id.startsWith("graphql-"));

function labIdFromPath(reqPath) {
  const m = reqPath.match(/^\/vuln\/([a-z0-9-]+)/);
  return m ? m[1] : null;
}

function rawDifficultyFrom(req) {
  if (req.query && req.query.difficulty) return String(req.query.difficulty);
  if (req.body && req.body.difficulty) return String(req.body.difficulty);
  if (req.cookies && req.cookies.difficulty) return String(req.cookies.difficulty);
  return null;
}

function difficultyGuard(req, res, next) {
  const isGraphql = req.path === GRAPHQL_SHARED_ENDPOINT;
  if (!req.path.startsWith("/vuln/") && !isGraphql) return next();
  const raw = rawDifficultyFrom(req);
  if (raw === null) return next(); // unspecified — a normal default, not invalid

  const lower = raw.toLowerCase();
  if (VALID_TIERS.includes(lower)) return next();

  if (KNOWN_UNIMPLEMENTED_TIERS.includes(lower)) {
    const labId = isGraphql ? null : labIdFromPath(req.path);
    if (lower === "expert" && isGraphql && GRAPHQL_LAB_IDS_WITH_EXPERT.length) return next();
    if (lower === "expert" && labId && EXPERT_SUPPORTED_LAB_IDS.includes(labId)) return next();
    return res.status(501).json({
      success: false,
      error: `The "${lower}" difficulty tier is not yet implemented for ${labId ? `the "${labId}" lab` : "this lab"}. Available tiers: ${VALID_TIERS.join(", ")}${EXPERT_SUPPORTED_LAB_IDS.length ? ` (expert is implemented for: ${EXPERT_SUPPORTED_LAB_IDS.join(", ")})` : ""}.`,
    });
  }

  return res.status(400).json({
    success: false,
    error: `Invalid difficulty "${raw}". Valid values: ${VALID_TIERS.concat(KNOWN_UNIMPLEMENTED_TIERS).join(", ")}.`,
  });
}

module.exports = { difficultyGuard, VALID_TIERS, KNOWN_UNIMPLEMENTED_TIERS, EXPERT_SUPPORTED_LAB_IDS };
