/**
 * src/utils/difficulty.js — resolves the requested difficulty tier from a
 * request (query param, body field, or cookie, in that priority order),
 * defaulting to "easy" for anything unrecognized.
 *
 * UPDATED (Phase 7): "expert" is now a recognized value here. This is
 * SAFE precisely because src/middleware/difficulty-guard.js already runs
 * before any route handler and rejects ?difficulty=expert with a proper
 * 501 for every lab NOT in its own EXPERT_SUPPORTED_LAB_IDS list — by the
 * time this function is ever called with "expert", the guard has already
 * confirmed the specific lab being requested actually has real expert
 * logic to run. Labs without expert content are simply unreachable with
 * this value; there's nothing for this function to protect against
 * on its own. (An earlier version of this comment said adding "expert"
 * here without downstream handling would be worse than not adding it at
 * all — that's still true in isolation, but the guard is the downstream
 * handling; this function doesn't need its own copy of that logic.)
 */
function difficultyOf(req) {
  const d = (
    (req.query && req.query.difficulty) ||
    (req.body && req.body.difficulty) ||
    (req.cookies && req.cookies.difficulty) ||
    "easy"
  ).toLowerCase();
  return ["easy", "medium", "hard", "expert"].includes(d) ? d : "easy";
}

module.exports = { difficultyOf };
