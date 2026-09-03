/**
 * src/core/chain-engine — server-tracked, named-state progression per
 * attack chain (upgrade-spec Section 33: "Do not reduce complex chains to
 * solved = true").
 *
 * ADAPTATION: the spec's own example sequence is NOT_STARTED -> STARTED ->
 * OBJECTIVE_1 -> OBJECTIVE_2 -> OBJECTIVE_3 -> EXPLOIT_VERIFIED ->
 * FLAG_ISSUED -> SOLVED. This app's 3 existing chains genuinely have 1, 2,
 * and 3 real gated intermediate steps respectively — forcing every chain
 * into exactly 3 generic "OBJECTIVE_N" slots would mean either inventing
 * fake intermediate states for the chains that don't have 3, or
 * collapsing genuinely distinct steps into one slot for the chain that
 * does. Instead, each chain declares its OWN ordered list of
 * meaningfully-named milestones between STARTED and EXPLOIT_VERIFIED
 * (e.g. chain-support-takeover's are CREDENTIAL_LEAK_FOUND -> AUTHENTICATED
 * -> TICKET_ACCESS_CONFIRMED). NOT_STARTED / STARTED / EXPLOIT_VERIFIED /
 * FLAG_ISSUED / SOLVED remain fixed and identical across every chain,
 * exactly as the spec names them — only the middle section is per-chain.
 *
 * State lives in session.chains[chainId] = { current, reached: {state:
 * timestamp}, history: [{state, at}] }. Call sites in routes/vulns-
 * chains.js call advanceChainState() additively at each real gated
 * transition already present in that code — this module never changes
 * what a chain's routes actually do or return, it only records that a
 * genuine transition happened.
 */

const CHAIN_DEFINITIONS = {
  "chain-support-takeover": {
    milestones: ["CREDENTIAL_LEAK_FOUND", "AUTHENTICATED", "TICKET_ACCESS_CONFIRMED"],
  },
  "chain-internal-pivot": {
    milestones: ["SSRF_KEY_OBTAINED"],
  },
  "chain-xss-to-admin-action": {
    milestones: ["PAYLOAD_STORED", "ADMIN_EXECUTION_CONFIRMED"],
  },
};

function fullSequence(chainId) {
  const def = CHAIN_DEFINITIONS[chainId];
  if (!def) return null;
  return ["NOT_STARTED", "STARTED", ...def.milestones, "EXPLOIT_VERIFIED", "FLAG_ISSUED", "SOLVED"];
}

function getChainState(session, chainId) {
  if (!CHAIN_DEFINITIONS[chainId]) return null;
  if (!session.chains) session.chains = {};
  if (!session.chains[chainId]) {
    session.chains[chainId] = { current: "NOT_STARTED", reached: {}, history: [] };
  }
  return session.chains[chainId];
}

/**
 * Advances a chain to `toState`, but only forward. Requesting a state
 * that's already been reached (or an earlier one) is a safe no-op —
 * reloading a page or re-triggering an earlier step never regresses
 * progress. Requesting a state further ahead than the current one records
 * every milestone in between as reached too (covers a learner re-hitting a
 * later step's endpoint, e.g. after a page reload, before an earlier
 * step's own call site happened to run in this exact request ordering).
 * Requesting an unrecognized state name, or a chainId with no definition,
 * is a safe no-op.
 */
function advanceChainState(session, chainId, toState) {
  const seq = fullSequence(chainId);
  if (!seq) return null;
  const state = getChainState(session, chainId);
  const curIdx = seq.indexOf(state.current);
  const toIdx = seq.indexOf(toState);
  if (toIdx === -1 || toIdx <= curIdx) return state;
  for (let i = curIdx + 1; i <= toIdx; i++) {
    if (!(seq[i] in state.reached)) state.reached[seq[i]] = Date.now();
  }
  state.current = toState;
  state.history.push({ state: toState, at: Date.now() });
  return state;
}

function chainProgressSummary(session, chainId) {
  const seq = fullSequence(chainId);
  if (!seq) return null;
  const state = getChainState(session, chainId);
  const curIdx = seq.indexOf(state.current);
  return {
    chainId,
    sequence: seq,
    current: state.current,
    reached: state.reached,
    history: state.history,
    percentComplete: Math.round((curIdx / (seq.length - 1)) * 100),
  };
}

function allChainIds() {
  return Object.keys(CHAIN_DEFINITIONS);
}

module.exports = { advanceChainState, getChainState, chainProgressSummary, fullSequence, allChainIds, CHAIN_DEFINITIONS };
