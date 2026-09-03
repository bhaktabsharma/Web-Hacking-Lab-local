/**
 * src/labs/fixtures/users.js — shared fake user directory.
 *
 * Extracted from routes/vuln-common.js (Phase 1 architecture pass, see
 * docs/UPGRADE-LOG.md). Behavior unchanged. Used by IDOR, Access Control,
 * and the Final Challenge labs. All-fake data (upgrade-spec Section 11) —
 * *-demo.test email domain, no real people.
 */
const USERS = [
  { canonicalId: 1, username: "amoore", email: "a.moore@securecorp-demo.test", phone: "555-0101" },
  { canonicalId: 2, username: "bkline", email: "b.kline@securecorp-demo.test", phone: "555-0102" },
  { canonicalId: 3, username: "cwalsh", email: "c.walsh@securecorp-demo.test", phone: "555-0103" },
  { canonicalId: 4, username: "dpatel", email: "d.patel@securecorp-demo.test", phone: "555-0104" },
  { canonicalId: 5, username: "erivera", email: "e.rivera@securecorp-demo.test", phone: "555-0105" },
  { canonicalId: 6, username: "fchen", email: "f.chen@securecorp-demo.test", phone: "555-0106" },
  { canonicalId: 7, username: "gsingh", email: "g.singh@securecorp-demo.test", phone: "555-0107" },
  { canonicalId: 8, username: "hnguyen", email: "h.nguyen@securecorp-demo.test", phone: "555-0108" },
  { canonicalId: 9, username: "iolsen", email: "i.olsen@securecorp-demo.test", phone: "555-0109" },
  { canonicalId: 10, username: "jkumar", email: "j.kumar@securecorp-demo.test", phone: "555-0110" },
  { canonicalId: 11, username: "kbrooks", email: "k.brooks@securecorp-demo.test", phone: "555-0111" },
  { canonicalId: 12, username: "lferrer", email: "l.ferrer@securecorp-demo.test", phone: "555-0112" },
];

const ADMIN = {
  canonicalId: 100,
  username: "admin",
  email: "admin@securecorp-demo.test",
  phone: "555-0100",
  password: "CTBB_S3cr3t_2026!",
};

function findUserByCanonicalId(id) {
  if (id === 100) return ADMIN;
  return USERS.find((u) => u.canonicalId === id);
}

function encodeId(canonicalId, difficulty) {
  if (difficulty === "hard") return Buffer.from(String(canonicalId), "utf8").toString("base64");
  if (difficulty === "medium") return String(canonicalId * 37 + 4);
  return String(canonicalId);
}

function decodeId(raw, difficulty) {
  if (raw === undefined || raw === null || raw === "") return NaN;
  if (difficulty === "hard") {
    try {
      return parseInt(Buffer.from(String(raw), "base64").toString("utf8"), 10);
    } catch (e) {
      return NaN;
    }
  }
  if (difficulty === "medium") {
    const n = parseInt(raw, 10);
    if (Number.isNaN(n)) return NaN;
    return (n - 4) / 37;
  }
  return parseInt(raw, 10);
}

module.exports = { USERS, ADMIN, findUserByCanonicalId, encodeId, decodeId };
