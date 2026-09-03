/**
 * src/utils/random.js — shared randomness helper.
 * Used by the session engine (session ids) and the flag engine (flags,
 * client-proof tokens). Node's crypto.randomBytes, not Math.random — every
 * value here is meant to be genuinely unguessable.
 */
const crypto = require("crypto");

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString("hex");
}

module.exports = { randomHex };
