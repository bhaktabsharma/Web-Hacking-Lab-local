/**
 * src/services/fake-internal-network.js — simulated "internal" services.
 *
 * Extracted from routes/vuln-common.js (Phase 1 architecture pass, see
 * docs/UPGRADE-LOG.md). Behavior unchanged.
 *
 * Used ONLY by the SSRF lab. No real outbound network request is ever made
 * by this app — an SSRF payload is matched against these dictionary keys
 * and the corresponding canned response is returned, full stop. Splitting
 * this out (rather than inline in a shared 280-line file) is what makes
 * the SSRF-isolation test planned for Phase 6 (upgrade-spec Section 48)
 * clean to write: it can assert directly against this module that it's a
 * static lookup table with no `http.request`/`fetch`/`net.connect` inside
 * it, and separately fuzz the SSRF route with localhost/LAN/metadata-style
 * payloads to confirm only these exact keys ever produce a response.
 */
const FAKE_INTERNAL_SERVICES = {
  "169.254.169.254/latest/meta-data/iam/security-credentials/admin":
    '{"AccessKeyId":"AKIAFAKEDEMOTRAINING","SecretAccessKey":"fakeSecretDoNotUse1234567890","Token":"fake"}',
  "localhost:6379/info": "# Redis (simulated)\r\nredis_version:7.0.0\r\nrole:master\r\n",
  "internal-api.local/admin/users": '[{"id":1,"username":"admin","role":"superadmin"}]',
  "127.0.0.1/admin": "<h1>Internal Admin Panel (simulated)</h1><p>This should never be reachable from outside.</p>",
};

module.exports = { FAKE_INTERNAL_SERVICES };
