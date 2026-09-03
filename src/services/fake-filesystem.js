/**
 * src/services/fake-filesystem.js — a completely FAKE virtual filesystem.
 *
 * Extracted from routes/vuln-common.js (Phase 1 architecture pass, see
 * docs/UPGRADE-LOG.md). Behavior unchanged.
 *
 * Traversal/inclusion bugs resolve against THIS object only — never Node's
 * real `fs` module against the host disk. This keeps every "arbitrary file
 * read" lab realistic in technique while being 100% harmless to run on
 * your own laptop. Splitting this into its own module (rather than living
 * inline in a 280-line shared file) is also what makes the filesystem-
 * isolation test planned for Phase 6 (upgrade-spec Section 49) clean to
 * write: it can assert directly against this module that nothing in it
 * ever calls into Node's `fs`, `path.resolve` against `process.cwd()`, etc.
 */
const VFS = {
  "/etc/passwd":
    "root:x:0:0:root:/root:/bin/bash\n" +
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
    "trainee:x:1000:1000:Trainee User:/home/trainee:/bin/bash\n",
  "/var/www/config.php":
    "<?php\ndefine('DB_HOST','127.0.0.1');\ndefine('DB_USER','securecorp_app');\ndefine('DB_PASS','Tr41n1ng_DB_2026!');\n?>",
  "/home/trainee/.ssh/id_rsa":
    "-----BEGIN OPENSSH PRIVATE KEY-----\n(fake training key — not a real credential)\nAAAAB3NzaC1yc2EAAAADAQABFAKEKEYDONOTUSE==\n-----END OPENSSH PRIVATE KEY-----",
  "/var/log/access.log": "127.0.0.1 - - [training] GET /index.html 200\n",
  "/app/templates/en.txt": "Welcome to SecureCorp Demo!",
  "/app/templates/fr.txt": "Bienvenue chez SecureCorp Demo !",
  "/app/templates/es.txt": "¡Bienvenido a SecureCorp Demo!",
  "/app/documents/report1.txt": "Q1 Report (fake demo data): revenue up 4% quarter over quarter.",
  "/app/documents/report2.txt": "Q2 Report (fake demo data): headcount grew by 3 engineers.",
};

module.exports = { VFS };
