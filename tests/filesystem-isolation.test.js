/**
 * tests/filesystem-isolation.test.js — upgrade-spec Section 49: "Prove
 * that traversal cannot access /etc/passwd, process files, project files,
 * environment files, host filesystem. The lab should only see the fake
 * filesystem."
 *
 * Two layers of proof:
 *   STATIC  — grep every route/src file for `require("fs")`. It should
 *             appear in exactly one place (the legitimate file-upload
 *             feature's own multer-managed sandbox directory — see
 *             routes/vulns-serverlogic.js), and every call site there must
 *             use a fixed path, never a value derived from request input.
 *             path-traversal/LFI/XXE must instead resolve exclusively
 *             through src/services/fake-filesystem.js's VFS object.
 *   DYNAMIC — fuzz the live /vuln/path-traversal and /vuln/lfi routes with
 *             real host-filesystem paths and confirm the responses never
 *             contain REAL system content. This container's actual
 *             /etc/passwd has entries the fake VFS's /etc/passwd
 *             deliberately does not (bin/sys/sync users) — a positive,
 *             concrete signal that would only appear if a real file read
 *             ever happened.
 */
const fs = require("fs");
const path = require("path");
const http = require("http");

const ROOT = path.join(__dirname, "..");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function httpGet(urlPath) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: "localhost", port: 3000, path: urlPath, method: "GET" }, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    r.on("error", reject);
    r.end();
  });
}

function staticChecks() {
  const fsRequireSites = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".js")) {
        const src = fs.readFileSync(full, "utf8");
        if (/require\(\s*["']fs["']\s*\)/.test(src)) fsRequireSites.push(path.relative(ROOT, full));
      }
    }
  }
  walk(path.join(ROOT, "routes"));
  walk(path.join(ROOT, "src"));

  check(
    "exactly one route/src file requires the real 'fs' module (the file-upload sandbox)",
    fsRequireSites.length === 1 && fsRequireSites[0] === path.join("routes", "vulns-serverlogic.js"),
    JSON.stringify(fsRequireSites)
  );

  if (fsRequireSites.length) {
    const src = fs.readFileSync(path.join(ROOT, fsRequireSites[0]), "utf8");
    const fsCallLines = src.split("\n").filter((l) => /\bfs\.(readFile|writeFile|existsSync|mkdirSync|unlinkSync|readdirSync)/.test(l));
    check("every real fs.* call site found", fsCallLines.length > 0, fsCallLines.length);
    const userControlled = fsCallLines.filter((l) => /req\.(query|body|params)/.test(l));
    check(
      "none of those fs.* call sites take a value directly from request input (query/body/params)",
      userControlled.length === 0,
      JSON.stringify(userControlled)
    );
    // No fs.readFile*/writeFile* at all — only existsSync/mkdirSync/unlinkSync
    // for sandbox directory setup/cleanup, never reading arbitrary content.
    const contentReadWrite = fsCallLines.filter((l) => /\bfs\.(readFile|writeFile)/.test(l));
    check("no fs.readFile/writeFile call exists anywhere (only dir setup + cleanup)", contentReadWrite.length === 0, JSON.stringify(contentReadWrite));
  }

  const vfsPath = path.join(ROOT, "src", "services", "fake-filesystem.js");
  const vfsSrc = fs.readFileSync(vfsPath, "utf8");
  check(
    "src/services/fake-filesystem.js is a static object literal (no fs/path module usage at all)",
    !/require\(\s*["'](fs|path)["']\s*\)/.test(vfsSrc)
  );
}

async function dynamicChecks() {
  // Telltale signatures that only exist in THIS container's real
  // /etc/passwd, deliberately absent from the fake VFS's version (which
  // only has root/daemon/trainee — see src/services/fake-filesystem.js).
  const REAL_SYSTEM_TELLTALES = ["bin:x:2:2:bin:", "sys:x:3:3:sys:", "www-data"];

  const traversalPayloads = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "../../../../server.js",
    "../../../../../../proc/self/environ",
  ];

  for (const payload of traversalPayloads) {
    const { status, body } = await httpGet(`/vuln/path-traversal?difficulty=easy&file=${encodeURIComponent(payload)}`);
    check(`path-traversal with "${payload}" responds 200`, status === 200, "status=" + status);
    for (const telltale of REAL_SYSTEM_TELLTALES) {
      check(`path-traversal with "${payload}" does not leak real telltale "${telltale}"`, !body.includes(telltale));
    }
  }

  // The one traversal payload that SHOULD succeed against the fake VFS —
  // confirms the isolation is real ("nothing gets through") and not just
  // "the feature is broken and nothing ever resolves."
  const { body: vfsBody } = await httpGet(`/vuln/path-traversal?difficulty=easy&file=${encodeURIComponent("../../../../etc/passwd")}`);
  check("the fake VFS's own /etc/passwd IS reachable via the same traversal technique", vfsBody.includes("trainee:x:1000:1000"));
  for (const telltale of REAL_SYSTEM_TELLTALES) {
    check(`even the successful fake-VFS read does not contain real telltale "${telltale}"`, !vfsBody.includes(telltale));
  }

  // Same battery against /vuln/lfi (?lang=).
  for (const payload of traversalPayloads) {
    const { status, body } = await httpGet(`/vuln/lfi?difficulty=easy&lang=${encodeURIComponent(payload)}`);
    check(`lfi with "${payload}" responds 200`, status === 200, "status=" + status);
    for (const telltale of REAL_SYSTEM_TELLTALES) {
      check(`lfi with "${payload}" does not leak real telltale "${telltale}"`, !body.includes(telltale));
    }
  }
}

async function run() {
  staticChecks();
  await dynamicChecks();
  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
