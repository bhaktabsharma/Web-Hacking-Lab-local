/**
 * tests/discovery.test.js — Phase 2/realism addition: application
 * discovery artifacts (upgrade-spec Section 41: "robots.txt, sitemap,
 * API documentation... hidden but discoverable endpoints"). Confirms the
 * new site-wide artifacts exist, are content-typed correctly, reference
 * real routes, and don't collide with the pre-existing lab-specific
 * robots.txt used inside the exposed-dev-endpoint lab.
 */
const http = require("http");

let pass = 0, fail = 0;
function check(name, cond, extra) { if (cond) { pass++; console.log("PASS:", name); } else { fail++; console.log("FAIL:", name, extra || ""); } }
setTimeout(() => { console.log(`DEADLINE HIT: ${pass} passed, ${fail} failed (incomplete)`); process.exit(2); }, 30000).unref();

function get(urlPath) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:3000${urlPath}`, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body, headers: res.headers }));
    }).on("error", reject);
  });
}

async function run() {
  // --- robots.txt ---------------------------------------------------
  const rRobots = await get("/robots.txt");
  check("GET /robots.txt responds 200", rRobots.status === 200);
  check("robots.txt is served as text/plain", (rRobots.headers["content-type"] || "").includes("text/plain"));
  check("robots.txt has a User-agent directive", /User-agent:\s*\*/.test(rRobots.body));
  check("robots.txt has at least one Disallow rule", /Disallow:/.test(rRobots.body));
  check("robots.txt points to a Sitemap URL", /Sitemap:\s*http/.test(rRobots.body));
  check("robots.txt does NOT reveal CTF/training language", !/flag|ctf|vulnerab|exploit/i.test(rRobots.body));

  // --- sitemap.xml -----------------------------------------------------
  const rSitemap = await get("/sitemap.xml");
  check("GET /sitemap.xml responds 200", rSitemap.status === 200);
  check("sitemap.xml is served as application/xml", (rSitemap.headers["content-type"] || "").includes("xml"));
  check("sitemap.xml is well-formed enough to contain a <urlset>", /<urlset/.test(rSitemap.body));
  check("sitemap.xml lists the SecureCorp intranet", /<loc>[^<]*\/company<\/loc>/.test(rSitemap.body));
  check("sitemap.xml lists ShopSphere", /<loc>[^<]*\/shopsphere<\/loc>/.test(rSitemap.body));
  check("sitemap.xml lists Finova", /<loc>[^<]*\/finova<\/loc>/.test(rSitemap.body));

  // Every URL listed in the sitemap should actually resolve — a sitemap
  // full of 404s would be a realism bug, not just an oversight.
  const locs = [...rSitemap.body.matchAll(/<loc>(https?:\/\/[^<]+)<\/loc>/g)].map((m) => m[1]);
  check("sitemap.xml lists at least a few URLs", locs.length >= 3, locs.length);
  for (const loc of locs) {
    const path = loc.replace(/^https?:\/\/[^/]+/, "") || "/";
    const r = await get(path);
    check(`sitemap URL ${path} actually resolves (200)`, r.status === 200, "status=" + r.status);
  }

  // --- API reference -----------------------------------------------
  const rApiDocs = await get("/api-docs");
  check("GET /api-docs responds 200", rApiDocs.status === 200);
  check("api-docs documents a real, stable platform endpoint", /\/api\/progress/.test(rApiDocs.body));
  check("api-docs documents the GraphQL endpoint", /\/graphql/.test(rApiDocs.body));
  check("api-docs does NOT enumerate individual /vuln/* lab sub-routes (not a spoiler sheet)", !/\/vuln\//.test(rApiDocs.body));

  // --- no collision with the pre-existing lab-specific robots.txt ---
  const rLabRobots = await get("/vuln/exposed-dev-endpoint/robots.txt?difficulty=hard");
  check("the pre-existing lab-specific robots.txt (inside exposed-dev-endpoint) still works, unaffected", rLabRobots.status === 200);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
