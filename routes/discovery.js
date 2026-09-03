/**
 * routes/discovery.js — application-discovery artifacts (upgrade-spec
 * Section 41: "robots.txt, sitemap, API documentation... public assets,
 * hidden but discoverable endpoints"). Genuinely missing until now — the
 * only prior robots.txt in this app was a single lab-specific one used as
 * an in-lab hint (routes/vulns-infra.js's exposed-dev-endpoint), not a
 * real site-wide artifact a learner doing normal reconnaissance would
 * check first, the way they would against any real bug-bounty target.
 *
 * Deliberately realistic, not a spoiler sheet: robots.txt disallows real,
 * plausible-sounding paths without literally naming which ones are
 * vulnerable; the sitemap lists the three real target applications and
 * their genuinely-existing top-level pages; the API reference documents
 * the platform's own stable cross-cutting endpoints (the kind of thing
 * real companies actually publish) rather than enumerating every /vuln/*
 * sub-route, which would just hand over the answer key.
 */
const express = require("express");
const router = express.Router();

router.get("/robots.txt", (req, res) => {
  res.type("text/plain").send(
    [
      "User-agent: *",
      "Disallow: /admin",
      "Disallow: /internal",
      "Disallow: /api/",
      "Disallow: /_debug",
      "Disallow: /backup",
      "",
      `Sitemap: ${req.protocol}://${req.get("host")}/sitemap.xml`,
      "",
    ].join("\n")
  );
});

router.get("/sitemap.xml", (req, res) => {
  const base = `${req.protocol}://${req.get("host")}`;
  const urls = [
    "/",
    "/company",
    "/shopsphere",
    "/finova",
    "/api-docs",
  ];
  const body =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
    urls.map((u) => `  <url><loc>${base}${u}</loc></url>`).join("\n") +
    `\n</urlset>\n`;
  res.type("application/xml").send(body);
});

router.get("/api-docs", (req, res) => {
  res.type("text/html").send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" /><title>SecureCorp Platform — API Reference</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:760px;margin:40px auto;padding:0 20px;color:#1c2024;background:#fff;}
  h1{font-size:1.4rem;} h2{font-size:1.05rem;margin-top:28px;border-bottom:1px solid #e2e5e9;padding-bottom:6px;}
  code{background:#f4f5f7;padding:2px 6px;border-radius:4px;font-family:ui-monospace,Menlo,monospace;font-size:.85em;}
  table{width:100%;border-collapse:collapse;margin-top:10px;font-size:.88rem;}
  td,th{padding:7px 8px;border-bottom:1px solid #ececec;text-align:left;vertical-align:top;}
  th{color:#5b6470;font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.03em;}
  .note{color:#7d838d;font-size:.85rem;}
</style></head><body>
  <h1>SecureCorp Platform — API Reference</h1>
  <p class="note">Internal reference for integrating with our platform APIs. Most endpoints require an authenticated session (cookie-based) or a bearer token, depending on the service.</p>

  <h2>Core platform</h2>
  <table>
    <tr><th>Method</th><th>Path</th><th>Description</th></tr>
    <tr><td>GET</td><td><code>/api/progress</code></td><td>Current session's progress summary.</td></tr>
    <tr><td>POST</td><td><code>/api/reports</code></td><td>Submit a report against a resource.</td></tr>
    <tr><td>GET</td><td><code>/api/reports</code></td><td>List submitted reports for the current session.</td></tr>
    <tr><td>POST</td><td><code>/graphql</code></td><td>Primary GraphQL endpoint. Schema available on request.</td></tr>
  </table>

  <h2>ShopSphere</h2>
  <table>
    <tr><th>Method</th><th>Path</th><th>Description</th></tr>
    <tr><td>GET</td><td><code>/shopsphere</code></td><td>Storefront home — featured products, recent orders.</td></tr>
  </table>

  <h2>Finova</h2>
  <table>
    <tr><th>Method</th><th>Path</th><th>Description</th></tr>
    <tr><td>GET</td><td><code>/finova</code></td><td>Account overview — balances, recent transactions.</td></tr>
  </table>

  <p class="note">Questions about API access? Contact your account manager.</p>
</body></html>`);
});

module.exports = { router };
