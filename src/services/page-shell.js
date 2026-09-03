/**
 * src/services/page-shell.js — shared page chrome for every standalone
 * "vulnerable target" page.
 *
 * Extracted from routes/vuln-common.js (Phase 1 architecture pass, see
 * docs/UPGRADE-LOG.md).
 *
 * PHASE 2 UPDATE (upgrade-spec Sections 7-9, 43-45: "the target application
 * must look like an ordinary product, not a CTF page"): the topbar used to
 * literally render `SecureCorp Demo · sandbox · difficulty: ${difficulty}`
 * on every single target page — a direct CTF-language leak into the layer
 * the spec says must not have one. Difficulty selection is still a real,
 * necessary feature (the training platform picks it and passes it via
 * `?difficulty=`), it just doesn't need to be *labeled* as such inside the
 * target app's own chrome any more than a real app labels which QA
 * environment tier a customer is on. Replaced with a normal logged-in-user
 * indicator instead (spec Section 44's own example: "Welcome back, Alex").
 * The `difficulty` parameter is unchanged — every one of the 87 call sites
 * across routes/*.js still passes it the same way — it's just no longer
 * echoed into the visible page text here.
 */
function renderVulnPage({ appName, difficulty, bodyHtml, extraHead }) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<title>${appName} — SecureCorp</title>
<style>
  *{box-sizing:border-box;}
  body{background:#f4f5f7;color:#1c2024;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;}
  .topbar{background:#1c2024;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;}
  .topbar .name{font-weight:700;letter-spacing:.02em;}
  .topbar .user{font-size:.8rem;color:#c7ccd4;display:flex;align-items:center;gap:8px;}
  .topbar .avatar{width:22px;height:22px;border-radius:50%;background:#f5a524;color:#1c1200;display:inline-flex;align-items:center;justify-content:center;font-weight:700;font-size:.68rem;}
  .intranav{background:#252932;padding:6px 24px;display:flex;gap:16px;font-size:.75rem;}
  .intranav a{color:#9aa1ab;text-decoration:none;}
  .intranav a:hover{color:#fff;}
  .wrap{max-width:720px;margin:32px auto;background:#fff;border:1px solid #e2e5e9;border-radius:10px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,.06);}
  h1{font-size:1.3rem;margin:0 0 18px;}
  label{display:block;font-size:.82rem;color:#5b6470;margin-bottom:4px;font-weight:600;}
  input[type=text],input[type=password],input[type=email],input[type=file],textarea,select{
    width:100%;padding:9px 11px;border:1px solid #d3d7dd;border-radius:6px;font-size:.92rem;margin-bottom:14px;font-family:inherit;
  }
  textarea{font-family:ui-monospace,Menlo,monospace;font-size:.82rem;min-height:100px;}
  button,.btn{background:#f5a524;color:#1c1200;border:none;padding:10px 18px;border-radius:6px;font-weight:700;cursor:pointer;font-size:.9rem;}
  button.secondary,.btn.secondary{background:#eceef1;color:#1c2024;}
  button.danger{background:#ef4444;color:#fff;}
  a.btn{display:inline-block;text-decoration:none;}
  .result{background:#f4f5f7;border:1px solid #e2e5e9;border-radius:8px;padding:14px 16px;margin-top:16px;font-family:ui-monospace,Menlo,monospace;font-size:.82rem;white-space:pre-wrap;word-break:break-word;}
  .note{font-size:.8rem;color:#7d838d;margin-top:10px;}
  .field-hidden-value{color:#a78bfa;font-weight:700;}
  table{width:100%;border-collapse:collapse;font-size:.85rem;}
  td,th{padding:7px 6px;border-bottom:1px solid #ececec;text-align:left;}
  .pill{display:inline-block;background:#eceef1;border-radius:999px;padding:2px 9px;font-size:.7rem;font-family:ui-monospace,Menlo,monospace;}
</style>
${extraHead || ""}
</head><body>
  <div class="topbar">
    <span class="name">${appName}</span>
    <span class="user"><span class="avatar">AR</span> Alex Rivera</span>
  </div>
  <div class="intranav">
    <a href="/company">🏠 Intranet Home</a>
    <a href="/company#dashboard">Dashboard</a>
    <a href="/company#profile">Profile</a>
    <a href="/company#support">Support</a>
    <a href="/company#billing">Billing</a>
    <a href="/company#admin">Admin</a>
    <a href="/company#api">API Explorer</a>
  </div>
  <div class="wrap">${bodyHtml}</div>
</body></html>`;
}

module.exports = { renderVulnPage };
