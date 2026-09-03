/**
 * src/services/finova-shell.js — page chrome for "Finova", the third
 * distinct target application (upgrade-spec Section 9). Same pattern as
 * src/services/shopsphere-shell.js (Phase 2b) — different name, different
 * color identity (navy/blue banking palette), different nav (Accounts /
 * Transfers / Cards / Statements / Support), a different fake logged-in
 * customer. Same interface shape as renderVulnPage()/renderShopSpherePage()
 * and the same no-CTF-language rule from Phase 2a.
 */
function renderFinovaPage({ appName, difficulty, bodyHtml, extraHead }) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<title>${appName} — Finova</title>
<style>
  *{box-sizing:border-box;}
  body{background:#f4f6fb;color:#0f1d3d;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;}
  .topbar{background:#0b1a3a;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;}
  .topbar .name{font-weight:700;letter-spacing:.02em;}
  .topbar .name::before{content:"🏦 ";}
  .topbar .user{font-size:.8rem;color:#a9b8e0;display:flex;align-items:center;gap:8px;}
  .topbar .avatar{width:22px;height:22px;border-radius:50%;background:#4f7cff;color:#fff;display:inline-flex;align-items:center;justify-content:center;font-weight:700;font-size:.68rem;}
  .finnav{background:#12245a;padding:6px 24px;display:flex;gap:16px;font-size:.75rem;}
  .finnav a{color:#a9b8e0;text-decoration:none;}
  .finnav a:hover{color:#fff;}
  .wrap{max-width:720px;margin:32px auto;background:#fff;border:1px solid #dde3f2;border-radius:10px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,.06);}
  h1{font-size:1.3rem;margin:0 0 18px;}
  label{display:block;font-size:.82rem;color:#4a5578;margin-bottom:4px;font-weight:600;}
  input[type=text],input[type=password],input[type=email],input[type=file],textarea,select{
    width:100%;padding:9px 11px;border:1px solid #ccd4ea;border-radius:6px;font-size:.92rem;margin-bottom:14px;font-family:inherit;
  }
  textarea{font-family:ui-monospace,Menlo,monospace;font-size:.82rem;min-height:100px;}
  button,.btn{background:#3355e0;color:#fff;border:none;padding:10px 18px;border-radius:6px;font-weight:700;cursor:pointer;font-size:.9rem;}
  button.secondary,.btn.secondary{background:#e8ecfa;color:#0f1d3d;}
  button.danger{background:#ef4444;color:#fff;}
  a.btn{display:inline-block;text-decoration:none;}
  .result{background:#f2f4fb;border:1px solid #dde3f2;border-radius:8px;padding:14px 16px;margin-top:16px;font-family:ui-monospace,Menlo,monospace;font-size:.82rem;white-space:pre-wrap;word-break:break-word;}
  .note{font-size:.8rem;color:#5c6690;margin-top:10px;}
  table{width:100%;border-collapse:collapse;font-size:.85rem;}
  td,th{padding:7px 6px;border-bottom:1px solid #eceff8;text-align:left;}
  .pill{display:inline-block;background:#e8ecfa;color:#12245a;border-radius:999px;padding:2px 9px;font-size:.7rem;font-family:ui-monospace,Menlo,monospace;}
</style>
${extraHead || ""}
</head><body>
  <div class="topbar">
    <span class="name">${appName}</span>
    <span class="user"><span class="avatar">SC</span> Sam Chen</span>
  </div>
  <div class="finnav">
    <a href="/finova">🏠 Accounts</a>
    <a href="/finova#transfers">Transfers</a>
    <a href="/finova#cards">Cards</a>
    <a href="/finova#statements">Statements</a>
    <a href="/finova#support">Support</a>
  </div>
  <div class="wrap">${bodyHtml}</div>
</body></html>`;
}

module.exports = { renderFinovaPage };
