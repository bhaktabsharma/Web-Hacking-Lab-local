/**
 * src/services/shopsphere-shell.js — page chrome for "ShopSphere", the
 * second distinct target application (upgrade-spec Section 9: "Create
 * multiple realistic applications... these applications can share the
 * same underlying framework but should feel like different real
 * products.").
 *
 * PHASE 2 ADDITION. Until now every lab shared one SecureCorp-branded
 * shell (src/services/page-shell.js) regardless of what the lab's own
 * `demoApp` metadata claimed — several business-logic labs were already
 * labeled "SecureCorp Store — Checkout" etc. in labs-data.js but still
 * rendered with the exact same intranet chrome as every SQL-injection or
 * IDOR lab. This is a genuinely distinct shell: different name, different
 * color identity (emerald/teal instead of SecureCorp's amber), different
 * nav (Home / Products / Cart / Orders / Account / Support instead of
 * Dashboard / Profile / Billing / Admin / API Explorer), a different fake
 * logged-in customer — so a learner opening a ShopSphere lab in a new tab
 * genuinely feels like they're testing a different product, not the same
 * intranet with a new page title.
 *
 * Same design rule as page-shell.js (Phase 2a): no difficulty/sandbox/CTF
 * language anywhere in this chrome. Same interface shape as
 * renderVulnPage() ({ appName, difficulty, bodyHtml, extraHead }) so
 * route files can adopt it with a minimal, purely presentational change —
 * the vulnerable logic behind it is untouched either way.
 */
function renderShopSpherePage({ appName, difficulty, bodyHtml, extraHead }) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<title>${appName} — ShopSphere</title>
<style>
  *{box-sizing:border-box;}
  body{background:#f6faf9;color:#0f2a24;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;}
  .topbar{background:#0b3b32;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;}
  .topbar .name{font-weight:700;letter-spacing:.02em;}
  .topbar .name::before{content:"🛍️ ";}
  .topbar .user{font-size:.8rem;color:#bfe6da;display:flex;align-items:center;gap:8px;}
  .topbar .avatar{width:22px;height:22px;border-radius:50%;background:#2dd4a7;color:#04231d;display:inline-flex;align-items:center;justify-content:center;font-weight:700;font-size:.68rem;}
  .shopnav{background:#0f4a3e;padding:6px 24px;display:flex;gap:16px;font-size:.75rem;}
  .shopnav a{color:#bfe6da;text-decoration:none;}
  .shopnav a:hover{color:#fff;}
  .wrap{max-width:720px;margin:32px auto;background:#fff;border:1px solid #dcece6;border-radius:10px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,.06);}
  h1{font-size:1.3rem;margin:0 0 18px;}
  label{display:block;font-size:.82rem;color:#4d6b62;margin-bottom:4px;font-weight:600;}
  input[type=text],input[type=password],input[type=email],input[type=file],textarea,select{
    width:100%;padding:9px 11px;border:1px solid #cfe3db;border-radius:6px;font-size:.92rem;margin-bottom:14px;font-family:inherit;
  }
  textarea{font-family:ui-monospace,Menlo,monospace;font-size:.82rem;min-height:100px;}
  button,.btn{background:#0f8f6f;color:#fff;border:none;padding:10px 18px;border-radius:6px;font-weight:700;cursor:pointer;font-size:.9rem;}
  button.secondary,.btn.secondary{background:#e4f3ee;color:#0f2a24;}
  button.danger{background:#ef4444;color:#fff;}
  a.btn{display:inline-block;text-decoration:none;}
  .result{background:#f2f8f6;border:1px solid #dcece6;border-radius:8px;padding:14px 16px;margin-top:16px;font-family:ui-monospace,Menlo,monospace;font-size:.82rem;white-space:pre-wrap;word-break:break-word;}
  .note{font-size:.8rem;color:#5c766d;margin-top:10px;}
  table{width:100%;border-collapse:collapse;font-size:.85rem;}
  td,th{padding:7px 6px;border-bottom:1px solid #eaf3f0;text-align:left;}
  .pill{display:inline-block;background:#e4f3ee;color:#0f4a3e;border-radius:999px;padding:2px 9px;font-size:.7rem;font-family:ui-monospace,Menlo,monospace;}
  .product-line{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #eaf3f0;font-size:.88rem;}
</style>
${extraHead || ""}
</head><body>
  <div class="topbar">
    <span class="name">${appName}</span>
    <span class="user"><span class="avatar">JK</span> Jordan Kim</span>
  </div>
  <div class="shopnav">
    <a href="/shopsphere">🏠 Home</a>
    <a href="/shopsphere#products">Products</a>
    <a href="/shopsphere#cart">Cart</a>
    <a href="/shopsphere#orders">Orders</a>
    <a href="/shopsphere#account">Account</a>
    <a href="/shopsphere#support">Support</a>
  </div>
  <div class="wrap">${bodyHtml}</div>
</body></html>`;
}

module.exports = { renderShopSpherePage };
