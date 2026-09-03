const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

// PHASE 2 UPDATE (upgrade-spec Sections 7-9, 43-45): this hub's copy used
// to literally say "the internal company hub tying every training area
// together" and "part of the platform" directly on the rendered page —
// exactly the kind of CTF/training language the spec says must never
// appear inside the target application. Tile hrefs/anchors are UNCHANGED
// (nothing else routes through them, confirmed via a repo-wide grep before
// editing this file), only the copy and a bit of surrounding realism.
const TILES = [
  { anchor: "dashboard", icon: "📊", name: "Dashboard", desc: "Company KPIs and quick links.", href: "/vuln/fuzz-params" },
  { anchor: "profile", icon: "👤", name: "Profile", desc: "Manage your account details.", href: "/vuln/vertical-privesc" },
  { anchor: "support", icon: "🎫", name: "Support", desc: "Submit and track support tickets.", href: "/vuln/secondary-context" },
  { anchor: "billing", icon: "💳", name: "Billing", desc: "Invoices and checkout.", href: "/vuln/info-disclosure" },
  { anchor: "admin", icon: "🛠", name: "Admin Console", desc: "Tenant and workspace administration.", href: "/vuln/multi-tenant-isolation" },
  { anchor: "api", icon: "🔌", name: "API Explorer", desc: "Internal API access, token-protected.", href: "/vuln/jwt-vulnerabilities" },
  { anchor: "files", icon: "📁", name: "File Manager", desc: "Upload and manage shared files.", href: "/vuln/file-upload" },
  { anchor: "orders", icon: "🛒", name: "Orders", desc: "Order history, discounts, coupons.", href: "/vuln/http-param-pollution" }
];

const STATS = [
  { label: "Open tickets", value: "14" },
  { label: "Active projects", value: "6" },
  { label: "Pending invoices", value: "3" },
  { label: "Team members", value: "27" },
];

const ACTIVITY = [
  "Priya S. updated the Q3 rollout project timeline.",
  "Invoice #4471 was sent to Meridian Logistics.",
  "New support ticket opened: \"Export button times out on large orders.\"",
  "Marcus D. added 2 new members to the Platform team.",
];

router.get("/company", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const tiles = TILES.map((t) => `
    <a class="tile" id="${t.anchor}" href="${t.href}?difficulty=${difficulty}" target="_blank" style="text-decoration:none;color:inherit;">
      <div class="tile-icon">${t.icon}</div>
      <div class="tile-name">${t.name}</div>
      <div class="tile-desc">${t.desc}</div>
    </a>`).join("");
  const statCards = STATS.map((s) => `
    <div class="stat"><div class="stat-value">${s.value}</div><div class="stat-label">${s.label}</div></div>`).join("");
  const activityItems = ACTIVITY.map((a) => `<li>${a}</li>`).join("");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Intranet", difficulty,
    extraHead: `<style>
      .tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:10px;}
      .tile{background:#f8f9fb;border:1px solid #e2e5e9;border-radius:10px;padding:18px;transition:transform .1s;}
      .tile:hover{transform:translateY(-2px);border-color:#c7ccd4;}
      .tile-icon{font-size:1.6rem;}
      .tile-name{font-weight:700;margin-top:6px;}
      .tile-desc{font-size:.78rem;color:#7d838d;margin-top:4px;}
      .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:18px 0 24px;}
      .stat{background:#f8f9fb;border:1px solid #e2e5e9;border-radius:10px;padding:14px 16px;}
      .stat-value{font-size:1.35rem;font-weight:700;}
      .stat-label{font-size:.75rem;color:#7d838d;margin-top:2px;}
      .activity{margin:0;padding-left:18px;font-size:.85rem;color:#3a4048;}
      .activity li{margin-bottom:6px;}
      .section-title{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:#7d838d;font-weight:700;margin:22px 0 8px;}
    </style>`,
    bodyHtml: `
      <h1>Welcome back, Alex</h1>
      <p class="note">Here's what's happening across the workspace today.</p>
      <div class="stats">${statCards}</div>
      <div class="section-title">Quick links</div>
      <div class="tiles">${tiles}</div>
      <div class="section-title">Recent activity</div>
      <ul class="activity">${activityItems}</ul>
    `
  }));
});

// ============================================================================
// PHASE 2 ADDITION — ShopSphere home page. Second distinct target
// application (upgrade-spec Section 9). Mirrors /company's role for
// SecureCorp: a real landing/hub page a learner can browse, discover
// products on, and navigate into the actual vulnerable checkout flow from
// — not a bare list of lab links. Tiles here link ONLY to the labs that
// were actually re-skinned with the ShopSphere shell (price-tampering,
// coupon-abuse, workflow-bypass, refund-abuse — see routes/vulns-
// business.js and docs/UPGRADE-LOG.md); linking to a SecureCorp-skinned
// page from here would break the "different product" illusion this
// exists to create.
// ============================================================================
const SHOP_TILES = [
  { icon: "🛒", name: "Checkout", desc: "Review your cart and complete your order.", href: "/vuln/price-tampering" },
  { icon: "🏷️", name: "Apply a Coupon", desc: "Have a promo code? Apply it at checkout.", href: "/vuln/coupon-abuse" },
  { icon: "📦", name: "Complete Your Order", desc: "Finish an order you started earlier.", href: "/vuln/workflow-bypass" },
  { icon: "↩️", name: "Refunds & Returns", desc: "Request a refund on a recent order.", href: "/vuln/refund-abuse" },
];

const RECENT_ORDERS = [
  { id: "#8842", item: "Standard Widget", status: "Completed", total: "$200.00" },
  { id: "#8801", item: "Pro Gadget", status: "Delivered", total: "$129.99" },
  { id: "#8760", item: "Premium Support Plan", status: "Active", total: "$999.00" },
];

router.get("/shopsphere", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const productCards = C.listProducts().map((p) => `
    <div class="tile">
      <div class="tile-name">${p.name}</div>
      <div class="tile-desc">${p.blurb}</div>
      <div style="margin-top:8px;font-weight:700;">$${p.price.toFixed(2)}</div>
    </div>`).join("");
  const shopTiles = SHOP_TILES.map((t) => `
    <a class="tile" href="${t.href}?difficulty=${difficulty}" target="_blank" style="text-decoration:none;color:inherit;">
      <div class="tile-icon">${t.icon}</div>
      <div class="tile-name">${t.name}</div>
      <div class="tile-desc">${t.desc}</div>
    </a>`).join("");
  const orderRows = RECENT_ORDERS.map((o) => `<tr><td>${o.id}</td><td>${o.item}</td><td>${o.status}</td><td>${o.total}</td></tr>`).join("");

  res.send(C.renderShopSpherePage({
    appName: "ShopSphere", difficulty,
    extraHead: `<style>
      .tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:10px;}
      .tile{background:#f8fbfa;border:1px solid #dcece6;border-radius:10px;padding:18px;transition:transform .1s;}
      .tile:hover{transform:translateY(-2px);border-color:#b9dccf;}
      .tile-icon{font-size:1.6rem;}
      .tile-name{font-weight:700;margin-top:6px;}
      .tile-desc{font-size:.78rem;color:#5c766d;margin-top:4px;}
      .section-title{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:#5c766d;font-weight:700;margin:22px 0 8px;}
    </style>`,
    bodyHtml: `
      <h1>Welcome back, Jordan</h1>
      <p class="note">Here's what's new since your last visit.</p>
      <div class="section-title">Featured products</div>
      <div class="tiles">${productCards}</div>
      <div class="section-title">Quick links</div>
      <div class="tiles">${shopTiles}</div>
      <div class="section-title">Recent orders</div>
      <table><thead><tr><th>Order</th><th>Item</th><th>Status</th><th>Total</th></tr></thead><tbody>${orderRows}</tbody></table>
    `
  }));
});

// ============================================================================
// PHASE 2 ADDITION — Finova home page. Third distinct target application
// (upgrade-spec Section 9). Same pattern as /shopsphere: real content to
// browse, tiles linking ONLY into the labs actually re-skinned with the
// Finova shell (invitation-abuse, account-linking-abuse — see
// routes/vulns-business.js and docs/UPGRADE-LOG.md).
// ============================================================================
const FINOVA_TILES = [
  { icon: "🎁", name: "Refer a Friend", desc: "Earn account credit for every friend who signs up.", href: "/vuln/invitation-abuse" },
  { icon: "💳", name: "Link a Payment Account", desc: "Connect an external card or bank account.", href: "/vuln/account-linking-abuse" },
];

const FINOVA_ACCOUNTS = [
  { name: "Everyday Checking", number: "•••• 4471", balance: "$4,218.06" },
  { name: "High-Yield Savings", number: "•••• 8820", balance: "$12,940.51" },
];

const FINOVA_TRANSACTIONS = [
  { date: "Aug 24", desc: "Direct Deposit — Payroll", amount: "+$3,100.00" },
  { date: "Aug 22", desc: "Transfer to Savings", amount: "-$500.00" },
  { date: "Aug 19", desc: "Grocery Co-op", amount: "-$86.42" },
];

router.get("/finova", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const accountCards = FINOVA_ACCOUNTS.map((a) => `
    <div class="tile"><div class="tile-name">${a.name}</div><div class="tile-desc">${a.number}</div><div style="margin-top:8px;font-weight:700;">${a.balance}</div></div>`).join("");
  const tiles = FINOVA_TILES.map((t) => `
    <a class="tile" href="${t.href}?difficulty=${difficulty}" target="_blank" style="text-decoration:none;color:inherit;">
      <div class="tile-icon">${t.icon}</div><div class="tile-name">${t.name}</div><div class="tile-desc">${t.desc}</div>
    </a>`).join("");
  const txRows = FINOVA_TRANSACTIONS.map((t) => `<tr><td>${t.date}</td><td>${t.desc}</td><td>${t.amount}</td></tr>`).join("");

  res.send(C.renderFinovaPage({
    appName: "Finova", difficulty,
    extraHead: `<style>
      .tiles{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;margin-top:10px;}
      .tile{background:#f8f9fd;border:1px solid #dde3f2;border-radius:10px;padding:18px;transition:transform .1s;}
      .tile:hover{transform:translateY(-2px);border-color:#b9c6ee;}
      .tile-icon{font-size:1.6rem;}
      .tile-name{font-weight:700;margin-top:6px;}
      .tile-desc{font-size:.78rem;color:#5c6690;margin-top:4px;}
      .section-title{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:#5c6690;font-weight:700;margin:22px 0 8px;}
    </style>`,
    bodyHtml: `
      <h1>Good afternoon, Sam</h1>
      <p class="note">Here's your account overview.</p>
      <div class="section-title">Accounts</div>
      <div class="tiles">${accountCards}</div>
      <div class="section-title">Recent transactions</div>
      <table><thead><tr><th>Date</th><th>Description</th><th>Amount</th></tr></thead><tbody>${txRows}</tbody></table>
      <div class="section-title">Quick links</div>
      <div class="tiles">${tiles}</div>
    `
  }));
});

module.exports = { router };
